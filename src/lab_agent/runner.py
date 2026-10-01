"""Execution engine: Assignment -> Plan -> Execute -> Verify -> Evidence -> Report.

The runner knows nothing about specific applications.  For each step it:

1. checks dependencies (``depends_on`` must be COMPLETED, ``run_after`` finished);
2. evaluates the security policy (deny / ask the user / allow);
3. executes the capability through the registry;
4. registers and validates every evidence file (real files only);
5. runs the verification checks returned by the adapter and declared in the
   plan - a step is COMPLETED only when the adapter's claim, every check and
   the required evidence all hold;
6. on failure classifies the error and applies bounded recovery;
7. writes the checkpoint, SQLite events and ``logs/execution.jsonl``.

Pause/Stop requests are read from the checkpoint between steps (and Stop also
interrupts waits inside capabilities).  ``execute_workspace`` doubles as
*resume*: it reconciles interrupted steps and re-validates evidence first.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .ai import build_ai_plan
from .analyzer import analyze
from .config import AgentConfig, get_config
from .credentials import redact
from .database import RunDatabase
from .environment import discover_environment, save_environment
from .evidence import evidence_for_step, register_evidence, validate_evidence
from .integrations.base import CapabilityBlocked, ExecutionContext, IntegrationResult
from .integrations.registry import IntegrationRegistry, build_registry
from .llm import LLMProvider, provider_from_config
from .logging_setup import get_logger
from .models import (
    Attempt,
    ConfirmationRequest,
    PlannedTask,
    RunState,
    RunStatus,
    TaskStatus,
    utc_now,
)
from .policy import PolicyEngine
from .recovery import FailureKind, RecoveryEngine, classify
from .reports import generate_reports
from .tools.screenshot import take_screenshot
from .verification import CheckContext, run_checks
from .workspace import create_workspace, load_state, save_state

LOG = get_logger("runner")
TERMINAL = {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.BLOCKED, TaskStatus.SKIPPED}
_CANCEL_EVENTS: dict[str, threading.Event] = {}


def state_path(state: RunState) -> Path:
    return Path(state.workspace_path)


def cancel_event_for(workspace: Path) -> threading.Event:
    return _CANCEL_EVENTS.setdefault(str(workspace.resolve()), threading.Event())


def request_control(workspace: Path, control: str) -> RunState:
    """Ask a running (or future) execution to PAUSE or STOP; safe to call from another thread/process."""
    if control not in {"PAUSE_REQUESTED", "STOP_REQUESTED"}:
        raise ValueError("control must be PAUSE_REQUESTED or STOP_REQUESTED")
    state = load_state(workspace)
    state.control = control
    if state.status not in {RunStatus.IN_PROGRESS, "IN_PROGRESS"}:
        state.status = RunStatus.STOPPED if control == "STOP_REQUESTED" else RunStatus.PAUSED
    save_state(workspace, state)
    if control == "STOP_REQUESTED":
        cancel_event_for(workspace).set()
    RunDatabase(workspace).event(state.run_id or state.assignment, "agent.stopped" if control == "STOP_REQUESTED" else "agent.paused",
                                 {"requested": True})
    return state


def decide_confirmation(workspace: Path, step_id: int, approve: bool, note: str = "") -> RunState:
    state = load_state(workspace)
    pending = [c for c in state.confirmations if c.step_id == step_id and c.status == "PENDING"]
    if not pending:
        raise ValueError(f"No pending confirmation for step {step_id}")
    for request in pending:
        request.status = "APPROVED" if approve else "REJECTED"
        request.decided_at = utc_now()
        request.note = note
    task = state.step(step_id)
    if task is not None and task.status == TaskStatus.BLOCKED:
        task.status = TaskStatus.PENDING if approve else TaskStatus.BLOCKED
        task.status_reason = "approved by user" if approve else f"rejected by user {note}".strip()
    save_state(workspace, state)
    RunDatabase(workspace).event(state.run_id or state.assignment, "confirmation.decided",
                                 {"step_id": step_id, "approved": approve, "note": note})
    return state


class Runner:
    def __init__(self, workspace: Path, *, config: AgentConfig | None = None, registry: IntegrationRegistry | None = None,
                 screenshot_fn: Any = None, allowed_targets: set[str] | None = None,
                 environment: dict[str, Any] | None = None, advisor: LLMProvider | None = None) -> None:
        self.workspace = workspace.resolve()
        self.config = config or get_config()
        self.screenshot_fn = screenshot_fn or take_screenshot
        self.registry = registry or build_registry(self.screenshot_fn, self.config)
        self.state = load_state(self.workspace)
        self.db = RunDatabase(self.workspace)
        self.allowed_targets = {t.casefold() for t in (allowed_targets or set())} | set(self._saved_targets())
        self.policy = PolicyEngine(self.config, self.allowed_targets)
        self.environment = environment
        self.cancel = cancel_event_for(self.workspace)
        advisor = advisor if advisor is not None else provider_from_config(self.config, "recovery")
        self.recovery = RecoveryEngine(self.registry, self.config.execution.max_attempts, advisor)

    # ------------------------------------------------------------------ helpers
    def _saved_targets(self) -> list[str]:
        path = self.workspace / "metadata" / "authorized_targets.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []

    def event(self, name: str, payload: dict[str, Any] | None = None) -> None:
        self.db.event(self.state.run_id or self.state.assignment, name, payload)

    def save(self) -> None:
        on_disk = load_state(self.workspace)
        if on_disk.control and not self.state.control:
            self.state.control = on_disk.control
        for request in on_disk.confirmations:
            mine = next((c for c in self.state.confirmations if c.id == request.id), None)
            if mine is not None and request.status != "PENDING":
                mine.status, mine.decided_at, mine.note = request.status, request.decided_at, request.note
        save_state(self.workspace, self.state)
        self.db.sync_state(self.state)

    def _control(self) -> str | None:
        return load_state(self.workspace).control or self.state.control

    def _log_execution(self, record: dict[str, Any]) -> None:
        path = self.workspace / "logs" / "execution.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(redact(record), ensure_ascii=False, default=str) + "\n")

    def _context(self, task: PlannedTask, attempt: int) -> ExecutionContext:
        return ExecutionContext(
            workspace=self.workspace, assignment=self.state.assignment, allowed_targets=set(self.policy.targets),
            step_id=task.id, config=self.config, environment=self._app_environment(),
            screenshot_fn=self.screenshot_fn, event_fn=self.event, cancel_event=self.cancel, attempt=attempt,
        )

    def _app_environment(self) -> dict[str, Any]:
        apps: dict[str, Any] = dict((self.environment or {}).get("applications", {}))
        if (self.environment or {}).get("wsl") is not None:
            apps["_wsl"] = self.environment["wsl"]  # type: ignore[index]
        return apps

    # ------------------------------------------------------------------ preparation
    def prepare(self) -> None:
        if self.environment is None:
            self.environment = discover_environment(self.registry, self.config)
        save_environment(self.environment, self.workspace / "metadata" / "environment.json")
        if not self.state.run_id:
            self.state.run_id = uuid.uuid4().hex
        self.db.start_run(self.state.run_id, self.state.assignment, self.state.plan.planner or None)
        self.db.record_capabilities(self.state.run_id, [c.to_dict() for c in self.registry.capabilities()])
        self.reconcile()

    def reconcile(self) -> None:
        """Checkpoint recovery: re-validate completed evidence and settle interrupted steps."""
        checks = {item["id"]: item for item in validate_evidence(self.workspace)}
        for task in self.state.plan.steps:
            if task.status == TaskStatus.COMPLETED:
                broken = [item for item in evidence_for_step(self.workspace, task.id) if not checks.get(item.id, {}).get("verified")]
                if broken:
                    task.status = TaskStatus.PENDING
                    task.status_reason = f"evidence {[b.id for b in broken]} missing or modified; step will run again"
                    self.event("task.failed", {"step_id": task.id, "reason": task.status_reason})
            elif task.status == TaskStatus.RUNNING:
                if self._reconciled(task):
                    task.status = TaskStatus.COMPLETED
                    task.status_reason = "result from the interrupted run verified on resume"
                    self.event("task.reconciled", {"step_id": task.id})
                else:
                    task.status = TaskStatus.PENDING
                    task.status_reason = "interrupted; will run again"
        self.state.completed_steps = [t.id for t in self.state.plan.steps if t.status == TaskStatus.COMPLETED]

    def _reconciled(self, task: PlannedTask) -> bool:
        adapter = self.registry.adapter_for(task.action) if self.registry.has(task.action) else None
        hook = getattr(adapter, "reconcile", None)
        if callable(hook):
            try:
                return bool(hook(task.action, task.parameters, self._context(task, 0)))
            except Exception:  # noqa: BLE001
                return False
        if not task.verification_checks:
            return False
        report = run_checks(task.verification_checks, CheckContext(self.workspace, url_allowed=self.policy.url_allowed))
        return report.passed and (not task.evidence_required or bool(evidence_for_step(self.workspace, task.id)))

    # ------------------------------------------------------------------ main loop
    def run(self, generate_report: bool = True) -> RunState:
        self.prepare()
        self.state.control = None
        on_disk = load_state(self.workspace)
        if on_disk.control:
            on_disk.control = None
            save_state(self.workspace, on_disk)
        self.cancel.clear()
        self.state.status = RunStatus.IN_PROGRESS
        self.state.started_at = self.state.started_at or utc_now()
        self.save()
        self.event("agent.started", {"resume": any(t.attempts for t in self.state.plan.steps),
                                     "capabilities": len(self.registry.capabilities()), "planner": self.state.plan.planner})
        attempted: set[int] = set()
        try:
            while True:
                control = self._control()
                if control == "STOP_REQUESTED":
                    self.state.status, self.state.status_reason = RunStatus.STOPPED, "stopped by user"
                    self.event("agent.stopped", {})
                    break
                if control == "PAUSE_REQUESTED":
                    self.state.status, self.state.status_reason = RunStatus.PAUSED, "paused by user"
                    self.event("agent.paused", {})
                    break
                task = self._next_task(attempted)
                if task is None:
                    break
                attempted.add(task.id)
                self._execute_task(task)
                if self.config.execution.stop_on_failure and task.status == TaskStatus.FAILED and task.required:
                    break
        finally:
            self.registry.shutdown()
            self.state.current_step = None
            self.state.current_application = None
        if self.state.status not in {RunStatus.STOPPED, RunStatus.PAUSED}:
            self.state.status, self.state.status_reason = self._final_status()
            self.state.control = None
        self.state.finished_at = utc_now()
        self.save()
        self.db.finish_run(self.state.run_id or "", str(self.state.status))
        if generate_report:
            try:
                reports = generate_reports(self.workspace, self.registry)
                self.event("report.completed", reports)
            except Exception as exc:  # noqa: BLE001 - report failure must not hide the run result
                self.db.record_error(self.state.run_id or "", None, "report", str(exc))
                self.event("report.failed", {"error": str(exc)})
        self.event("agent.completed" if self.state.status == RunStatus.COMPLETED else "agent.finished",
                   {"status": self.state.status, "reason": self.state.status_reason})
        return self.state

    def _next_task(self, attempted: set[int]) -> PlannedTask | None:
        for task in self.state.plan.steps:
            if task.id in attempted or task.status in {TaskStatus.COMPLETED, TaskStatus.SKIPPED}:
                continue
            if task.status == TaskStatus.BLOCKED and self._awaiting_confirmation(task):
                continue
            if task.status == TaskStatus.BLOCKED and any(c.step_id == task.id and c.status == "REJECTED" for c in self.state.confirmations):
                continue
            return task
        return None

    def _awaiting_confirmation(self, task: PlannedTask) -> bool:
        return any(c.step_id == task.id and c.status == "PENDING" for c in self.state.confirmations)

    def _final_status(self) -> tuple[RunStatus, str]:
        required = [t for t in self.state.plan.steps if t.required]
        if all(t.status in {TaskStatus.COMPLETED, TaskStatus.SKIPPED} for t in required):
            return RunStatus.COMPLETED, "all required steps completed and verified"
        if any(self._awaiting_confirmation(t) for t in required):
            return RunStatus.WAITING_CONFIRMATION, "waiting for user confirmation"
        failed = [t.id for t in required if t.status == TaskStatus.FAILED]
        blocked = [t.id for t in required if t.status == TaskStatus.BLOCKED]
        if failed:
            return RunStatus.FAILED, f"required step(s) {failed} failed" + (f"; {blocked} blocked" if blocked else "")
        if blocked:
            return RunStatus.BLOCKED, f"required step(s) {blocked} blocked"
        return RunStatus.IN_PROGRESS, "unfinished steps remain"

    # ------------------------------------------------------------------ one step
    def _dependency_problem(self, task: PlannedTask) -> str | None:
        for dependency in task.depends_on:
            other = self.state.step(dependency)
            if other is None:
                return f"unknown dependency {dependency}"
            if other.status not in {TaskStatus.COMPLETED, TaskStatus.SKIPPED}:
                return f"dependency step {dependency} is {other.status.value}"
        for dependency in task.run_after:
            other = self.state.step(dependency)
            if other is not None and other.status not in TERMINAL:
                return f"step {dependency} has not finished"
        return None

    def _set(self, task: PlannedTask, status: TaskStatus, reason: str = "", kind: str | None = None) -> None:
        task.status = status
        task.status_reason = reason
        task.finished_at = utc_now()
        if status == TaskStatus.COMPLETED:
            if task.id not in self.state.completed_steps:
                self.state.completed_steps.append(task.id)
            self.state.errors = [e for e in self.state.errors if e.get("step_id") != task.id]
            self.event("task.completed", {"step_id": task.id, "capability": task.action})
            self._invalidate_dependents(task)
        else:
            if task.id in self.state.completed_steps:
                self.state.completed_steps.remove(task.id)
            self.state.errors = [e for e in self.state.errors if e.get("step_id") != task.id]
            self.state.errors.append({"step_id": task.id, "error": reason, "kind": kind or status.value.lower()})
            self.db.record_error(self.state.run_id or "", task.id, kind or status.value.lower(), reason)
            self.event("task.blocked" if status == TaskStatus.BLOCKED else "task.failed",
                       {"step_id": task.id, "reason": reason, "kind": kind})
        self.save()

    def _invalidate_dependents(self, task: PlannedTask) -> None:
        """A step that completes on resume may change what later steps already summarised.

        Example: hashing ran while Foremost was BLOCKED; once Foremost completes, the hash list and the
        tool comparison must be rebuilt.  Steps confirmed by the student are never reset.
        """
        for other in self.state.plan.steps:
            if (other.status == TaskStatus.COMPLETED and task.id in (*other.depends_on, *other.run_after)
                    and other.finished_at is not None and task.finished_at is not None and other.finished_at < task.finished_at
                    and not other.status_reason.startswith("manually verified")):
                other.status = TaskStatus.PENDING
                other.status_reason = f"step {task.id} produced new results; running again"
                if other.id in self.state.completed_steps:
                    self.state.completed_steps.remove(other.id)
                self.event("task.invalidated", {"step_id": other.id, "because_of": task.id})

    def _execute_task(self, task: PlannedTask) -> None:
        problem = self._dependency_problem(task)
        if problem:
            self._set(task, TaskStatus.BLOCKED, f"not started: {problem}", "dependency")
            return
        if not self.registry.has(task.action):
            self._set(task, TaskStatus.FAILED, f"capability {task.action!r} is not registered", "invalid_plan")
            return
        task.action = self.registry.normalize(task.action)
        capability = self.registry.capability(task.action)
        decision = self.policy.check(capability, task.parameters)
        if not decision.allowed:
            self.event("policy.denied", {"step_id": task.id, "reason": decision.reason})
            self._set(task, TaskStatus.BLOCKED, decision.reason, "policy")
            return
        if decision.confirmation_required and not any(c.step_id == task.id and c.status == "APPROVED" for c in self.state.confirmations):
            self._request_confirmation(task, decision.reason)
            return
        task.status, task.started_at, task.status_reason = TaskStatus.RUNNING, utc_now(), ""
        self.state.current_step, self.state.current_application = task.id, capability.tool
        self.save()
        self.event("task.started", {"step_id": task.id, "capability": task.action, "title": task.title})
        if self.config.screenshots.mode == "all":
            self._screenshot(task, "before")

        parameters = dict(task.parameters)
        attempt = 0
        while True:
            attempt += 1
            record = Attempt(number=len(task.attempts) + 1)
            task.attempts.append(record)
            context = self._context(task, attempt)
            started = time.monotonic()
            self.event("capability.started", {"step_id": task.id, "capability": task.action, "attempt": attempt})
            outcome, error, kind, result = self._attempt(task, parameters, context)
            record.finished_at, record.outcome, record.error = utc_now(), outcome, error
            record.failure_kind = kind.value if kind else None
            self._log_execution({"timestamp": datetime.now(UTC).isoformat(), "step_id": task.id, "application": capability.tool,
                                 "capability": task.action, "parameters": parameters, "attempt": attempt, "outcome": outcome,
                                 "duration_seconds": round(time.monotonic() - started, 3), "error": error,
                                 "summary": task.result_summary, "exit_code": (result.details.get("exit_code") if result else None),
                                 "stdout": str((result.details.get("stdout") if result else "") or "")[-2000:],
                                 "stderr": str((result.details.get("stderr") if result else "") or "")[-2000:],
                                 "verification": task.verification_results})
            if outcome == "COMPLETED":
                self._set(task, TaskStatus.COMPLETED, task.result_summary or "verified")
                break
            if outcome == "BLOCKED":
                self._set(task, TaskStatus.BLOCKED, error or "blocked", kind.value if kind else "blocked")
                break
            if kind == FailureKind.STOPPED:
                task.status, task.status_reason = TaskStatus.PENDING, "interrupted by Stop; will run on resume"
                self.save()
                break
            recovery = self.recovery.decide(task, kind or FailureKind.UNKNOWN, attempt, error or "", context,
                                            {"details": (result.details if result else {}), "verification": task.verification_results})
            record.recovery = recovery.reason
            if recovery.action == "retry":
                if recovery.parameters:
                    parameters = {**parameters, **recovery.parameters}
                self.state.recoveries.append({"step_id": task.id, "attempt": attempt, "kind": (kind or FailureKind.UNKNOWN).value,
                                              "action": recovery.reason, "notes": recovery.notes,
                                              "parameters": recovery.parameters or {}, "at": utc_now().isoformat()})
                self.event("recovery.started", {"step_id": task.id, "reason": recovery.reason, "notes": recovery.notes})
                self.save()
                continue
            if recovery.action == "ask_human":
                self._request_confirmation(task, f"{error}. {recovery.reason}. Fix the situation and approve to retry.")
                break
            status = TaskStatus.BLOCKED if recovery.action == "blocked" else TaskStatus.FAILED
            self._set(task, status, error or recovery.reason, (kind or FailureKind.UNKNOWN).value)
            break
        if task.parameters != parameters and task.status == TaskStatus.COMPLETED:
            task.parameters = parameters
        if self.config.screenshots.mode == "all":
            self._screenshot(task, "after")
        self.save()

    def _request_confirmation(self, task: PlannedTask, reason: str) -> None:
        if not self._awaiting_confirmation(task):
            request = ConfirmationRequest(id=uuid.uuid4().hex[:8], step_id=task.id, reason=reason)
            self.state.confirmations.append(request)
            self.event("confirmation.requested", {"step_id": task.id, "reason": reason, "id": request.id})
        task.status, task.status_reason = TaskStatus.BLOCKED, f"waiting for confirmation: {reason}"
        self.save()

    def _attempt(self, task: PlannedTask, parameters: dict[str, Any], context: ExecutionContext
                 ) -> tuple[str, str | None, FailureKind | None, IntegrationResult | None]:
        try:
            result = self.registry.execute(task.action, parameters, context)
        except CapabilityBlocked as exc:
            return "BLOCKED", str(exc), FailureKind.BLOCKED, None
        except Exception as exc:  # noqa: BLE001 - adapters raise library-specific errors
            kind = classify(exc)
            if kind in {FailureKind.POLICY}:
                return "BLOCKED", f"{type(exc).__name__}: {exc}", kind, None
            return "FAILED", f"{type(exc).__name__}: {exc}", kind, None
        task.result_details = _trimmed(result.details)
        if result.blocked:
            return "BLOCKED", result.reason or "capability reported BLOCKED", FailureKind.BLOCKED, result
        registered, evidence_errors = self._register(task, result)
        for section in result.report_sections:
            if section not in task.report_sections:
                task.report_sections.append(section)
        if task.screenshot_required and not any(item["type"] in {"screenshot", "figure"} for item in registered):
            picture = self._screenshot(task, "result", window_hint=task.tool)
            if picture is not None:
                registered.append({"path": str(picture), "type": "screenshot"})
            else:
                evidence_errors.append("the step requires a screenshot but capture is unavailable")
        checks = list(result.checks) + list(task.verification_checks)
        if task.evidence_required:
            wanted = task.evidence_type_required
            if not any(wanted is None or item["type"] == wanted or (wanted == "file" and item["type"] != "screenshot")
                       for item in registered):
                evidence_errors.append(f"required {wanted or 'evidence'} was not produced")
        self.event("verification.started", {"step_id": task.id, "checks": len(checks)})
        report = run_checks(checks, CheckContext(self.workspace, details=result.details,
                                                 evidence_paths=[Path(item["path"]) for item in registered],
                                                 url_allowed=self.policy.url_allowed)) if checks else None
        results = report.results if report else []
        task.verification_results = [r.to_dict() for r in results] + [
            {"type": "evidence", "passed": False, "detail": message, "spec": {}} for message in evidence_errors]
        if not checks and not registered:
            task.verification_results.append({"type": "adapter", "passed": result.verified,
                                               "detail": "adapter-reported result without files", "spec": {}})
        self.db.record_verification(self.state.run_id or "", task.id, task.verification_results)
        passed = result.verified and not evidence_errors and (report is None or report.passed)
        summary = self._summary(result, report)
        task.result_summary = summary
        self.event("verification.passed" if passed else "verification.failed",
                   {"step_id": task.id, "summary": (report.summary() if report else "no checks"), "evidence_errors": evidence_errors})
        if passed:
            self.event("capability.completed", {"step_id": task.id, "capability": task.action, "verified": True})
            return "COMPLETED", None, None, result
        self.event("capability.failed", {"step_id": task.id, "capability": task.action})
        reason = result.reason if not result.verified else ""
        failure = "; ".join(part for part in (reason, *evidence_errors, report.summary() if report and not report.passed else "") if part)
        return "FAILED", failure or "verification failed", FailureKind.VERIFICATION_FAILED, result

    def _summary(self, result: IntegrationResult, report: Any) -> str:
        interesting = {k: v for k, v in result.details.items() if k not in {"stdout", "stderr", "command", "rows", "files", "hashes",
                                                                          "history", "artifacts", "reachability"}
                       and isinstance(v, (str, int, float, bool)) and len(str(v)) < 200}
        text = ", ".join(f"{k}={v}" for k, v in list(interesting.items())[:8])
        if report is not None:
            text = f"{text}; {report.summary()}" if text else report.summary()
        return text[:1000]

    def _register(self, task: PlannedTask, result: IntegrationResult) -> tuple[list[dict[str, Any]], list[str]]:
        registered: list[dict[str, Any]] = []
        errors: list[str] = []
        for artifact in result.evidence:
            path = Path(str(artifact.get("path", "")))
            kind = str(artifact.get("type", "file"))
            try:
                item = register_evidence(self.workspace, path, str(artifact.get("description") or f"Evidence for step {task.id}"),
                                         kind, task.id, capability=task.action, requirement_refs=task.requirement_refs)
            except (OSError, ValueError) as exc:
                errors.append(f"{path.name}: {exc}")
                continue
            self.db.sync_evidence(self.state.run_id or self.state.assignment, item.id, item.path, item.type, item.verified,
                                  step_id=task.id, sha256=item.sha256, description=item.description)
            self.event("evidence.created", {"step_id": task.id, "id": item.id, "path": item.path, "type": item.type,
                                            "sha256": item.sha256})
            if kind == "screenshot":
                self.event("screenshot.created", {"step_id": task.id, "path": item.path})
            registered.append({"path": str(self.workspace / item.path), "type": item.type, "id": item.id})
        return registered, errors

    def _screenshot(self, task: PlannedTask, label: str, window_hint: str | None = None) -> Path | None:
        window = None
        if window_hint and self.config.screenshots.target == "window":
            try:
                from .desktop.profiles import load_profile

                window = (load_profile(window_hint).get("window") or {}).get("title_re")
            except (FileNotFoundError, RuntimeError, ValueError):
                window = None
        try:
            try:
                picture = self.screenshot_fn(self.workspace, name=f"step_{task.id:02d}_{label}.png", window_title_re=window)
            except TypeError:
                picture = self.screenshot_fn(self.workspace, name=f"step_{task.id:02d}_{label}.png")
            item = register_evidence(self.workspace, Path(picture), f"Step {task.id} {label}: {task.title}", "screenshot", task.id,
                                     capability=task.action, requirement_refs=task.requirement_refs)
            self.db.sync_evidence(self.state.run_id or self.state.assignment, item.id, item.path, item.type, item.verified,
                                  step_id=task.id, sha256=item.sha256, description=item.description)
            self.event("screenshot.created", {"step_id": task.id, "path": item.path})
            return Path(picture)
        except Exception as exc:  # noqa: BLE001 - screenshots are best effort unless required
            LOG.debug("screenshot failed: %s", exc)
            return None


def _trimmed(value: Any, depth: int = 0) -> Any:
    """Adapter details small enough for the checkpoint: long text, deep nesting and long lists are cut."""
    if isinstance(value, str):
        return value if len(value) <= 4000 else value[:2000] + "\n...\n" + value[-1500:]
    if isinstance(value, dict):
        return {str(k): _trimmed(v, depth + 1) for k, v in list(value.items())[:200]} if depth < 5 else "..."
    if isinstance(value, list | tuple):
        return [_trimmed(v, depth + 1) for v in list(value)[:200]] if depth < 5 else "..."
    if value is None or isinstance(value, bool | int | float):
        return value
    return str(value)


def execute_workspace(
    workspace: Path,
    allowed_targets: set[str] | None = None,
    generate_report: bool = True,
    *,
    config: AgentConfig | None = None,
    registry: IntegrationRegistry | None = None,
    screenshot_fn: Any = None,
    environment: dict[str, Any] | None = None,
    advisor: LLMProvider | None = None,
) -> RunState:
    runner = Runner(workspace, config=config, registry=registry, screenshot_fn=screenshot_fn or take_screenshot,
                    allowed_targets=allowed_targets, environment=environment, advisor=advisor)
    return runner.run(generate_report=generate_report)


def plan_assignment(
    paths: list[Path],
    workspace_root: Path,
    provider: str = "auto",
    model: str | None = None,
    allowed_targets: set[str] | None = None,
    *,
    config: AgentConfig | None = None,
    registry: IntegrationRegistry | None = None,
    environment: dict[str, Any] | None = None,
    llm: LLMProvider | None = None,
    screenshot_fn: Any = None,
) -> tuple[Path, str]:
    """Analyze + plan + create the workspace, without executing."""
    config = config or get_config()
    registry = registry or build_registry(screenshot_fn or take_screenshot, config)
    analysis = analyze(paths)
    if environment is None:
        environment = discover_environment(registry, config)
    plan, planner = build_ai_plan(analysis, provider, model, registry=registry, config=config, environment=environment,
                                  allowed_targets=allowed_targets, llm=llm)
    workspace = create_workspace(analysis, plan, workspace_root)
    state = load_state(workspace)
    state.run_id = uuid.uuid4().hex
    save_state(workspace, state)
    metadata = workspace / "metadata"
    (metadata / "planner.json").write_text(json.dumps({
        "provider": planner, "model": model, "planner_detail": plan.planner, "warnings": plan.warnings,
        "capabilities": [task.action for task in plan.steps]}, ensure_ascii=False, indent=2), encoding="utf-8")
    (metadata / "authorized_targets.json").write_text(json.dumps(sorted(t.casefold() for t in (allowed_targets or set()))),
                                                    encoding="utf-8")
    save_environment(environment, metadata / "environment.json")
    return workspace, planner


def run_assignment(
    paths: list[Path],
    workspace_root: Path,
    provider: str = "auto",
    model: str | None = None,
    allowed_targets: set[str] | None = None,
    *,
    config: AgentConfig | None = None,
    registry: IntegrationRegistry | None = None,
    environment: dict[str, Any] | None = None,
    llm: LLMProvider | None = None,
    screenshot_fn: Any = None,
    advisor: LLMProvider | None = None,
) -> tuple[Path, RunState, str]:
    screenshot_fn = screenshot_fn or take_screenshot
    config = config or get_config()
    registry = registry or build_registry(screenshot_fn, config)
    workspace, planner = plan_assignment(paths, workspace_root, provider, model, allowed_targets, config=config,
                                         registry=registry, environment=environment, llm=llm, screenshot_fn=screenshot_fn)
    if environment is None:
        environment = json.loads((workspace / "metadata" / "environment.json").read_text(encoding="utf-8"))
    execute_workspace(workspace, allowed_targets, config=config, registry=registry, screenshot_fn=screenshot_fn,
                      environment=environment, advisor=advisor)
    return workspace, load_state(workspace), planner
