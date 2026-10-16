"""Small, read-only workspace snapshots for humans and agents; no AI calls."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .credentials import redact, redact_text
from .evidence import list_evidence, validate_evidence
from .models import TaskStatus
from .workspace import load_state


def _short(value: object, limit: int = 300) -> str:
    return redact_text(str(value))[:limit]


def workspace_context(workspace: Path, *, limit: int = 5, step_id: int | None = None,
                      verify: bool = False) -> dict[str, Any]:
    if not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")
    state = load_state(workspace)
    steps = state.plan.steps
    if step_id is not None and state.step(step_id) is None:
        raise ValueError(f"Unknown step id: {step_id}")
    confirmations = [c for c in state.confirmations if c.status == "PENDING"]
    issues = [t for t in steps if t.status in {TaskStatus.BLOCKED, TaskStatus.FAILED}]
    active = [t for t in steps if t.status == TaskStatus.RUNNING]
    completed = {t.id for t in steps if t.status == TaskStatus.COMPLETED}
    terminal = completed | {t.id for t in steps if t.status in {
        TaskStatus.FAILED, TaskStatus.BLOCKED, TaskStatus.SKIPPED}}
    ready = [t for t in steps if t.status == TaskStatus.PENDING and
             set(t.depends_on) <= completed and set(t.run_after) <= terminal]
    next_step = next(iter(active or ready or issues), None)
    focus = [state.step(step_id)] if step_id is not None else ((issues + active + ready) or steps[-limit:])[:limit]
    evidence = list_evidence(workspace)
    selected_ids = {t.id for t in focus if t is not None}
    selected_evidence = [e for e in evidence if e.step_id in selected_ids]
    checks = validate_evidence(workspace) if verify else []
    result: dict[str, Any] = {
        "workspace": str(workspace.resolve()), "assignment": state.assignment,
        "objective": _short(state.plan.objective, 500), "status": state.status,
        "reason": _short(state.status_reason), "snapshot_at": state.updated_at.isoformat(),
        "counts": dict(Counter(t.status.value for t in steps)), "total_steps": len(steps),
        "steps": [{"id": t.id, "action": t.action, "status": t.status.value,
                   "title": _short(t.title, 160), "reason": _short(t.status_reason),
                   **({"parameters": t.parameters, "verification_checks": t.verification_checks,
                       "depends_on": t.depends_on, "run_after": t.run_after} if step_id is not None else {})}
                  for t in focus if t is not None],
        "pending_confirmations": [{"step": c.step_id, "reason": _short(c.reason)}
                                  for c in confirmations[:limit]],
        "confirmation_count": len(confirmations),
        "recent_errors": [{"step": e.get("step_id"), "kind": _short(e.get("kind", ""), 80),
                           "error": _short(e.get("error", ""), 500)} for e in state.errors[-min(limit, 3):]],
        "evidence": {"total": len(evidence), "focus_total": len(selected_evidence),
                     "checked_now": verify, "invalid_now": sum(not c["verified"] for c in checks) if verify else None,
                     "files": [{"path": e.path, "step": e.step_id, "sha256": e.sha256,
                                "recorded_verified": e.verified} for e in selected_evidence[:limit]]},
        "reports": [p.relative_to(workspace).as_posix()
                    for p in sorted((workspace / "reports").glob("*")) if p.is_file()][:limit],
        "details": {"state": "state/state.json", "plan": "metadata/execution_plan.json",
                    "commands": "logs/commands.jsonl"},
    }
    if confirmations:
        action = {"kind": "user_confirmation", "step": confirmations[0].step_id}
    elif active or state.status == "IN_PROGRESS":
        action = {"kind": "inspect_running", "step": next_step.id if next_step else None}
    elif issues and not ready:
        action = {"kind": "resolve_blocker", "step": issues[0].id}
    elif next_step:
        action = {"kind": "resume", "step": next_step.id}
    elif any(t.status == TaskStatus.PENDING for t in steps):
        action = {"kind": "inspect_dependencies", "step": None}
    else:
        action = {"kind": "none", "step": None}
    if verify and any(not c["verified"] for c in checks):
        action = {"kind": "inspect_evidence", "step": None}
    result["next_action"] = action
    return redact(result)  # type: ignore[no-any-return]
