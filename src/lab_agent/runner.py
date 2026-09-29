"""End-to-end execution and recovery for a single assignment."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from .ai import build_ai_plan
from .analyzer import analyze
from .automation import autopsy_e2e_operation, browser_operation, desktop_operation, urls_from_text
from .database import RunDatabase
from .evidence import register_evidence
from .models import PlannedTask, RunState, TaskStatus
from .reports import generate_reports
from .tools.screenshot import take_screenshot
from .workspace import calculate_hashes, create_workspace, load_state, save_state


def _event(
    db: RunDatabase, state: RunState, name: str, payload: dict[str, object] | None = None
) -> None:
    db.event(state.run_id or state.assignment, name, payload)


def _register(
    db: RunDatabase, state: RunState, path: Path, description: str, kind: str, step_id: int
) -> None:
    item = register_evidence(state_path(state), path, description, kind, step_id)
    db.sync_evidence(state.run_id or state.assignment, item.id, item.path, item.type, item.verified)
    _event(db, state, "evidence.verified", {"id": item.id, "path": item.path})


def state_path(state: RunState) -> Path:
    return Path(state.workspace_path)


def _step_screenshot(workspace: Path, task: PlannedTask, label: str) -> Path | None:
    try:
        return take_screenshot(workspace, name=f"step_{task.id:02d}_{label}.png")
    except RuntimeError:
        return None


def _run_step(
    workspace: Path,
    state: RunState,
    task: PlannedTask,
    db: RunDatabase,
    allowed_targets: set[str],
) -> None:
    task.status = TaskStatus.RUNNING
    state.current_step = task.id
    state.status = "IN_PROGRESS"
    save_state(workspace, state)
    db.sync_state(state)
    _event(db, state, "task.started", {"step_id": task.id, "action": task.action})

    before = _step_screenshot(workspace, task, "before")
    if before:
        _register(db, state, before, f"Before step {task.id}: {task.title}", "screenshot", task.id)
        _event(db, state, "screenshot.created", {"step_id": task.id, "path": str(before)})

    try:
        if task.action == "hash_inputs":
            hashes = {
                path.name: calculate_hashes(path)
                for path in (workspace / "input").iterdir()
                if path.is_file()
            }
            output = workspace / "results" / f"step_{task.id:02d}_hashes.json"
            output.write_text(
                json.dumps(hashes, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            _register(db, state, output, f"Hashes generated for step {task.id}", "hash", task.id)

        elif task.action == "autopsy_e2e":
            result = autopsy_e2e_operation(workspace, state.assignment)
            _register(
                db, state, Path(result["screenshot"]),
                "Verified Autopsy forensic workflow result",
                "screenshot",
                task.id,
            )
            _register(
                db, state, Path(result["command_log"]),
                "Autopsy command-line ingest execution log",
                "log",
                task.id,
            )
            _event(
                db,
                state,
                "autopsy.completed",
                {
                    "case_dir": result["case_dir"],
                    "data_source": result["data_source"],
                    "pid": result["pid"],
                },
            )
            if not result.get("verified"):
                raise RuntimeError("Autopsy reported an unverified result.")

        elif task.action == "desktop":
            result = desktop_operation(
                workspace,
                task.parameters.get("profile", ""),
                task.parameters.get("operation", "launch"),
                state.assignment,
            )
            if not result.get("verified"):
                raise RuntimeError("Desktop operation returned without verification.")
            picture = Path(result["screenshot"])
            _register(
                db,
                state,
                picture,
                f"{result['profile']} {result['operation']}",
                "screenshot",
                task.id,
            )
            _event(
                db,
                state,
                "application.action.completed",
                {"profile": result["profile"], "operation": result["operation"], "pid": result["pid"]},
            )

        elif task.action == "browser":
            url = task.parameters.get("url") or next(iter(urls_from_text(task.description)), "")
            result = browser_operation(workspace, url, allowed_targets)
            _register(
                db,
                state,
                Path(result["screenshot"]),
                f"Browser result: {result['title']}",
                "screenshot",
                task.id,
            )

        elif task.action == "screenshot":
            picture = _step_screenshot(workspace, task, "result")
            if not picture:
                raise RuntimeError(
                    "Screenshot capture is unavailable; install the gui extra and run "
                    "in an interactive desktop session."
                )
            _register(
                db, state, picture, f"Screenshot required by step {task.id}", "screenshot", task.id
            )

        elif task.action == "manual_review":
            task.status = TaskStatus.BLOCKED
            state.errors.append(
                {
                    "step_id": task.id,
                    "error": "Manual review is required; no result was claimed.",
                }
            )
            _event(db, state, "task.blocked", {"step_id": task.id})
            return

        else:
            raise ValueError(f"Unknown planned action: {task.action}")

        task.status = TaskStatus.COMPLETED
        if task.id not in state.completed_steps:
            state.completed_steps.append(task.id)
        state.errors = [error for error in state.errors if error.get("step_id") != task.id]
        _event(db, state, "task.completed", {"step_id": task.id})

    except Exception as exc:  # noqa: BLE001
        task.status = TaskStatus.FAILED
        state.errors.append({"step_id": task.id, "error": str(exc)})
        _event(db, state, "task.failed", {"step_id": task.id, "error": str(exc)})

    finally:
        after = _step_screenshot(workspace, task, "after")
        if after:
            _register(db, state, after, f"After step {task.id}: {task.title}", "screenshot", task.id)
            _event(db, state, "screenshot.created", {"step_id": task.id, "path": str(after)})

        state.status = (
            "COMPLETED"
            if all(
                step.status in {TaskStatus.COMPLETED, TaskStatus.SKIPPED}
                for step in state.plan.steps
            )
            else "IN_PROGRESS"
        )
        save_state(workspace, state)
        db.sync_state(state)


def execute_workspace(
    workspace: Path,
    allowed_targets: set[str] | None = None,
    generate_report: bool = True,
) -> RunState:
    state = load_state(workspace)
    db = RunDatabase(workspace)
    if not state.run_id:
        state.run_id = uuid.uuid4().hex
    allowed_targets = {target.casefold() for target in (allowed_targets or set())}
    db.sync_state(state)
    _event(db, state, "agent.started", {"resume": True})

    for task in state.plan.steps:
        if load_state(workspace).status == "STOPPED":
            state.status = "STOPPED"
            _event(db, state, "agent.stopped")
            break
        if task.status in {
            TaskStatus.PENDING,
            TaskStatus.RUNNING,
            TaskStatus.FAILED,
            TaskStatus.BLOCKED,
        }:
            _run_step(workspace, state, task, db, allowed_targets)

    if generate_report:
        reports = generate_reports(workspace)
        _event(db, state, "report.completed", reports)

    save_state(workspace, state)
    db.sync_state(state)
    return state


def run_assignment(
    paths: list[Path],
    workspace_root: Path,
    provider: str = "auto",
    model: str | None = None,
    allowed_targets: set[str] | None = None,
) -> tuple[Path, RunState, str]:
    analysis = analyze(paths)
    plan, planner = build_ai_plan(analysis, provider, model)
    workspace = create_workspace(analysis, plan, workspace_root)
    state = load_state(workspace)
    state.run_id = uuid.uuid4().hex
    save_state(workspace, state)
    (workspace / "metadata" / "planner.json").write_text(
        json.dumps({"provider": planner, "model": model}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    execute_workspace(workspace, allowed_targets)
    return workspace, load_state(workspace), planner
