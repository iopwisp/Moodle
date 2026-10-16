"""Evidence-based execution review shared by CLI and assignment orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .credentials import redact
from .evidence import list_evidence, validate_evidence
from .models import TaskStatus
from .workspace import load_state, verify_inputs_unchanged


def review_workspace(workspace: Path) -> dict[str, Any]:
    state = load_state(workspace)
    checks = validate_evidence(workspace)
    valid_ids = {c["id"] for c in checks if c["verified"]}
    evidence = list_evidence(workspace)
    valid = [e for e in evidence if e.id in valid_ids]
    required = [t for t in state.plan.steps if t.required]
    inputs = verify_inputs_unchanged(workspace)
    missing = [t.id for t in state.plan.steps if t.evidence_required and not any(
        e.step_id == t.id and (t.evidence_type_required is None or e.type == t.evidence_type_required)
        for e in valid)]
    screenshots = [t.id for t in state.plan.steps if t.screenshot_required and not any(
        e.step_id == t.id and e.type == "screenshot" for e in valid)]
    report = workspace / "reports" / f"{state.assignment}_Report.docx"
    ready = (bool(required) and all(t.status == TaskStatus.COMPLETED for t in required)
             and not any(t.status in {TaskStatus.FAILED, TaskStatus.BLOCKED, TaskStatus.RUNNING} for t in state.plan.steps)
             and not any(c.status == "PENDING" for c in state.confirmations)
             and not any(not c["verified"] for c in checks) and not missing and not screenshots
             and bool(inputs) and all(e["copy_unchanged"] is True and
                                     (e["source_unchanged"] is True or e["source"] == ".") for e in inputs))
    return redact({
        "assignment": state.assignment, "status": state.status, "reason": state.status_reason,
        "required_steps": len(required), "completed_steps": sum(t.status == TaskStatus.COMPLETED for t in required),
        "failed_steps": [t.id for t in state.plan.steps if t.status == TaskStatus.FAILED],
        "blocked_steps": [t.id for t in state.plan.steps if t.status == TaskStatus.BLOCKED],
        "evidence_count": len(evidence), "invalid_evidence": [c for c in checks if not c["verified"]],
        "screenshot_count": sum(e.type == "screenshot" for e in valid),
        "missing_required_evidence_steps": missing, "missing_required_screenshot_steps": screenshots,
        "inputs_unchanged": inputs, "ready": ready,
        "ready_scope": "execution and recorded evidence; assignment coverage and report layout require separate review",
        "report_path": str(report) if report.is_file() else None,
    })  # type: ignore[no-any-return]
