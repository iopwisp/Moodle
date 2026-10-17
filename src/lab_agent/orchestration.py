"""Prepare or resume one assignment through existing planners and the verified runner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import AgentConfig
from .context import workspace_context
from .credentials import redact
from .delivery import review_workspace
from .integrations.registry import IntegrationRegistry
from .runner import execute_workspace, plan_assignment
from .scenarios import plan_scenario
from .screenshot_review import prepare_screenshot_checklist
from .workspace import load_state, write_json


def orchestrate_assignment(paths: list[Path], root: Path, *, workspace: Path | None = None,
                           scenario: Path | None = None, execute: bool = False, provider: str = "deterministic",
                           model: str | None = None, config: AgentConfig, registry: IntegrationRegistry,
                           allowed_targets: set[str] | None = None, environment: dict[str, Any] | None = None,
                           generate_report: bool = True) -> dict[str, Any]:
    if workspace is not None:
        if paths or scenario is not None:
            raise ValueError("Use either input paths (new assignment) or --workspace (resume), not both")
        load_state(workspace)
    elif not paths:
        raise ValueError("Provide assignment files or --workspace to continue an existing assignment")
    elif scenario is not None:
        workspace = plan_scenario(scenario, paths, root, config=config, registry=registry,
                                   allowed_targets=allowed_targets)
    else:
        workspace, _ = plan_assignment(paths, root, provider, model, allowed_targets, config=config,
                                        registry=registry, environment=environment)
    analysis_file = workspace / "metadata" / "assignment_analysis.json"
    analysis = json.loads(analysis_file.read_text(encoding="utf-8")) if analysis_file.is_file() else {}
    brief_file = workspace / "metadata" / "assignment_brief.json"
    if not brief_file.exists():
        write_json(brief_file, redact({
            "requirements": analysis.get("requirements", []), "questions": analysis.get("questions", []),
            "screenshots": analysis.get("screenshot_requirements", []),
            "deliverables": analysis.get("deliverables", []), "limitations": analysis.get("limitations", []),
            "coverage_review": "pending: compare full original instructions, including figures and tables",
            "report_review": "pending: required format, filename, language, style and rendered pages",
        }))
    prepare_screenshot_checklist(workspace)
    execution_config = config.model_copy(deep=True)
    if provider == "deterministic" or scenario is not None:
        execution_config.ai.provider = "deterministic"
        execution_config.ai.recovery_advice = False
    if execute:
        execute_workspace(workspace, allowed_targets, config=execution_config, registry=registry,
                          environment=environment, generate_report=generate_report)
    result = workspace_context(workspace)
    result["assignment_brief"] = "metadata/assignment_brief.json"
    result["screenshot_checklist"] = "metadata/screenshot_checklist.json"
    result["completion_rule"] = "Check every original requirement and review the final report before declaring delivery complete"
    if execute:
        review = review_workspace(workspace)
        write_json(workspace / "execution_summary.json", review)
        result["execution_ready"] = review["ready"]
        result["execution_review"] = "execution_summary.json"
        if not review["ready"] and result["next_action"]["kind"] == "none":
            result["next_action"] = {"kind": "inspect_execution_review", "step": None}
        result["delivery_review"] = "required: assignment coverage and report format/layout"
    return result
