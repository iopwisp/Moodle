"""Reusable YAML plans executed through the regular policy/evidence runner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .analyzer import SUPPORTED, analyze
from .config import AgentConfig
from .integrations.registry import IntegrationRegistry
from .models import AssignmentAnalysis, ExecutionPlan, PlannedTask
from .planning import normalize_plan, validate_plan
from .policy import PolicyEngine
from .workspace import create_workspace, sha256_file, write_json


class ScenarioStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    title: str = ""
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[int] | None = None
    run_after: list[int] = Field(default_factory=list)
    required: bool = True
    evidence_required: bool = True
    evidence_type_required: str | None = None
    screenshot_required: bool = False
    expected_result: str = ""
    verification_checks: list[dict[str, Any]] = Field(default_factory=list)
    requirement_refs: list[str] = Field(default_factory=list)


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    objective: str = Field(min_length=1)
    steps: list[ScenarioStep] = Field(min_length=1, max_length=200)


def plan_scenario(scenario_file: Path, paths: list[Path], root: Path, *, config: AgentConfig,
                  registry: IntegrationRegistry, allowed_targets: set[str] | None = None) -> Path:
    raw = scenario_file.read_text(encoding="utf-8")
    try:
        spec = Scenario.model_validate(yaml.safe_load(raw))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid scenario YAML: {exc}") from exc
    sources = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(path)
        sources.extend(sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path])
    if not sources:
        raise ValueError("Provide at least one input file")
    # Explicit scenarios need no natural-language assignment: binary evidence alone is enough.
    if any(p.suffix.lower() in SUPPORTED for p in sources):
        analysis = analyze(paths)
    else:
        analysis = AssignmentAnalysis(assignment=spec.name, source_files=[str(p.resolve()) for p in sources],
                                      objective=spec.objective, tools=[], requirements=[], screenshot_requirements=[],
                                      expected_outputs=[], limitations=[], extracted_text_files={})
    tasks = []
    for index, step in enumerate(spec.steps, 1):
        values = step.model_dump()
        values["depends_on"] = step.depends_on if step.depends_on is not None else ([index - 1] if index > 1 else [])
        values["title"] = step.title or step.action
        values["description"] = step.description or values["title"]
        tasks.append(PlannedTask(id=index, **values))
    plan = normalize_plan(ExecutionPlan(assignment=analysis.assignment, objective=spec.objective,
                                      steps=tasks, source_files=analysis.source_files,
                                      planner=f"scenario:{spec.name}"), registry)
    validation = validate_plan(plan, registry, PolicyEngine(config, allowed_targets))
    if not validation.ok:
        raise ValueError("Scenario rejected: " + "; ".join(str(e) for e in validation.errors))
    plan.warnings = [str(w) for w in validation.warnings]
    workspace = create_workspace(analysis, plan, root)
    (workspace / "metadata" / "scenario.yaml").write_text(raw, encoding="utf-8")
    write_json(workspace / "metadata" / "scenario.json", {
        "name": spec.name, "source": str(scenario_file.resolve()),
        "sha256": sha256_file(workspace / "metadata" / "scenario.yaml"), "planner_ai_calls": 0})
    write_json(workspace / "metadata" / "authorized_targets.json", sorted(allowed_targets or set()))
    return workspace
