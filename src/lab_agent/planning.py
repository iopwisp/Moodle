"""Plan validation: every step must be executable, ordered and within scope."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .integrations.registry import IntegrationRegistry
from .models import ExecutionPlan
from .policy import PolicyEngine
from .verification import check_types


@dataclass
class PlanIssue:
    step_id: int | None
    message: str
    severity: str = "error"  # error | warning

    def __str__(self) -> str:
        prefix = f"step {self.step_id}: " if self.step_id is not None else ""
        return f"{prefix}{self.message}"


@dataclass
class PlanValidation:
    issues: list[PlanIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[PlanIssue]:
        return [issue for issue in self.issues if issue.severity == "error"]

    @property
    def warnings(self) -> list[PlanIssue]:
        return [issue for issue in self.issues if issue.severity == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors


class PlanValidationError(ValueError):
    def __init__(self, validation: PlanValidation) -> None:
        self.validation = validation
        super().__init__("Invalid plan: " + "; ".join(str(issue) for issue in validation.errors[:10]))


def validate_plan(plan: ExecutionPlan, registry: IntegrationRegistry, policy: PolicyEngine | None = None) -> PlanValidation:
    result = PlanValidation()
    known_checks = set(check_types())
    ids = [task.id for task in plan.steps]
    if len(ids) != len(set(ids)):
        result.issues.append(PlanIssue(None, "step ids must be unique"))
    if not plan.steps:
        result.issues.append(PlanIssue(None, "plan has no steps"))
    seen: set[int] = set()
    for task in plan.steps:
        if not registry.has(task.action):
            result.issues.append(PlanIssue(task.id, f"unknown capability {task.action!r}"))
            seen.add(task.id)
            continue
        for problem in registry.validate_parameters(task.action, task.parameters):
            result.issues.append(PlanIssue(task.id, f"{task.action}: {problem}"))
        for dependency in [*task.depends_on, *task.run_after]:
            if dependency not in seen:
                result.issues.append(PlanIssue(task.id, f"dependency {dependency} must be an earlier step"))
        for check in task.verification_checks:
            if check.get("type") not in known_checks:
                result.issues.append(PlanIssue(task.id, f"unknown verification check {check.get('type')!r}"))
        if policy is not None:
            capability = registry.capability(task.action)
            decision = policy.check(capability, task.parameters)
            if not decision.allowed:
                severity = "error" if capability.network or "network" in decision.reason.lower() or "not authorized" in decision.reason else "warning"
                result.issues.append(PlanIssue(task.id, decision.reason, severity))
            elif decision.confirmation_required:
                result.issues.append(PlanIssue(task.id, f"will ask for approval: {decision.reason}", "warning"))
        seen.add(task.id)
    return result


def normalize_plan(plan: ExecutionPlan, registry: IntegrationRegistry) -> ExecutionPlan:
    """Canonical capability names and tool fields (legacy aliases -> namespaced names)."""
    for task in plan.steps:
        task.action = registry.normalize(task.action)
        if registry.has(task.action):
            task.tool = registry.capability(task.action).tool
    return plan


def plan_summary(plan: ExecutionPlan) -> list[dict[str, Any]]:
    return [{"id": t.id, "title": t.title, "capability": t.action, "depends_on": t.depends_on, "run_after": t.run_after,
             "required": t.required} for t in plan.steps]
