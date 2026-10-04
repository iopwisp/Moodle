"""Capability-aware planning (AI or deterministic) and AI recovery advice.

The planner sees the assignment text, the classified evidence inventory, the
available environment and the capability catalog of the registry.  It must
answer with a JSON plan whose ``action`` values come from that catalog; the
plan is then validated (capability exists, parameters match the declaration,
dependencies point backwards, verification checks are known, network targets
are authorized).  Invalid AI plans are sent back once with the validation
errors; if the provider still fails the deterministic planner is used (and
the fallback is recorded), unless ``ai.fallback: none``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .config import AgentConfig, get_config
from .integrations.registry import IntegrationRegistry, build_registry
from .llm import (
    LLMProvider,
    ProviderError,
    make_provider,
    provider_from_config,
    resolve_provider_name,
)
from .models import AssignmentAnalysis, ExecutionPlan, PlannedTask
from .planning import PlanValidationError, normalize_plan, validate_plan
from .policy import PolicyEngine

__all__ = ["advise_recovery", "build_ai_plan", "deterministic_plan", "plan_schema", "provider_from_config"]

_NAME_VALUE = {"type": "object", "additionalProperties": False, "properties": {"name": {"type": "string"},
                                                                              "value": {"type": "string"}},
               "required": ["name", "value"]}


def plan_schema(registry: IntegrationRegistry) -> dict[str, Any]:
    capabilities = sorted(capability.name for capability in registry.capabilities())
    check = {"type": "object", "additionalProperties": False,
             "properties": {"type": {"type": "string"}, "fields": {"type": "array", "items": _NAME_VALUE}},
             "required": ["type", "fields"]}
    item = {
        "type": "object", "additionalProperties": False,
        "properties": {
            "title": {"type": "string"}, "description": {"type": "string"},
            "action": {"type": "string", "enum": capabilities},
            "parameters": {"type": "array", "description": "name/value parameters of the capability", "items": _NAME_VALUE},
            "depends_on": {"type": "array", "items": {"type": "integer"}},
            "evidence_required": {"type": "boolean"},
            "evidence_type_required": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "screenshot_required": {"type": "boolean"},
            "expected_result": {"type": "string"}, "verification": {"type": "string"},
            "verification_checks": {"type": "array", "items": check},
            "requirement_refs": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["title", "description", "action", "parameters", "depends_on", "evidence_required",
                     "evidence_type_required", "screenshot_required", "expected_result", "verification",
                     "verification_checks", "requirement_refs"],
    }
    return {"type": "object", "additionalProperties": False,
            "properties": {"objective": {"type": "string"}, "steps": {"type": "array", "items": item}},
            "required": ["objective", "steps"]}


SYSTEM_PROMPT = (
    "You plan the execution of an authorized university laboratory assignment. Return JSON only. "
    "Use only capabilities from the catalog; never invent capabilities, shell commands, file paths outside the "
    "inventory, mouse coordinates, credentials or network targets."
)


def _prompt(analysis: AssignmentAnalysis, registry: IntegrationRegistry, environment: dict[str, Any] | None,
            targets: set[str], feedback: list[str] | None = None) -> str:
    inventory = "\n".join(
        f"- {f.workspace_path or f.path} | role={f.role} | {f.size} bytes{' | ' + f.note if f.note else ''}" for f in analysis.files
    ) or "\n".join(f"- {p}" for p in analysis.source_files)
    apps = environment.get("applications", {}) if environment else {}
    env_lines = "\n".join(f"- {name}: {'available ' + str(info.get('version') or '') if info.get('available') else 'NOT available'}"
                          for name, info in sorted(apps.items())) or "- unknown (not discovered)"
    corpus = "\n\n".join(f"FILE: {path}\n{text[:30000]}" for path, text in analysis.extracted_text_files.items()
                         if not text.startswith("[ZIP member"))[:120000]
    parts = [
        "CAPABILITY CATALOG (tool.action: description, parameters, evidence, verification):",
        registry.catalog(),
        "\nEVIDENCE INVENTORY (use these workspace paths in parameters):",
        inventory,
        "\nENVIRONMENT:",
        env_lines,
        f"\nAUTHORIZED NETWORK TARGETS: localhost, 127.0.0.1{', ' + ', '.join(sorted(targets)) if targets else ''}",
        "\nRULES:",
        "- action MUST be a catalog capability; parameters only those it declares, as name/value strings.",
        "- Steps are numbered from 1 in order; depends_on lists earlier step numbers whose success is required.",
        ("- Prefer capabilities that produce verifiable evidence; add verification_checks (types: file_exists, text_contains, "
         "hash_match, csv_rows, zip_valid, pdf_valid, image_valid, sqlite_query, details_value, http_status, port_open, "
         "window_exists) describing observable post-conditions."),
        ("- Mark screenshot_required when the assignment asks for a screenshot of that step; link requirement_refs to the "
         "assignment sentences each step satisfies."),
        ("- When something cannot be automated safely (essay answers, logins with captcha, canvas drawing) use "
         "core.manual_review with a precise reason instead of pretending."),
        "- Do not plan capabilities whose application is NOT available unless no alternative exists; they will be BLOCKED.",
    ]
    if feedback:
        parts += ["\nYOUR PREVIOUS PLAN WAS REJECTED. Fix these problems:", *[f"- {item}" for item in feedback]]
    parts += ["\nASSIGNMENT MATERIALS:", corpus]
    return "\n".join(parts)


def _pairs(items: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in items:
        name = str(item.get("name", "")).strip()
        if not name:
            raise ValueError("parameter names cannot be empty")
        result[name] = item.get("value")
    return result


def plan_from_payload(analysis: AssignmentAnalysis, value: dict[str, Any], registry: IntegrationRegistry,
                      planner: str) -> ExecutionPlan:
    tasks: list[PlannedTask] = []
    for index, raw in enumerate(value["steps"], start=1):
        action = registry.normalize(str(raw["action"]))
        checks = [{"type": check["type"], **_pairs(check.get("fields", []))} for check in raw.get("verification_checks", [])]
        tasks.append(PlannedTask(
            id=index, title=str(raw["title"])[:160], description=str(raw["description"]),
            tool=registry.capability(action).tool if registry.has(action) else action.split(".")[0],
            action=action, parameters=_pairs(raw.get("parameters", [])),
            depends_on=[int(d) for d in raw.get("depends_on", [])],
            evidence_required=bool(raw.get("evidence_required")), evidence_type_required=raw.get("evidence_type_required"),
            screenshot_required=bool(raw.get("screenshot_required")),
            expected_result=str(raw.get("expected_result", "")), verification=str(raw.get("verification", "")),
            verification_checks=checks, requirement_refs=[str(r)[:300] for r in raw.get("requirement_refs", [])],
        ))
    return ExecutionPlan(assignment=analysis.assignment, objective=str(value.get("objective") or analysis.objective),
                         steps=tasks, source_files=analysis.source_files, planner=planner)


def ai_plan(analysis: AssignmentAnalysis, provider: LLMProvider, registry: IntegrationRegistry, policy: PolicyEngine,
            environment: dict[str, Any] | None = None, attempts: int = 2) -> ExecutionPlan:
    feedback: list[str] | None = None
    last_error: Exception | None = None
    for _ in range(max(1, attempts)):
        answer = provider.complete_json(SYSTEM_PROMPT, _prompt(analysis, registry, environment, policy.targets, feedback),
                                        plan_schema(registry), name="lab_plan")
        try:
            label = f"{provider.name}:{provider.model}" if provider.model else provider.name
            plan = plan_from_payload(analysis, answer, registry, label)
        except (KeyError, ValueError) as exc:
            last_error, feedback = exc, [str(exc)]
            continue
        validation = validate_plan(plan, registry, policy)
        if validation.ok:
            plan.warnings = [str(issue) for issue in validation.warnings]
            return plan
        last_error, feedback = PlanValidationError(validation), [str(issue) for issue in validation.errors]
    raise ProviderError(f"AI plan rejected after {attempts} attempt(s): {last_error}")


# ---------------------------------------------------------------------------- deterministic
def _score(capability: Any, text: str) -> float:
    return float(sum(1 for keyword in capability.keywords if keyword.lower() in text))


QUESTION_RE = re.compile(
    r"\?\s*$|^\W*(что|как|почему|зачем|какой|какая|какие|каким|какую|в\s+ч[её]м|чем|сколько|объясните|опишите|сравните|"
    r"докажите|поясните|what|why|how|which|when|explain|describe|compare|discuss)\b", re.IGNORECASE)


def is_question(requirement: str) -> bool:
    """Theory the student answers in writing - never an action for a tool, whatever keywords it contains."""
    return bool(QUESTION_RE.search(requirement.strip()))


def _answers_task(index: int, questions: list[str], language_hint: str) -> PlannedTask:
    russian = bool(re.search(r"[А-Яа-яЁё]", language_hint))
    return PlannedTask(
        id=index, title="Ответы на вопросы" if russian else "Answers to the questions",
        description="\n".join(questions), tool="core", action="core.manual_review",
        parameters={"reason": "The analytical questions require the student's own written answers; the agent does not write them."},
        requirement_refs=[q[:300] for q in questions[:60]])


def deterministic_plan(analysis: AssignmentAnalysis, registry: IntegrationRegistry) -> ExecutionPlan:
    """Adapter workflow templates first; otherwise match each requirement to a capability by keywords."""
    templated: list[dict[str, Any]] = []
    for adapter in registry.adapters():
        hook = getattr(adapter, "plan_templates", None)
        if callable(hook):
            proposal = hook(analysis, registry) or []
            offset = len(templated)
            for step in proposal:
                step = dict(step)
                step["depends_on"] = [d + offset for d in step.get("depends_on", [])]
                step["run_after"] = [d + offset for d in step.get("run_after", [])]
                templated.append(step)
    tasks: list[PlannedTask] = []
    if templated:
        for index, step in enumerate(templated, start=1):
            capability = registry.capability(step["action"])
            evidence_type = step.get("evidence_type")
            tasks.append(PlannedTask(
                id=index, title=step["title"], description=step.get("description", step["title"]), tool=capability.tool,
                action=capability.name, parameters=dict(step.get("parameters", {})), depends_on=step["depends_on"],
                run_after=step["run_after"], required=bool(step.get("required", True)),
                evidence_required=evidence_type is not None, evidence_type_required=evidence_type,
                expected_result=capability.verification, verification=capability.verification,
                requirement_refs=[step["requirement"]] if step.get("requirement") else [],
            ))
    else:
        actions = [r for r in analysis.requirements if not is_question(r)] or ([] if analysis.requirements else [analysis.objective])
        for index, requirement in enumerate(actions, start=1):
            tasks.append(_match_requirement(index, requirement, analysis, registry))
    questions = list(dict.fromkeys([*analysis.questions, *(r for r in analysis.requirements if is_question(r))]))
    if questions and not any(t.action == "core.manual_review" and "answers" in str(t.parameters.get("reason", "")).lower()
                             for t in tasks):
        tasks.append(_answers_task(len(tasks) + 1, questions, analysis.title or analysis.objective))
    plan = ExecutionPlan(assignment=analysis.assignment, objective=analysis.title or analysis.objective, steps=tasks,
                         source_files=analysis.source_files, planner="deterministic")
    return normalize_plan(plan, registry)


def _match_requirement(index: int, requirement: str, analysis: AssignmentAnalysis, registry: IntegrationRegistry) -> PlannedTask:
    lowered = requirement.lower()
    screenshot = any(term in lowered for term in ("screenshot", "screen shot", "скриншот", "снимок экрана"))
    best: tuple[float, str, dict[str, Any]] | None = None
    for adapter in registry.adapters():
        hook = getattr(adapter, "match_requirement", None)
        if callable(hook):
            match = hook(requirement, analysis)
            if match and (best is None or match[2] > best[0]):
                best = (match[2], match[0], match[1])
    for capability in registry.capabilities():
        score = _score(capability, lowered)
        if score <= 0 or any(p.required for p in capability.params()) or capability.risk != "safe":
            continue
        if best is None or score > best[0]:
            best = (score, capability.name, {})
    if best is None:
        return PlannedTask(id=index, title=requirement[:120], description=requirement, tool="core", action="core.manual_review",
                           parameters={"reason": "No registered capability can perform this requirement automatically."},
                           requirement_refs=[requirement[:300]], screenshot_required=screenshot)
    capability = registry.capability(best[1])
    evidence_type = "screenshot" if screenshot and "screenshot" in capability.evidence_types else (
        capability.evidence_types[0] if capability.evidence_types else None)
    parameters = dict(best[2])
    if capability.name == "core.screenshot":
        parameters.setdefault("description", requirement[:200])
    return PlannedTask(id=index, title=requirement[:120], description=requirement, tool=capability.tool, action=capability.name,
                       parameters=parameters, evidence_required=evidence_type is not None, evidence_type_required=evidence_type,
                       screenshot_required=screenshot, expected_result=capability.verification,
                       verification=capability.verification, requirement_refs=[requirement[:300]])


# ---------------------------------------------------------------------------- entry point
def build_ai_plan(
    analysis: AssignmentAnalysis,
    provider: str = "auto",
    model: str | None = None,
    *,
    registry: IntegrationRegistry | None = None,
    config: AgentConfig | None = None,
    environment: dict[str, Any] | None = None,
    allowed_targets: set[str] | None = None,
    llm: LLMProvider | None = None,
) -> tuple[ExecutionPlan, str]:
    config = config or get_config()
    registry = registry or build_registry(config=config)
    policy = PolicyEngine(config, allowed_targets)
    name = resolve_provider_name(provider if provider != "auto" else config.ai.provider if config.ai.provider != "auto" else "auto")
    if name not in {"deterministic", "openai", "ollama", "codex"} and llm is None:
        raise ValueError("AI provider must be auto, openai, ollama, codex, or deterministic.")
    if llm is None and name != "deterministic":
        try:
            llm = make_provider(name, model, config)
        except ProviderError:
            if config.ai.fallback == "none":
                raise
            llm = None
    if llm is not None:
        try:
            plan = ai_plan(analysis, llm, registry, policy, environment, attempts=config.ai.max_retries + 1)
            return plan, llm.name
        except (ProviderError, ValueError) as exc:
            if config.ai.fallback == "none":
                raise
            plan = deterministic_plan(analysis, registry)
            plan.planner = f"deterministic (fallback: {exc})"[:500]
            plan.warnings.append(f"AI planner failed and the deterministic planner was used: {exc}")
            return plan, "deterministic"
    plan = deterministic_plan(analysis, registry)
    validation = validate_plan(plan, registry, policy)
    plan.warnings = [str(issue) for issue in validation.issues]
    return plan, "deterministic"


# ---------------------------------------------------------------------------- recovery advice
ADVICE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "decision": {"type": "string", "enum": ["retry", "replace_parameters", "insert_step", "stop", "ask_human"]},
        "reason": {"type": "string"},
        "parameters": {"type": "array", "items": _NAME_VALUE},
        "step_action": {"type": "string"},
    },
    "required": ["decision", "reason", "parameters", "step_action"],
}


def advise_recovery(provider: LLMProvider, registry: IntegrationRegistry, task: PlannedTask, error: str,
                    observation: dict[str, Any]) -> dict[str, Any]:
    """Ask the AI what to do after a failed/unverified step; the answer is validated before use."""
    payload = {
        "step": {"id": task.id, "title": task.title, "capability": task.action, "parameters": task.parameters,
                 "expected_result": task.expected_result},
        "error": error[:3000],
        "observation": observation,
        "catalog": registry.catalog()[:20000],
        "rules": "Only propose parameters declared by the capability or another catalog capability (insert_step). "
                 "Never widen network scope; ask_human when unsure.",
    }
    answer = provider.complete_json("You diagnose failed lab automation steps. Return JSON only.",
                                    json.dumps(payload, ensure_ascii=False, default=str)[:60000], ADVICE_SCHEMA, name="recovery")
    parameters = _pairs(answer.get("parameters", []))
    action = registry.normalize(answer.get("step_action") or task.action)
    if answer["decision"] in {"replace_parameters", "insert_step"}:
        if not registry.has(action):
            return {"decision": "ask_human", "reason": f"AI proposed unknown capability {action}"}
        problems = registry.validate_parameters(action, parameters)
        if problems:
            return {"decision": "ask_human", "reason": "AI proposal invalid: " + "; ".join(problems)}
    return {"decision": answer["decision"], "reason": answer["reason"], "parameters": parameters, "action": action}

