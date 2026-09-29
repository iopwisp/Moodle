"""AI planners that turn an assignment into a validated capability plan."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .analyzer import build_plan
from .automation import urls_from_text
from .integrations.registry import IntegrationRegistry, build_registry
from .models import AssignmentAnalysis, ExecutionPlan, PlannedTask


def _plan_schema(registry: IntegrationRegistry) -> dict[str, Any]:
    capabilities = sorted(capability.name for capability in registry.capabilities())
    item = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "title": {"type": "string"},
            "description": {"type": "string"},
            "tool": {"type": "string"},
            "action": {"type": "string", "enum": capabilities},
            "parameters": {
                "type": "array",
                "description": "Extensible name/value parameters for the selected capability.",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "name": {"type": "string"},
                        "value": {"type": "string"},
                    },
                    "required": ["name", "value"],
                },
            },
            "evidence_required": {"type": "boolean"},
            "evidence_type_required": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "expected_result": {"type": "string"},
            "verification": {"type": "string"},
        },
        "required": [
            "title", "description", "tool", "action", "parameters",
            "evidence_required", "evidence_type_required", "expected_result", "verification",
        ],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "objective": {"type": "string"},
            "steps": {"type": "array", "items": item},
        },
        "required": ["objective", "steps"],
    }


def _prompt(analysis: AssignmentAnalysis, registry: IntegrationRegistry) -> str:
    corpus = "\n\n".join(
        f"FILE: {path}\n{text[:30000]}" for path, text in analysis.extracted_text_files.items()
    )
    catalog = "\n".join(
        capability.as_prompt_line() for capability in registry.capabilities()
    )
    return (
        """Build a JSON execution plan for an authorized university laboratory assignment.

Capability catalog:
"""
        + catalog
        + """

Rules:
- action MUST be one of the capability names above.
- Put capability-specific values into parameters as name/value pairs.
- Never invent shell commands, destructive operations, passwords, raw mouse coordinates,
  or arbitrary network targets.
- Every visible result required by the assignment must have evidence.
- Prefer an end-to-end capability when one exists, instead of reducing the workflow to
  unrelated manual_review steps.
- Verification must describe an observable post-condition, not merely "the action ran".

"""
        + corpus
    )


def _from_payload(
    analysis: AssignmentAnalysis,
    value: dict[str, Any],
    registry: IntegrationRegistry,
) -> ExecutionPlan:
    tasks: list[PlannedTask] = []
    for index, raw in enumerate(value["steps"], start=1):
        action = registry.normalize(raw["action"])
        if not registry.has(action):
            raise ValueError(f"AI produced unsupported capability: {action}")
        parameters: dict[str, Any] = {}
        for item in raw.get("parameters", []):
            name = str(item["name"]).strip()
            if not name:
                raise ValueError("Capability parameter names cannot be empty.")
            parameters[name] = item["value"]
        capability = registry.capability(action)
        tasks.append(
            PlannedTask(
                id=index,
                title=raw["title"][:160],
                description=raw["description"],
                tool=capability.tool,
                action=action,
                parameters=parameters,
                evidence_required=raw["evidence_required"],
                evidence_type_required=raw["evidence_type_required"],
                expected_result=raw["expected_result"],
                verification=raw["verification"],
            )
        )
    if not tasks:
        raise ValueError("AI returned a plan without tasks")
    return ExecutionPlan(
        assignment=analysis.assignment,
        objective=value["objective"],
        steps=tasks,
        source_files=analysis.source_files,
    )


def _openai_plan(
    analysis: AssignmentAnalysis,
    model: str,
    registry: IntegrationRegistry,
) -> ExecutionPlan:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is required for the OpenAI planner.")
    body = {
        "model": model,
        "input": [
            {
                "role": "system",
                "content": "Return the requested JSON only. Select only capabilities from the supplied catalog.",
            },
            {"role": "user", "content": _prompt(analysis, registry)},
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "lab_plan",
                "strict": True,
                "schema": _plan_schema(registry),
            }
        },
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            answer = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"OpenAI planner request failed: HTTP {exc.code}") from exc
    text = answer.get("output_text")
    if not text:
        for output in answer.get("output", []):
            for content in output.get("content", []):
                if content.get("type") == "output_text":
                    text = content.get("text")
                    break
    if not text:
        raise RuntimeError("OpenAI planner returned no text output.")
    return _from_payload(analysis, json.loads(text), registry)


def _ollama_plan(
    analysis: AssignmentAnalysis,
    model: str,
    registry: IntegrationRegistry,
) -> ExecutionPlan:
    endpoint = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/") + "/api/chat"
    body = {
        "model": model,
        "stream": False,
        "format": _plan_schema(registry),
        "messages": [
            {"role": "system", "content": "Return valid JSON only using the supplied capability catalog."},
            {"role": "user", "content": _prompt(analysis, registry)},
        ],
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            answer = json.loads(response.read())
    except urllib.error.URLError as exc:
        raise RuntimeError("Ollama planner is unavailable.") from exc
    return _from_payload(analysis, json.loads(answer["message"]["content"]), registry)


def _deterministic_plan(
    analysis: AssignmentAnalysis,
    registry: IntegrationRegistry,
) -> ExecutionPlan:
    plan = build_plan(analysis)
    for task in plan.steps:
        lowered = task.description.lower()
        if any(term in lowered for term in ("autopsy", "disk image", ".dd", ".e01", "forensic")):
            task.action = "autopsy.e2e"
            task.parameters = {}
            task.evidence_required = True
            task.evidence_type_required = "screenshot"
        elif "sha" in lowered or "hash" in lowered:
            task.action = "core.hash_inputs"
            task.parameters = {}
            task.evidence_required = True
            task.evidence_type_required = "hash"
        elif "burp" in lowered:
            task.action = "desktop.profile"
            task.parameters = {"profile": "burp", "operation": "launch"}
        elif "http" in lowered or "browser" in lowered:
            urls = urls_from_text(task.description)
            task.action = "browser.visit"
            task.parameters = {"url": urls[0]} if urls else {}
        elif task.evidence_type_required == "screenshot":
            task.action = "core.screenshot"
            task.parameters = {"description": task.description}
    for task in plan.steps:
        if not registry.has(task.action):
            raise ValueError(f"Deterministic planner selected unavailable capability: {task.action}")
    return plan


def build_ai_plan(
    analysis: AssignmentAnalysis,
    provider: str = "auto",
    model: str | None = None,
) -> tuple[ExecutionPlan, str]:
    registry = build_registry()
    provider = provider.lower()
    if provider == "auto":
        provider = (
            "openai" if os.environ.get("OPENAI_API_KEY")
            else "ollama" if os.environ.get("OLLAMA_HOST")
            else "deterministic"
        )
    if provider == "openai":
        return _openai_plan(analysis, model or "gpt-6-astra", registry), "openai"
    if provider == "ollama":
        return _ollama_plan(analysis, model or "qwen2.5:14b", registry), "ollama"
    if provider == "deterministic":
        return _deterministic_plan(analysis, registry), "deterministic"
    raise ValueError("AI provider must be auto, openai, ollama, or deterministic.")
