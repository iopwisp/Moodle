"""AI planners that turn an assignment into a constrained execution plan."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .analyzer import build_plan
from .models import AssignmentAnalysis, ExecutionPlan, PlannedTask

ALLOWED_ACTIONS = {"hash_inputs", "desktop", "browser", "screenshot", "manual_review"}


def _plan_schema() -> dict[str, Any]:
    item = {
        "type": "object", "additionalProperties": False,
        "properties": {
            "title": {"type": "string"}, "description": {"type": "string"},
            "tool": {"type": "string"}, "action": {"type": "string", "enum": sorted(ALLOWED_ACTIONS)},
            "parameters": {"type": "object", "additionalProperties": False,
                           "properties": {"profile": {"type": "string"}, "operation": {"type": "string"}, "url": {"type": "string"}},
                           "required": ["profile", "operation", "url"]},
            "evidence_required": {"type": "boolean"}, "evidence_type_required": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "expected_result": {"type": "string"}, "verification": {"type": "string"},
        },
        "required": ["title", "description", "tool", "action", "parameters", "evidence_required", "evidence_type_required", "expected_result", "verification"],
    }
    return {
        "type": "object", "additionalProperties": False,
        "properties": {"objective": {"type": "string"}, "steps": {"type": "array", "items": item}},
        "required": ["objective", "steps"],
    }


def _prompt(analysis: AssignmentAnalysis) -> str:
    corpus = "\n\n".join(f"FILE: {path}\n{text[:30000]}" for path, text in analysis.extracted_text_files.items())
    return """Build a JSON plan for an authorized university lab assignment. Use only these actions: hash_inputs, desktop, browser, screenshot, manual_review. Never produce shell commands, destructive operations, arbitrary network targets, passwords, or raw coordinates. A desktop action must set parameters.profile to autopsy or burp and parameters.operation to one documented workflow operation. A browser action must set parameters.url to a localhost or explicitly authorized URL found in the assignment. Every visible desktop or browser result needs screenshot evidence. Keep requirements separate and concrete.\n\n""" + corpus


def _from_payload(analysis: AssignmentAnalysis, value: dict[str, Any]) -> ExecutionPlan:
    tasks: list[PlannedTask] = []
    for index, raw in enumerate(value["steps"], start=1):
        action = raw["action"]
        if action not in ALLOWED_ACTIONS:
            raise ValueError(f"AI produced unsupported action: {action}")
        tasks.append(PlannedTask(id=index, title=raw["title"][:160], description=raw["description"], tool=raw["tool"],
                                 action=action, parameters=raw["parameters"], evidence_required=raw["evidence_required"],
                                 evidence_type_required=raw["evidence_type_required"], expected_result=raw["expected_result"],
                                 verification=raw["verification"]))
    if not tasks:
        raise ValueError("AI returned a plan without tasks")
    return ExecutionPlan(assignment=analysis.assignment, objective=value["objective"], steps=tasks, source_files=analysis.source_files)


def _openai_plan(analysis: AssignmentAnalysis, model: str) -> ExecutionPlan:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is required for the OpenAI planner.")
    body = {"model": model, "input": [{"role": "system", "content": "Return the requested JSON only."}, {"role": "user", "content": _prompt(analysis)}],
            "text": {"format": {"type": "json_schema", "name": "lab_plan", "strict": True, "schema": _plan_schema()}}}
    request = urllib.request.Request("https://api.openai.com/v1/responses", data=json.dumps(body).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
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
    return _from_payload(analysis, json.loads(text))


def _ollama_plan(analysis: AssignmentAnalysis, model: str) -> ExecutionPlan:
    endpoint = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/") + "/api/chat"
    body = {"model": model, "stream": False, "format": _plan_schema(), "messages": [{"role": "system", "content": "Return valid JSON only."}, {"role": "user", "content": _prompt(analysis)}]}
    request = urllib.request.Request(endpoint, data=json.dumps(body).encode(), method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            answer = json.loads(response.read())
    except urllib.error.URLError as exc:
        raise RuntimeError("Ollama planner is unavailable.") from exc
    return _from_payload(analysis, json.loads(answer["message"]["content"]))


def build_ai_plan(analysis: AssignmentAnalysis, provider: str = "auto", model: str | None = None) -> tuple[ExecutionPlan, str]:
    provider = provider.lower()
    if provider == "auto":
        provider = "openai" if os.environ.get("OPENAI_API_KEY") else "ollama" if os.environ.get("OLLAMA_HOST") else "deterministic"
    if provider == "openai":
        return _openai_plan(analysis, model or "gpt-6-astra"), "openai"
    if provider == "ollama":
        return _ollama_plan(analysis, model or "qwen2.5:14b"), "ollama"
    if provider == "deterministic":
        plan = build_plan(analysis)
        for task in plan.steps:
            lowered = task.description.lower()
            if "sha" in lowered or "hash" in lowered:
                task.action = "hash_inputs"
            elif "autopsy" in lowered:
                task.action, task.parameters = "desktop", {"profile": "autopsy", "operation": "launch"}
            elif "burp" in lowered:
                task.action, task.parameters = "desktop", {"profile": "burp", "operation": "launch"}
            elif "http" in lowered or "browser" in lowered:
                task.action = "browser"
            elif task.evidence_type_required == "screenshot":
                task.action = "screenshot"
        return plan, "deterministic"
    raise ValueError("AI provider must be auto, openai, ollama, or deterministic.")
