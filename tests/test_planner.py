from __future__ import annotations

from pathlib import Path

import pytest
from assignment_factory import build_assignment_zip

from lab_agent.ai import build_ai_plan, deterministic_plan, plan_schema
from lab_agent.analyzer import analyze
from lab_agent.llm import ProviderError, ScriptedProvider
from lab_agent.planning import validate_plan
from lab_agent.policy import PolicyEngine


def _step(action: str, parameters: dict | None = None, depends_on: list[int] | None = None, **extra) -> dict:
    return {"title": action, "description": action, "action": action,
            "parameters": [{"name": k, "value": str(v)} for k, v in (parameters or {}).items()],
            "depends_on": depends_on or [], "evidence_required": True, "evidence_type_required": None,
            "screenshot_required": False, "expected_result": "", "verification": "", "verification_checks": [],
            "requirement_refs": [], **extra}


def test_analyzer_reads_zip_documents_and_classifies_files(tmp_path: Path) -> None:
    analysis = analyze([build_assignment_zip(tmp_path)])
    roles = {Path(f.path.split("::")[-1]).name: f.role for f in analysis.files}
    assert roles["evidence.dd"] == "evidence_image"
    assert roles["evidence.dd.sha256"] == "checksum"
    assert roles["Assignment_3_RU.docx"] == "assignment"
    assert roles["system_log.txt"] == "suspicious"
    assert "._evidence.dd" not in roles
    image = next(f for f in analysis.files if f.role == "evidence_image")
    assert image.workspace_path.startswith("working/extracted/") and image.sha256
    assert "comparison_results.csv" in analysis.deliverables
    assert any(q.startswith("1. В чем различие") or "различие" in q for q in analysis.questions)
    assert any(section["number"] == "7" for section in analysis.sections)
    assert any(len(value) == 64 for value in analysis.hashes.values())
    assert "Foremost" in " ".join(analysis.tools) or any("forensic" in t.lower() or "autopsy" in t.lower() for t in analysis.tools)


def test_deterministic_plan_uses_adapter_templates(tmp_path: Path, registry) -> None:
    plan = deterministic_plan(analyze([build_assignment_zip(tmp_path)]), registry)
    actions = [t.action for t in plan.steps]
    assert actions[0] == "forensics.verify_image_hash"
    assert "forensics.repair_zip_fragments" in actions and "autopsy.ingest" in actions
    repair = plan.steps[actions.index("forensics.repair_zip_fragments")]
    assert repair.parameters["offsets"] == "0x8000,0xc000"
    after = next(t for t in plan.steps if t.parameters.get("label") == "after")
    assert after.run_after and not after.depends_on
    assert validate_plan(plan, registry).ok, validate_plan(plan, registry).errors


def test_requirement_matching_without_templates(tmp_path: Path, registry) -> None:
    source = tmp_path / "lab.txt"
    source.write_text("1. Calculate SHA256 hash of the inputs\n2. Take a screenshot of the result\n3. Discuss the ethics\n"
                      "4. Open http://localhost:8000/login in the browser\n", encoding="utf-8")
    plan = deterministic_plan(analyze([source]), registry)
    assert [t.action for t in plan.steps] == ["core.hash_inputs", "core.screenshot", "core.manual_review", "browser.visit"]
    assert plan.steps[1].screenshot_required and plan.steps[3].parameters == {"url": "http://localhost:8000/login"}


def test_ai_plan_is_validated_and_mapped(tmp_path: Path, registry, config) -> None:
    source = tmp_path / "lab.txt"
    source.write_text("1. Hash the evidence\n", encoding="utf-8")
    provider = ScriptedProvider([{"objective": "Hash", "steps": [
        _step("core.hash_inputs", verification_checks=[{"type": "file_exists", "fields": [{"name": "path", "value": "results/input_hashes.json"}]}]),
        _step("core.screenshot", {"description": "result"}, [1], screenshot_required=True)]}])
    plan, planner = build_ai_plan(analyze([source]), "openai", registry=registry, config=config, llm=provider,
                                  environment={"applications": {}})
    assert planner == "scripted"
    assert plan.steps[0].verification_checks == [{"type": "file_exists", "path": "results/input_hashes.json"}]
    assert plan.steps[1].depends_on == [1] and plan.steps[1].screenshot_required
    prompt = provider.calls[0]["user"]
    assert "core.hash_inputs" in prompt and "EVIDENCE INVENTORY" in prompt and "input/lab.txt" in prompt


def test_invalid_ai_plan_gets_feedback_then_fallback(tmp_path: Path, registry, config) -> None:
    source = tmp_path / "lab.txt"
    source.write_text("1. Hash the evidence\n", encoding="utf-8")
    bad = {"objective": "x", "steps": [_step("core.hash_file", {"bogus": "1"})]}
    fixed = {"objective": "x", "steps": [_step("core.hash_file", {"path": "input/lab.txt"})]}
    provider = ScriptedProvider([bad, fixed])
    plan, _ = build_ai_plan(analyze([source]), "openai", registry=registry, config=config, llm=provider,
                            environment={"applications": {}})
    assert plan.steps[0].parameters == {"path": "input/lab.txt"}
    assert "PREVIOUS PLAN WAS REJECTED" in provider.calls[1]["user"]

    always_bad = ScriptedProvider(lambda s, u, schema: {"objective": "x", "steps": [_step("core.hash_file", {"bogus": "1"})]})
    plan, planner = build_ai_plan(analyze([source]), "openai", registry=registry, config=config, llm=always_bad,
                                  environment={"applications": {}})
    assert planner == "deterministic" and "fallback" in plan.planner and plan.warnings


def test_ai_cannot_expand_network_scope(tmp_path: Path, registry, config) -> None:
    source = tmp_path / "lab.txt"
    source.write_text("1. Visit the site\n", encoding="utf-8")
    provider = ScriptedProvider(lambda s, u, schema: {"objective": "x", "steps": [_step("browser.visit", {"url": "https://evil.example/"})]})
    config.ai.fallback = "none"
    with pytest.raises(ProviderError, match="not authorized"):
        build_ai_plan(analyze([source]), "openai", registry=registry, config=config, llm=provider, environment={"applications": {}})
    plan, _ = build_ai_plan(analyze([source]), "openai", registry=registry, config=config, llm=ScriptedProvider(
        [{"objective": "x", "steps": [_step("browser.visit", {"url": "https://lab.example.edu/"})]}]),
        environment={"applications": {}}, allowed_targets={"lab.example.edu"})
    assert plan.steps[0].parameters["url"] == "https://lab.example.edu/"


def test_schema_lists_only_registered_capabilities(registry) -> None:
    schema = plan_schema(registry)
    enum = schema["properties"]["steps"]["items"]["properties"]["action"]["enum"]
    assert "forensics.carve" in enum and "packet_tracer.verify_connectivity" in enum and "shell.exec" not in enum


def test_validation_catches_forward_dependencies(tmp_path: Path, registry, config) -> None:
    from lab_agent.models import ExecutionPlan, PlannedTask

    plan = ExecutionPlan(assignment="a", objective="o", source_files=[], steps=[
        PlannedTask(id=1, title="a", description="", action="core.hash_inputs", depends_on=[2]),
        PlannedTask(id=2, title="b", description="", action="core.hash_inputs", verification_checks=[{"type": "magic"}])])
    errors = [str(e) for e in validate_plan(plan, registry, PolicyEngine(config)).errors]
    assert any("must be an earlier step" in e for e in errors) and any("unknown verification check" in e for e in errors)
