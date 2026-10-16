from __future__ import annotations

import json
from pathlib import Path

import pytest

from lab_agent.cli import main
from lab_agent.delivery import review_workspace
from lab_agent.orchestration import orchestrate_assignment
from lab_agent.workspace import load_state, save_state


def _assignment(tmp_path, config, registry, *, execute=True):
    source = tmp_path / "assignment.txt"
    source.write_text("1. Calculate SHA256 hash of the input files.\n", encoding="utf-8")
    result = orchestrate_assignment([source], tmp_path / "ws", execute=execute,
                                    config=config, registry=registry, environment={"applications": {}},
                                    generate_report=False)
    return source, Path(result["workspace"]), result


def test_orchestration_executes_without_ai_and_retains_pending_delivery_review(tmp_path, config, registry, monkeypatch):
    def no_ai(*args, **kwargs):
        pytest.fail("AI planner/recovery should not be called")

    monkeypatch.setattr("lab_agent.ai.make_provider", no_ai)
    monkeypatch.setattr("lab_agent.llm.make_provider", no_ai)
    _, ws, result = _assignment(tmp_path, config, registry)
    assert result["status"] == "COMPLETED"
    assert result["execution_ready"] is True
    assert "required" in result["delivery_review"]
    brief = json.loads((ws / result["assignment_brief"]).read_text(encoding="utf-8"))
    assert brief["requirements"] and brief["coverage_review"].startswith("pending")


def test_resume_uses_existing_workspace_and_preserves_brief(tmp_path, config, registry):
    _, ws, _ = _assignment(tmp_path, config, registry, execute=False)
    brief = ws / "metadata/assignment_brief.json"
    brief.write_text('{"user_notes":"preserve"}', encoding="utf-8")
    result = orchestrate_assignment([], tmp_path / "ws", workspace=ws, execute=True,
                                    config=config, registry=registry, environment={"applications": {}},
                                    generate_report=False)
    assert result["execution_ready"] is True
    assert len(list((tmp_path / "ws").iterdir())) == 1
    assert json.loads(brief.read_text(encoding="utf-8")) == {"user_notes": "preserve"}


@pytest.mark.parametrize("damage", ["source", "copy", "missing_source", "missing_screenshot", "empty_plan"])
def test_review_never_accepts_broken_integrity_or_missing_screenshot(tmp_path, config, registry, damage):
    source, ws, _ = _assignment(tmp_path, config, registry)
    assert review_workspace(ws)["ready"] is True
    if damage == "source":
        source.write_text("changed original", encoding="utf-8")
    elif damage == "missing_source":
        source.unlink()
    elif damage == "copy":
        (ws / "input" / source.name).write_text("changed copy", encoding="utf-8")
    else:
        state = load_state(ws)
        if damage == "missing_screenshot":
            state.plan.steps[0].screenshot_required = True
        else:
            state.plan.steps = []
        save_state(ws, state)
    result = review_workspace(ws)
    assert result["ready"] is False
    if damage == "missing_screenshot":
        assert result["missing_required_screenshot_steps"] == [1]


def test_assignment_cli_defaults_to_deterministic_and_rejects_ambiguous_inputs(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("lab_agent.runner.discover_environment", lambda *a, **k: {"applications": {}})
    source = tmp_path / "assignment.txt"
    source.write_text("1. Calculate SHA256 hash\n", encoding="utf-8")
    assert main(["assignment", str(source)]) == 0
    result = json.loads(capsys.readouterr().out)
    ws = Path(result["workspace"])
    assert load_state(ws).plan.planner == "deterministic"
    assert main(["assignment", str(source), "--workspace", str(ws)]) == 2
    assert "either input paths" in capsys.readouterr().err
    assert main(["assignment"]) == 2
