from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from lab_agent.cli import main
from lab_agent.context import workspace_context
from lab_agent.credentials import remember_secret
from lab_agent.models import TaskStatus
from lab_agent.runner import execute_workspace
from lab_agent.scenarios import plan_scenario
from lab_agent.workspace import load_state, save_state

SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"


def _plan(tmp_path, config, registry):
    source = tmp_path / "lab.txt"
    source.write_text("Calculate hashes", encoding="utf-8")
    return plan_scenario(SCENARIOS / "hash_inputs.yaml", [source], tmp_path / "ws",
                         config=config, registry=registry)


def test_context_is_read_only_and_hashing_is_opt_in(tmp_path, config, registry, monkeypatch):
    ws = _plan(tmp_path, config, registry)
    before = (ws / "state/state.json").read_bytes()
    monkeypatch.setattr("lab_agent.context.validate_evidence", lambda ws: pytest.fail("unexpected re-hash"))
    summary = workspace_context(ws)
    assert summary["next_action"] == {"kind": "resume", "step": 1}
    assert summary["evidence"]["checked_now"] is False
    assert summary["evidence"]["invalid_now"] is None
    assert (ws / "state/state.json").read_bytes() == before
    with pytest.raises(ValueError, match="Unknown step"):
        workspace_context(ws, step_id=99)


def test_context_bounds_errors_and_redacts_secrets(tmp_path, config, registry):
    ws = _plan(tmp_path, config, registry)
    state = load_state(ws)
    state.plan.steps[0].status = TaskStatus.BLOCKED
    secret = "test-secret-12345"
    remember_secret(secret)
    state.errors = [{"step_id": 1, "error": secret + "x" * 10000}] * 20
    state.plan.steps[0].status_reason = "x" * 295 + secret
    save_state(ws, state)
    summary = workspace_context(ws, limit=1)
    assert len(summary["recent_errors"]) == 1
    assert len(json.dumps(summary)) < 4000
    assert secret not in json.dumps(summary)
    assert summary["steps"][0]["reason"].endswith("***RE")  # redacted before truncation
    assert summary["next_action"]["kind"] == "resolve_blocker"
    with pytest.raises(ValueError, match="limit"):
        workspace_context(ws, limit=0)


def test_scenario_executes_real_hash_and_context_detects_tampering(tmp_path, config, registry):
    ws = _plan(tmp_path, config, registry)
    config.ai.recovery_advice = False
    state = execute_workspace(ws, config=config, registry=registry, generate_report=False,
                              environment={"applications": {}})
    assert state.status == "COMPLETED"
    summary = workspace_context(ws, verify=True)
    assert summary["evidence"]["invalid_now"] == 0
    assert summary["evidence"]["files"]
    target = ws / summary["evidence"]["files"][0]["path"]
    target.write_text("tampered", encoding="utf-8")
    summary = workspace_context(ws, verify=True)
    assert summary["evidence"]["invalid_now"] > 0
    assert summary["next_action"]["kind"] == "inspect_evidence"


@pytest.mark.parametrize("step", [
    {"action": "unknown.tool"},
    {"action": "core.hash_file", "parameters": {"bogus": "x"}},
    {"action": "core.hash_inputs", "depends_on": [2]},
    {"action": "core.hash_inputs", "status": "COMPLETED"},
    {"action": "browser.visit", "parameters": {"url": "https://unauthorized.invalid"}},
])
def test_invalid_scenarios_do_not_create_workspaces(tmp_path, config, registry, step):
    spec = tmp_path / "bad.json"
    spec.write_text(json.dumps({"name": "bad", "objective": "Bad", "steps": [step]}), encoding="utf-8")
    source = tmp_path / "lab.txt"
    source.write_text("Lab", encoding="utf-8")
    with pytest.raises(ValueError):
        plan_scenario(spec, [source], tmp_path / "ws", config=config, registry=registry)
    assert not (tmp_path / "ws").exists()
    assert source.read_text(encoding="utf-8") == "Lab"


def test_checksum_scenario_uses_sequential_dependencies(tmp_path, config, registry):
    image = tmp_path / "evidence.dd"
    image.write_bytes(b"local test evidence")
    checksum = tmp_path / "evidence.dd.sha256"
    checksum.write_text(hashlib.sha256(image.read_bytes()).hexdigest(), encoding="utf-8")
    ws = plan_scenario(SCENARIOS / "verify_image.yaml", [image, checksum], tmp_path / "ws",
                       config=config, registry=registry)
    assert load_state(ws).plan.steps[1].depends_on == [1]
    state = execute_workspace(ws, config=config, registry=registry, generate_report=False,
                              environment={"applications": {}})
    assert state.status == "COMPLETED"
    assert image.read_bytes() == b"local test evidence"


def test_cli_scenario_and_context_do_not_plan_with_ai(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("lab_agent.llm.make_provider", lambda *a, **k: pytest.fail("unexpected AI provider"))
    source = tmp_path / "lab.txt"
    source.write_text("Calculate hashes", encoding="utf-8")
    assert main(["scenario", str(SCENARIOS / "hash_inputs.yaml"), str(source)]) == 0
    ws = json.loads(capsys.readouterr().out)["workspace"]
    assert main(["context", ws, "--step", "1"]) == 0
    detail = json.loads(capsys.readouterr().out)
    assert "parameters" in detail["steps"][0]
    assert detail["counts"] == {"PENDING": 1}
