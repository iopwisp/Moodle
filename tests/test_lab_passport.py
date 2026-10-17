from __future__ import annotations

import json
from pathlib import Path

import pytest

from lab_agent.cli import main
from lab_agent.context import workspace_context
from lab_agent.integrations.base import (
    BaseIntegration,
    Capability,
    CapabilityBlocked,
    ExecutionContext,
    IntegrationResult,
    Param,
)
from lab_agent.integrations.registry import IntegrationRegistry
from lab_agent.lab_passport import load_passport, passport_summary, save_passport
from lab_agent.policy import PolicyEngine
from lab_agent.scenarios import plan_scenario

QUOTE = "Use only lab.local in this authorized university exercise."


@pytest.fixture
def lab(tmp_path, config, registry):
    note = tmp_path / "authorization.txt"
    note.write_text(QUOTE, encoding="utf-8")
    scenario = Path(__file__).resolve().parents[1] / "scenarios/hash_inputs.yaml"
    ws = plan_scenario(scenario, [note], tmp_path / "runs", config=config, registry=registry)
    config.policy.network.authorized_targets = ["lab.local", "other.local"]
    values = {"name": "Local exercise", "purpose": "Inspect the university lab", "owner": "Student VM",
              "source": "input/authorization.txt", "excerpt": QUOTE,
              "targets": ["lab.local"], "actions": ["browser.visit"],
              "restrictions": ["No external systems"]}
    return ws, values


def test_passport_keeps_source_hash_and_compact_context(lab, registry):
    ws, values = lab
    saved = save_passport(ws, values, {c.name for c in registry.capabilities()})
    assert len(saved.source_sha256) == 64
    assert load_passport(ws) == saved
    summary = workspace_context(ws)["lab_scope"]
    assert summary["valid"] and summary["targets"] == ["lab.local"] and summary["excerpt"] == QUOTE
    with pytest.raises(ValueError, match="already exists"):
        save_passport(ws, values, set(values["actions"]))


def test_pdf_source_works_with_relative_paths_and_detects_changed_metadata(lab, registry):
    from reportlab.pdfgen.canvas import Canvas

    ws, values = lab
    source = ws / "input/instruction.pdf"
    canvas = Canvas(str(source))
    canvas.drawString(40, 700, QUOTE)
    canvas.save()
    save_passport(ws, {**values, "source": "input/instruction.pdf"}, {c.name for c in registry.capabilities()})
    assert load_passport(ws).excerpt == QUOTE
    path = ws / "metadata/lab_passport.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["excerpt"] = "Fabricated permission from edited metadata"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert passport_summary(ws)["valid"] is False


@pytest.mark.parametrize("change", [
    {"excerpt": "Invented authorization"}, {"source": "../authorization.txt"},
    {"targets": ["*.local"]}, {"targets": ["10.0.0.0/8"]},
    {"targets": ["https://lab.local/path"]}, {"targets": ["lab.local:8080"]},
    {"actions": ["invented.action"]},
])
def test_invalid_scope_never_creates_passport(lab, registry, change):
    ws, values = lab
    with pytest.raises(ValueError):
        save_passport(ws, {**values, **change}, {c.name for c in registry.capabilities()})
    assert not (ws / "metadata/lab_passport.json").exists()


def test_passport_only_restricts_existing_policy(lab, config, registry):
    ws, values = lab
    save_passport(ws, values, {c.name for c in registry.capabilities()})
    policy = PolicyEngine(config, workspace=ws)
    visit = registry.capability("browser.visit")
    assert policy.check(visit, {"url": "http://lab.local/"}).allowed
    assert not policy.check(visit, {"url": "http://other.local/"}).allowed
    assert not policy.url_allowed("http://other.local/redirect")
    assert not policy.check(registry.capability("browser.navigate"), {"url": "http://lab.local/"}).allowed
    config.policy.network.authorized_targets = []
    assert not PolicyEngine(config, workspace=ws).check(visit, {"url": "http://lab.local/"}).allowed


def test_changed_source_fails_closed_but_local_hashing_remains_available(lab, config, registry):
    ws, values = lab
    save_passport(ws, values, {c.name for c in registry.capabilities()})
    (ws / values["source"]).write_text("changed", encoding="utf-8")
    assert passport_summary(ws)["valid"] is False
    policy = PolicyEngine(config, workspace=ws)
    assert not policy.check(registry.capability("browser.visit"), {"url": "http://lab.local/"}).allowed
    assert policy.check(registry.capability("core.hash_inputs"), {}).allowed


def test_registry_checks_scope_before_plugin_action(lab, config):
    class Probe(BaseIntegration):
        name = "probe"
        CAPABILITIES = (Capability("probe.visit", "probe", "Test network operation",
                                   (Param("url", "url"),), network=True),)
        called = False

        def visit(self, parameters, context):
            self.called = True
            return IntegrationResult(True)

    ws, values = lab
    adapter = Probe()
    registry = IntegrationRegistry()
    registry.register(adapter)
    save_passport(ws, {**values, "actions": ["probe.visit"]}, {"probe.visit"})
    context = ExecutionContext(ws, "test", config=config)
    with pytest.raises(CapabilityBlocked, match="outside"):
        registry.execute("probe.visit", {"url": "http://other.local"}, context)
    assert not adapter.called
    with pytest.raises(CapabilityBlocked, match="explicit target"):
        registry.execute("probe.visit", {}, context)
    assert registry.execute("probe.visit", {"url": "http://lab.local"}, context).verified


def test_missing_passport_preserves_existing_policy_and_cli_can_create(lab, config, capsys):
    ws, values = lab
    assert PolicyEngine(config, workspace=ws).host_allowed("other.local")
    args = ["lab-passport", str(ws), "--create"]
    for field in ("name", "purpose", "owner", "source", "excerpt"):
        args.extend(["--" + field, values[field]])
    args.extend(["--target", "lab.local", "--action", "browser.visit"])
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main(["lab-passport", str(ws)]) == 0
    assert json.loads(capsys.readouterr().out)["source"] == "input/authorization.txt"
