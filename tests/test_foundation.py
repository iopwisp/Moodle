"""Config, policy, verification DSL, evidence validation, plugin SDK, LLM validation and redaction."""

from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from typing import Any

import pytest
from fakes import fake_screenshot

from lab_agent.config import load_config
from lab_agent.credentials import MASK, get_secret, redact
from lab_agent.evidence import list_evidence, register_evidence, validate_evidence
from lab_agent.integrations.base import (
    BaseIntegration,
    Capability,
    ExecutionContext,
    IntegrationResult,
    Param,
)
from lab_agent.integrations.registry import IntegrationRegistry, build_registry
from lab_agent.llm import OllamaProvider, OpenAIProvider, ProviderError, _validate
from lab_agent.policy import PolicyEngine
from lab_agent.verification import CheckContext, check_types, register_check, run_checks


def test_config_file_and_environment_overrides(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("ai: {provider: ollama, model: llama3}\npolicy: {network: {authorized_targets: [lab.local]}}\n"
                    "report: {student_name: Test Student}\n", encoding="utf-8")
    monkeypatch.setenv("LAB_AGENT_MAX_ATTEMPTS", "4")
    monkeypatch.setenv("LAB_AGENT_AUTHORIZED_TARGETS", "dvwa.local")
    config = load_config(path)
    assert config.ai.provider == "ollama" and config.ai.model == "llama3"
    assert config.execution.max_attempts == 4
    assert config.authorized_targets() == {"lab.local", "dvwa.local"}
    assert config.report.student_name == "Test Student"
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "missing.yaml")


def test_policy_engine(config) -> None:
    config.policy.network.authorized_targets = ["*.lab.local", "dvwa.test"]
    policy = PolicyEngine(config)
    browse = Capability("browser.visit", "browser", "", (Param("url", "url", True),), network=True)
    assert policy.check(browse, {"url": "http://127.0.0.1:8080"}).allowed
    assert policy.check(browse, {"url": "http://a.lab.local/"}).allowed
    assert policy.check(browse, {"url": "http://dvwa.test/"}).allowed
    assert not policy.check(browse, {"url": "https://google.com"}).allowed
    assert not policy.check(browse, {"url": "http://lab.local.evil.com/"}).allowed
    unsafe_ps = Capability("powershell.run_script", "powershell", "", risk="unsafe")
    assert not policy.check(unsafe_ps, {"command": "Remove-Item C:\\ -Recurse"}).allowed
    config.policy.powershell.arbitrary = True
    decision = policy.check(unsafe_ps, {"command": "Get-Date"})
    assert decision.allowed and decision.confirmation_required


def test_verification_dsl(tmp_path: Path) -> None:
    (tmp_path / "results").mkdir()
    (tmp_path / "results" / "out.txt").write_text("Received = 4\n", encoding="utf-8")
    (tmp_path / "results" / "rows.csv").write_text("a,sha256\n1,x\n2,y\n", encoding="utf-8")
    (tmp_path / "results" / "data.json").write_text(json.dumps({"stats": {"received": 4}}), encoding="utf-8")
    with zipfile.ZipFile(tmp_path / "results" / "ok.zip", "w") as archive:
        archive.writestr("document.txt", "x")
    with sqlite3.connect(tmp_path / "results" / "case.db") as db:
        db.execute("CREATE TABLE t (x)")
        db.execute("INSERT INTO t VALUES (1)")
    fake_screenshot(tmp_path, name="s.png")
    from lab_agent.workspace import sha256_file

    digest = sha256_file(tmp_path / "results" / "out.txt")
    (tmp_path / "results" / "out.sha256").write_text(f"{digest}  out.txt\n", encoding="utf-8")
    ctx = CheckContext(tmp_path, details={"status": 200, "nested": {"n": 3}, "exit_code": 0})
    good = [
        {"type": "file_exists", "path": "results/out.txt"}, {"type": "text_contains", "path": "results/out.txt", "value": "Received = 4"},
        {"type": "text_contains", "path": "results/out.txt", "regex": r"Received = [1-4]"},
        {"type": "csv_rows", "path": "results/rows.csv", "min": 2, "columns": ["sha256"]},
        {"type": "json_value", "path": "results/data.json", "key": "stats.received", "equals": 4},
        {"type": "hash_match", "path": "results/out.txt", "sha256_file": "results/out.sha256"},
        {"type": "zip_valid", "path": "results/ok.zip", "contains": "document.txt"},
        {"type": "sqlite_query", "path": "results/case.db", "query": "SELECT count(*) FROM t", "min": 1},
        {"type": "image_valid", "path": "screenshots/s.png"}, {"type": "details_value", "key": "nested.n", "min": 3},
        {"type": "command_exit_code", "equals": 0}, {"type": "dir_not_empty", "path": "results", "min": 3},
    ]
    report = run_checks(good, ctx)
    assert report.passed, report.summary()
    bad = run_checks([{"type": "file_exists", "path": "results/none.txt"}, {"type": "text_not_contains", "path": "results/out.txt",
                                                                              "value": "Received"},
                      {"type": "sqlite_query", "path": "results/case.db", "query": "DELETE FROM t"},
                      {"type": "file_exists", "path": "../outside.txt"}, {"type": "nonsense"},
                      {"type": "http_status", "url": "https://example.com"}], ctx)
    assert len(bad.failures) == 6
    assert {"http_status", "window_exists", "port_open", "pdf_valid"} <= set(check_types())


def test_custom_check_registration(tmp_path: Path) -> None:
    @register_check("always_even")
    def _even(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
        return spec["n"] % 2 == 0, "even"

    assert run_checks([{"type": "always_even", "n": 2}], CheckContext(tmp_path)).passed


def test_evidence_rejects_fake_files(tmp_path: Path) -> None:
    (tmp_path / "screenshots").mkdir()
    fake = tmp_path / "screenshots" / "fake.png"
    fake.write_bytes(b"not really a png")
    with pytest.raises(ValueError, match="Refusing"):
        register_evidence(tmp_path, fake, "fake", "screenshot")
    empty = tmp_path / "empty.txt"
    empty.write_text("")
    with pytest.raises(ValueError, match="empty"):
        register_evidence(tmp_path, empty, "empty")
    real = fake_screenshot(tmp_path, name="real.png")
    item = register_evidence(tmp_path, real, "real", "screenshot", 1)
    again = register_evidence(tmp_path, real, "real again", "screenshot", 1)
    assert item.id == again.id and len(list_evidence(tmp_path)) == 1
    manifest = json.loads((tmp_path / "metadata" / "evidence_manifest.json").read_text())
    assert manifest["items"][0]["sha256"] == item.sha256
    assert validate_evidence(tmp_path)[0]["verified"]


class Thermometer(BaseIntegration):
    name = "iot"
    CAPABILITIES = (Capability("iot.read", "iot", "read", (Param("unit", "str", True, choices=("C", "F")),), ("json",)),)

    def read(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        path = context.save_result("t.json", {"t": 21.5, "unit": parameters["unit"]})
        return IntegrationResult(True, {"t": 21.5}, [{"path": str(path), "type": "json", "description": "t"}])


def create_adapters(services: Any) -> list[Thermometer]:
    return [Thermometer()]


def test_plugin_sdk_registration_and_validation(tmp_path: Path) -> None:
    registry = IntegrationRegistry()
    registry.register(Thermometer())
    assert registry.validate_parameters("iot.read", {"unit": "C"}) == []
    problems = registry.validate_parameters("iot.read", {"unit": "K", "extra": 1})
    assert any("unknown parameter" in p for p in problems) and any("must be one of" in p for p in problems)
    assert registry.execute("iot.read", {"unit": "C"}, ExecutionContext(tmp_path, "a")).verified

    class BadName(Thermometer):
        name = "other"

    with pytest.raises(ValueError, match="namespaced"):
        IntegrationRegistry().register(BadName())


def test_entry_point_and_directory_plugins(tmp_path: Path, config, monkeypatch) -> None:
    class EntryPoint:
        name = "thermo"

        def load(self) -> Any:
            return lambda services: [Thermometer()]

    class Broken:
        name = "broken"

        def load(self) -> Any:
            raise ImportError("missing dependency")

    class EntryPoints:
        def select(self, group: str) -> list[Any]:
            assert group == "doneasik_lab_agent.integrations"
            return [EntryPoint(), Broken()]

    monkeypatch.setattr("lab_agent.integrations.registry.entry_points", lambda: EntryPoints())
    registry = build_registry(fake_screenshot, config)
    assert registry.has("iot.read") and registry.sources["iot"] == "entry_point:thermo"
    assert any(error["source"] == "entry_point:broken" for error in registry.load_errors)

    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "hello.py").write_text(
        "from lab_agent.integrations import BaseIntegration, Capability, IntegrationResult\n"
        "class Hello(BaseIntegration):\n    name='hello'\n    CAPABILITIES=(Capability('hello.say','hello','say'),)\n"
        "    def say(self, parameters, context):\n        return IntegrationResult(True, {'said': 'hi'})\n"
        "def create_adapters(services):\n    return [Hello()]\n", encoding="utf-8")
    (plugin_dir / "broken.py").write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    monkeypatch.setattr("lab_agent.integrations.registry.entry_points", lambda: type("E", (), {"select": lambda self, group: []})())
    config.plugins.directories = [str(plugin_dir)]
    registry = build_registry(fake_screenshot, config)
    assert registry.has("hello.say") and any("broken.py" in e["source"] for e in registry.load_errors)


def test_builtin_discovery_needs_no_core_edits(registry) -> None:
    tools = {c.tool for c in registry.capabilities()}
    assert {"core", "forensics", "autopsy", "browser", "burp", "packet_tracer", "wireshark", "overleaf", "powershell",
            "desktop", "ftk", "latex"} <= tools
    assert not registry.load_errors
    assert registry.normalize("hash_inputs") == "core.hash_inputs" and registry.has("desktop")


def test_llm_output_validation_and_retries(monkeypatch) -> None:
    schema = {"type": "object", "additionalProperties": False, "properties": {"a": {"type": "integer"}}, "required": ["a"]}
    _validate({"a": 1}, schema)
    for bad in ({}, {"a": "1"}, {"a": 1, "b": 2}, {"a": True}):
        with pytest.raises(ProviderError):
            _validate(bad, schema)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-1234567890abcdef")
    calls = []

    def fake_post(url: str, body: dict, headers: dict, timeout: float) -> dict:
        calls.append(url)
        if len(calls) == 1:
            import urllib.error

            raise urllib.error.HTTPError(url, 503, "busy", {}, None)  # type: ignore[arg-type]
        return {"output": [{"content": [{"type": "output_text", "text": json.dumps({"a": 3})}]}]}

    monkeypatch.setattr("lab_agent.llm._post", fake_post)
    monkeypatch.setattr("lab_agent.llm.time.sleep", lambda s: None)
    assert OpenAIProvider("m", retries=1).complete_json("s", "u", schema) == {"a": 3}
    monkeypatch.setattr("lab_agent.llm._post", lambda *a: {"message": {"content": "{\"a\": \"x\"}"}})
    with pytest.raises(ProviderError):
        OllamaProvider("m").complete_json("s", "u", schema)


def test_secrets_are_redacted(monkeypatch) -> None:
    monkeypatch.setenv("LAB_AGENT_OVERLEAF_PASSWORD", "hunter2-very-secret")
    secret = get_secret("LAB_AGENT_OVERLEAF_PASSWORD")
    text = redact({"note": f"password={secret} and sk-abcdefghijklmnopqrstu", "token": "abc", "nested": [f"x {secret}"]})
    assert secret not in json.dumps(text) and text["token"] == MASK and "sk-abc" not in text["note"]


def test_example_config_is_valid() -> None:
    config = load_config(Path(__file__).parents[1] / "config.example.yaml")
    assert config.policy.powershell.arbitrary is False and config.screenshots.mode == "evidence"
