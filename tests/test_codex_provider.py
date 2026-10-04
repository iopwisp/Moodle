from __future__ import annotations

import itertools
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from lab_agent.llm import CodexProvider, ProviderError, make_provider

SCHEMA = {"type": "object", "additionalProperties": False, "required": ["steps"],
          "properties": {"steps": {"type": "array", "items": {"type": "string"}}}}


class FakeCodex:
    """Imitates `codex exec`: reads the prompt from stdin and writes the final message to the -o file."""

    def __init__(self, answer: str | None = '{"steps": ["hash", "ingest"]}', returncode: int = 0, stderr: str = "") -> None:
        self.answer, self.returncode, self.stderr = answer, returncode, stderr
        self.calls: list[dict[str, Any]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        options = dict(itertools.pairwise(command))
        self.calls.append({"command": command, "prompt": kwargs["input"].decode("utf-8"),
                           "schema": json.loads(Path(options["--output-schema"]).read_text(encoding="utf-8"))})
        if self.answer is not None:
            Path(options["-o"]).write_text(self.answer, encoding="utf-8")
        return subprocess.CompletedProcess(command, self.returncode, b"", self.stderr.encode())


@pytest.fixture
def codex_exe(tmp_path: Path) -> str:
    exe = tmp_path / "codex.exe"
    exe.write_bytes(b"MZ")
    return str(exe)


def test_codex_answer_is_schema_checked_json(codex_exe: str, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeCodex()
    monkeypatch.setattr(subprocess, "run", fake)
    provider = CodexProvider("", executable=codex_exe)
    assert provider.complete_json("You plan labs.", "Assignment text", SCHEMA, name="plan") == {"steps": ["hash", "ingest"]}
    command = fake.calls[0]["command"]
    assert command[:2] == [codex_exe, "exec"] and command[-1] == "-"
    assert command[command.index("--sandbox") + 1] == "read-only" and "--ephemeral" in command and "-m" not in command
    assert fake.calls[0]["schema"] == SCHEMA
    assert "You plan labs." in fake.calls[0]["prompt"] and "Assignment text" in fake.calls[0]["prompt"]


def test_model_is_passed_when_configured(codex_exe: str, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeCodex()
    monkeypatch.setattr(subprocess, "run", fake)
    CodexProvider("gpt-6-mini", executable=codex_exe).complete_json("s", "u", SCHEMA)
    command = fake.calls[0]["command"]
    assert command[command.index("-m") + 1] == "gpt-6-mini"


def test_wrong_shape_is_rejected(codex_exe: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", FakeCodex('{"steps": "not a list"}'))
    with pytest.raises(ProviderError, match="expected array"):
        CodexProvider("", executable=codex_exe).complete_json("s", "u", SCHEMA)


def test_failures_are_retried_then_reported(codex_exe: str, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeCodex(answer=None, returncode=1, stderr="stream error: usage limit reached")
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(ProviderError, match="usage limit"):
        CodexProvider("", executable=codex_exe, retries=1).complete_json("s", "u", SCHEMA)
    assert len(fake.calls) == 2


def test_not_signed_in_stops_immediately(codex_exe: str, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeCodex(answer=None, returncode=1, stderr="Error: Not logged in. Run codex login")
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(ProviderError, match="codex login"):
        CodexProvider("", executable=codex_exe, retries=3).complete_json("s", "u", SCHEMA)
    assert len(fake.calls) == 1


def test_provider_is_selectable_by_name(codex_exe: str, monkeypatch: pytest.MonkeyPatch, config) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("LAB_AGENT_CODEX_PATH", codex_exe)
    provider = make_provider("codex", config=config)
    assert isinstance(provider, CodexProvider) and provider.executable == codex_exe and provider.timeout >= 300


def test_missing_codex_is_a_provider_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LAB_AGENT_CODEX_PATH", str(tmp_path / "absent.exe"))
    with pytest.raises(ProviderError, match="Codex CLI was not found"):
        CodexProvider("")


@pytest.mark.skipif(os.environ.get("LAB_AGENT_REAL_CODEX") != "1", reason="set LAB_AGENT_REAL_CODEX=1 (uses Codex quota)")
def test_real_codex_answers_with_schema() -> None:
    answer = CodexProvider("").complete_json("Return the steps of a forensic hash check.", "Two short steps.", SCHEMA)
    assert answer["steps"] and all(isinstance(step, str) for step in answer["steps"])
