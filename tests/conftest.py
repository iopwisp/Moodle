from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fakes import fake_screenshot

from lab_agent.config import AgentConfig, set_config
from lab_agent.integrations.registry import build_registry

EMPTY_ENVIRONMENT = {"os": "test", "applications": {}, "wsl": {"available": False, "tools": {}}}


@pytest.fixture(autouse=True)
def deterministic_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> AgentConfig:
    """Every test runs with defaults: no config.yaml, no AI keys, no profile overrides."""
    for variable in ("OPENAI_API_KEY", "OLLAMA_HOST", "LAB_AGENT_CONFIG", "LAB_AGENT_AUTOPSY_PATH", "LAB_AGENT_BURP_PATH",
                     "LAB_AGENT_PACKET_TRACER_PATH", "LAB_AGENT_WIRESHARK_PATH", "LAB_AGENT_PROFILES_DIR",
                     "LAB_AGENT_AUTHORIZED_TARGETS", "LAB_AGENT_TESTDISK_PATH", "LAB_AGENT_PHOTOREC_PATH"):
        monkeypatch.delenv(variable, raising=False)
    # Applications installed on the developer machine (Autopsy, Burp, ...) must not leak into tests:
    # discovery may only find what a test puts on PATH, in an env var or in its own install root.
    monkeypatch.setattr("lab_agent.environment._roots", list)
    monkeypatch.setattr("lab_agent.environment._registry_entries", list)
    config = AgentConfig()
    config.ai.provider = "deterministic"
    config.workspace_root = str(tmp_path / "workspaces")
    set_config(config)
    yield config
    set_config(None)


@pytest.fixture
def config(deterministic_config: AgentConfig) -> AgentConfig:
    return deterministic_config


@pytest.fixture
def registry(config: AgentConfig):  # type: ignore[no-untyped-def]
    return build_registry(fake_screenshot, config)


@pytest.fixture
def environment() -> dict:
    return {"os": "test", "applications": {}, "wsl": {"available": False, "tools": {}}}
