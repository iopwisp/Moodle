"""Unified configuration: ``config.yaml`` plus ``LAB_AGENT_*`` environment overrides.

Resolution order (later wins):

1. built-in defaults;
2. the YAML file named by ``--config``, ``LAB_AGENT_CONFIG`` or ``./config.yaml``;
3. individual environment variables such as ``LAB_AGENT_AI_PROVIDER``.

Secrets are never stored here; see :mod:`lab_agent.secrets`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AIConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = "auto"
    model: str | None = None
    base_url: str | None = None
    timeout_seconds: float = 90.0
    max_retries: int = 2
    fallback: Literal["deterministic", "none"] = "deterministic"
    recovery_advice: bool = True


class ToolPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool = True
    require_confirmation: bool = False


class PowerShellPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    arbitrary: bool = False


class NetworkPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    localhost: bool = True
    authorized_targets_only: bool = True
    authorized_targets: list[str] = Field(default_factory=list)


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tools: dict[str, ToolPolicy] = Field(default_factory=dict)
    powershell: PowerShellPolicy = Field(default_factory=PowerShellPolicy)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    require_confirmation_for_risk: list[str] = Field(default_factory=lambda: ["unsafe"])


class ExecutionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_attempts: int = 2
    step_timeout_seconds: float = 3600.0
    stop_on_failure: bool = False


class ScreenshotConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["evidence", "all", "none"] = "evidence"
    target: Literal["window", "desktop"] = "window"


class BrowserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    headless: bool = False
    timeout_seconds: float = 45.0
    viewport_width: int = 1440
    viewport_height: int = 1000
    allow_external_subresources: bool = True


class ReportConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    student_name: str = ""
    group: str = ""
    student_id: str = ""
    case_id: str = ""
    course: str = ""
    instructor: str = ""
    university: str = ""
    department: str = ""
    city: str = ""
    language: Literal["auto", "en", "ru"] = "auto"  # auto: the language of the assignment text


class PluginConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry_points: bool = True
    directories: list[str] = Field(default_factory=list)


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: str = "INFO"
    json_logs: bool = False


class AgentConfig(BaseModel):
    """Every tunable setting of the agent in one validated object."""

    model_config = ConfigDict(extra="forbid")

    workspace_root: str = "workspace"
    ai: AIConfig = Field(default_factory=AIConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    screenshots: ScreenshotConfig = Field(default_factory=ScreenshotConfig)
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    plugins: PluginConfig = Field(default_factory=PluginConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    applications: dict[str, str] = Field(
        default_factory=dict,
        description="Explicit executable paths keyed by application name, e.g. autopsy.",
    )

    def authorized_targets(self, extra: set[str] | None = None) -> set[str]:
        hosts = {host.casefold() for host in self.policy.network.authorized_targets}
        return hosts | {host.casefold() for host in (extra or set())}


_ENV_OVERRIDES: dict[str, tuple[str, ...]] = {
    "LAB_AGENT_WORKSPACE_ROOT": ("workspace_root",),
    "LAB_AGENT_AI_PROVIDER": ("ai", "provider"),
    "LAB_AGENT_AI_MODEL": ("ai", "model"),
    "LAB_AGENT_AI_TIMEOUT": ("ai", "timeout_seconds"),
    "LAB_AGENT_MAX_ATTEMPTS": ("execution", "max_attempts"),
    "LAB_AGENT_SCREENSHOT_MODE": ("screenshots", "mode"),
    "LAB_AGENT_BROWSER_HEADLESS": ("browser", "headless"),
    "LAB_AGENT_LOG_LEVEL": ("logging", "level"),
    "LAB_AGENT_JSON_LOGS": ("logging", "json_logs"),
    "LAB_AGENT_STUDENT_NAME": ("report", "student_name"),
    "LAB_AGENT_STUDENT_GROUP": ("report", "group"),
    "LAB_AGENT_STUDENT_ID": ("report", "student_id"),
    "LAB_AGENT_CASE_ID": ("report", "case_id"),
}


def _set_path(data: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    cursor = data
    for key in path[:-1]:
        cursor = cursor.setdefault(key, {})
    cursor[path[-1]] = value


def _coerce(value: str) -> Any:
    lowered = value.strip().casefold()
    if lowered in {"true", "yes", "1", "on"}:
        return True
    if lowered in {"false", "no", "0", "off"}:
        return False
    return value


def config_file_candidates(explicit: Path | None = None) -> list[Path]:
    candidates: list[Path] = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("LAB_AGENT_CONFIG"):
        candidates.append(Path(os.environ["LAB_AGENT_CONFIG"]))
    candidates.append(Path.cwd() / "config.yaml")
    return candidates


def load_config(path: Path | None = None, *, use_env: bool = True) -> AgentConfig:
    """Load configuration; an explicitly named file must exist."""
    data: dict[str, Any] = {}
    if path is not None and not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    for candidate in config_file_candidates(path):
        if candidate.is_file():
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover - PyYAML ships with the gui extra
                raise RuntimeError("config.yaml requires PyYAML: pip install PyYAML") from exc
            loaded = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            if not isinstance(loaded, dict):
                raise ValueError(f"Configuration must be a YAML mapping: {candidate}")
            data = loaded
            break
    if use_env:
        for variable, target in _ENV_OVERRIDES.items():
            if variable in os.environ:
                _set_path(data, target, _coerce(os.environ[variable]))
        extra_targets = os.environ.get("LAB_AGENT_AUTHORIZED_TARGETS", "")
        if extra_targets:
            network = data.setdefault("policy", {}).setdefault("network", {})
            existing = list(network.get("authorized_targets", []))
            network["authorized_targets"] = existing + [
                host.strip() for host in extra_targets.split(",") if host.strip()
            ]
    return AgentConfig.model_validate(data)


_ACTIVE: AgentConfig | None = None


def get_config() -> AgentConfig:
    """Process-wide configuration, loaded lazily."""
    global _ACTIVE
    if _ACTIVE is None:
        _ACTIVE = load_config()
    return _ACTIVE


def set_config(config: AgentConfig | None) -> None:
    """Install (or with ``None`` reset) the process-wide configuration."""
    global _ACTIVE
    _ACTIVE = config
