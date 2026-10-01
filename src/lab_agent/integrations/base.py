"""Plugin SDK: the stable contract between the core agent and every integration.

An integration ("adapter") publishes named :class:`Capability` objects and
executes them, returning an :class:`IntegrationResult`.  The core runner never
contains application-specific logic; everything it needs to know is declared
here:

* ``Capability.parameters`` - typed :class:`Param` specs used for plan
  validation and for the AI capability catalog;
* ``Capability.evidence_types`` - evidence the capability may produce;
* ``Capability.verification`` - human-readable post-condition semantics;
* ``IntegrationResult.checks`` - machine-checkable post-conditions evaluated
  by :mod:`lab_agent.verification` *after* the adapter returns, so an adapter
  cannot mark its own work verified without observable proof.

Optional adapter hooks (all duck-typed, see :class:`BaseIntegration`):

* ``applications()`` - :class:`AppSpec` list for environment discovery;
* ``plan_templates(analysis, registry)`` - deterministic workflow proposals;
* ``match_requirement(text)`` - keyword scoring for the deterministic planner;
* ``recover(capability, parameters, context, failure_kind)`` - recovery action;
* ``reconcile(capability, parameters, context)`` - post-crash result check;
* ``shutdown()`` - release applications/sessions at the end of a run.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

PARAM_TYPES = {"str", "int", "float", "bool", "list", "dict", "path", "url"}


@dataclass(frozen=True)
class Param:
    """Typed capability parameter."""

    name: str
    type: str = "str"
    required: bool = False
    description: str = ""
    default: Any = None
    choices: tuple[str, ...] = ()

    def describe(self) -> str:
        text = f"{self.name}:{self.type}{'' if self.required else '?'}"
        if self.choices:
            text += "{" + "|".join(self.choices) + "}"
        return text + (f" ({self.description})" if self.description else "")


def _as_param(value: str | Param) -> Param:
    if isinstance(value, Param):
        return value
    name = value.rstrip("?")
    return Param(name=name, required=not value.endswith("?"))


@dataclass(frozen=True)
class Capability:
    """A single operation an integration can execute."""

    name: str
    tool: str
    description: str
    parameters: tuple[str | Param, ...] = ()
    evidence_types: tuple[str, ...] = ()
    verification: str = ""
    risk: str = "safe"  # safe | elevated | unsafe
    requires: tuple[str, ...] = ()  # e.g. ("app:autopsy",)
    network: bool = False
    keywords: tuple[str, ...] = ()

    def params(self) -> list[Param]:
        return [_as_param(item) for item in self.parameters]

    def param(self, name: str) -> Param | None:
        return next((item for item in self.params() if item.name == name), None)

    def as_prompt_line(self) -> str:
        params = ", ".join(item.describe() for item in self.params()) or "none"
        evidence = ", ".join(self.evidence_types) if self.evidence_types else "optional"
        line = f"- {self.name}: {self.description}. parameters=[{params}]; evidence={evidence}"
        if self.verification:
            line += f"; verifies: {self.verification}"
        if self.risk != "safe":
            line += f"; risk={self.risk}"
        return line

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "tool": self.tool,
            "description": self.description,
            "parameters": [
                {"name": p.name, "type": p.type, "required": p.required, "description": p.description}
                for p in self.params()
            ],
            "evidence_types": list(self.evidence_types),
            "verification": self.verification,
            "risk": self.risk,
            "requires": list(self.requires),
            "network": self.network,
        }


@dataclass(frozen=True)
class AppSpec:
    """How to discover an application on this computer."""

    name: str
    display_name: str
    env_var: str | None = None
    executables: tuple[str, ...] = ()  # file names searched on PATH / install dirs
    install_globs: tuple[str, ...] = ()  # glob patterns under known roots
    registry_name_re: str | None = None  # Windows uninstall DisplayName regex
    version_args: tuple[str, ...] = ()  # e.g. ("--version",)
    version_re: str = r"(\d+(?:\.\d+){1,3})"
    capabilities: tuple[str, ...] = ()


@dataclass
class ExecutionContext:
    """Runtime context shared by all integrations."""

    workspace: Path
    assignment: str
    allowed_targets: set[str] = field(default_factory=set)
    step_id: int | None = None
    config: Any = None
    environment: dict[str, Any] = field(default_factory=dict)
    screenshot_fn: Callable[..., Path] | None = None
    event_fn: Callable[[str, dict[str, Any]], None] | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)
    attempt: int = 1

    def __post_init__(self) -> None:
        self.workspace = Path(self.workspace)
        self.allowed_targets = {target.casefold() for target in self.allowed_targets}

    # -- paths -----------------------------------------------------------------
    def folder(self, name: str) -> Path:
        path = self.workspace / name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def resolve(self, value: str | Path, *, must_exist: bool = True, base: str | None = None) -> Path:
        """Resolve a workspace-relative path and refuse anything outside the workspace."""
        raw = Path(value)
        root = self.workspace.resolve()
        candidates = [raw] if raw.is_absolute() else [root / raw] + ([root / base / raw] if base else [])
        for candidate in candidates:
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root):
                raise PermissionError(f"Path escapes the assignment workspace: {value}")
            if not must_exist or resolved.exists():
                return resolved
        raise FileNotFoundError(f"Workspace file not found: {value}")

    def save_result(self, filename: str, content: Any) -> Path:
        if Path(filename).name != filename:
            raise ValueError(f"Result file name must not contain directories: {filename}")
        target = self.folder("results") / filename
        if isinstance(content, (dict, list)):
            target.write_text(json.dumps(content, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        elif isinstance(content, (bytes, bytearray)):
            target.write_bytes(bytes(content))
        else:
            target.write_text(str(content), encoding="utf-8")
        return target

    # -- runtime services ------------------------------------------------------
    def log(self, event: str, payload: dict[str, Any] | None = None) -> None:
        if self.event_fn is not None:
            self.event_fn(event, payload or {})

    def screenshot(self, name: str, *, window_title_re: str | None = None) -> Path:
        """Capture a (window-targeted when possible) screenshot; raises when impossible."""
        if self.screenshot_fn is None:
            from ..tools.screenshot import take_screenshot

            return take_screenshot(self.workspace, name=name, window_title_re=window_title_re)
        try:
            return self.screenshot_fn(self.workspace, name=name, window_title_re=window_title_re)
        except TypeError:  # legacy screenshot functions without window support
            return self.screenshot_fn(self.workspace, name=name)

    def app_path(self, name: str) -> str | None:
        """Executable path discovered for an application (config > env > discovery)."""
        if self.config is not None and name in getattr(self.config, "applications", {}):
            return str(self.config.applications[name])
        info = self.environment.get(name) if isinstance(self.environment, dict) else None
        if isinstance(info, dict) and info.get("available"):
            return str(info.get("path"))
        return None

    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def sleep(self, seconds: float) -> None:
        """Interruptible sleep honouring Stop requests."""
        if self.cancel_event.wait(timeout=max(0.0, seconds)):
            raise InterruptedError("Execution stopped by the user.")

    def stamp(self) -> str:
        return time.strftime("%Y%m%d_%H%M%S")


@dataclass
class IntegrationResult:
    """Normalized result returned by every integration capability.

    ``verified`` is the adapter's own claim.  The runner additionally evaluates
    ``checks`` (verification DSL) and validates every evidence file; only when
    all of them pass is a step COMPLETED.
    """

    verified: bool
    details: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    blocked: bool = False
    checks: list[dict[str, Any]] = field(default_factory=list)
    report_sections: list[dict[str, Any]] = field(default_factory=list)

    @property
    def reason(self) -> str:
        return str(self.details.get("reason", ""))

    @classmethod
    def blocked_result(cls, reason: str, **details: Any) -> IntegrationResult:
        return cls(verified=False, blocked=True, details={"reason": reason, **details})

    @classmethod
    def failed(cls, reason: str, **details: Any) -> IntegrationResult:
        return cls(verified=False, details={"reason": reason, **details})


@dataclass
class StepFacts:
    """What actually happened in one plan step, as handed to :meth:`BaseIntegration.narrate`."""

    action: str
    title: str
    status: str  # COMPLETED | FAILED | BLOCKED | SKIPPED | PENDING
    parameters: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    requirement_refs: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)  # workspace-relative paths
    sections: list[dict[str, Any]] = field(default_factory=list)  # adapter report_sections
    workspace: Path | None = None

    @property
    def completed(self) -> bool:
        return self.status == "COMPLETED"

    def section_rows(self, index: int = 0) -> list[dict[str, Any]]:
        tables = [s.get("table") or [] for s in self.sections if s.get("table")]
        return list(tables[index]) if index < len(tables) else []


@dataclass
class Narrative:
    """How a step reads in the student report: a heading and plain prose, no tool jargon.

    ``tables`` replaces the adapter's report-section tables (``None`` keeps them, ``[]`` drops them);
    each entry is ``{"caption": str, "rows": list[dict]}``.  ``finding`` is one sentence for the
    conclusion; leave it empty when the step established nothing worth concluding.
    """

    heading: str
    paragraphs: list[str] = field(default_factory=list)
    finding: str = ""
    tables: list[dict[str, Any]] | None = None
    figure_caption: str = ""
    show_code: bool = True
    show_figures: bool = True
    outcome_explained: bool = False  # True: the paragraphs already explain why an unfinished step did not finish
    software: list[tuple[str, str]] = field(default_factory=list)  # (program, version) actually used by the step


class CapabilityBlocked(RuntimeError):
    """Raised when a capability cannot run here (missing app, credential, login...)."""


@runtime_checkable
class IntegrationAdapter(Protocol):
    """Protocol implemented by built-in and third-party integrations."""

    name: str

    def capabilities(self) -> list[Capability]: ...

    def execute(
        self,
        capability: str,
        parameters: dict[str, Any],
        context: ExecutionContext,
    ) -> IntegrationResult: ...


_METHOD_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


class BaseIntegration:
    """Convenience base class: ``<tool>.<action>`` dispatches to ``self.<action>()``.

    Subclasses declare ``name`` and ``CAPABILITIES`` (or override
    :meth:`capabilities`) and implement one method per action with the
    signature ``(self, parameters, context) -> IntegrationResult``.
    """

    name: str = ""
    CAPABILITIES: tuple[Capability, ...] = ()
    APPLICATIONS: tuple[AppSpec, ...] = ()

    def capabilities(self) -> list[Capability]:
        return list(self.CAPABILITIES)

    def applications(self) -> list[AppSpec]:
        return list(self.APPLICATIONS)

    def execute(
        self,
        capability: str,
        parameters: dict[str, Any],
        context: ExecutionContext,
    ) -> IntegrationResult:
        declared = {item.name for item in self.capabilities()}
        if capability not in declared:
            raise ValueError(f"Unsupported {self.name} capability: {capability}")
        action = capability.split(".", 1)[1]
        if not _METHOD_RE.fullmatch(action) or not callable(getattr(self, action, None)):
            raise NotImplementedError(f"{self.name} declares {capability} but does not implement it")
        result: IntegrationResult = getattr(self, action)(parameters, context)
        return result

    def shutdown(self) -> None:
        """Release resources opened during a run."""

    def narrate(self, facts: StepFacts, language: str) -> Narrative | None:
        """Describe a finished step for the student report (``language`` is ``"ru"`` or ``"en"``).

        Dispatches to ``narrate_<action>(facts, language)`` when the integration defines it; ``None``
        lets the report fall back to a generic description built from the step's facts.
        """
        method = getattr(self, "narrate_" + facts.action.split(".", 1)[-1], None)
        result: Narrative | None = method(facts, language) if callable(method) else None
        return result


def param_str(parameters: dict[str, Any], name: str, default: str = "") -> str:
    value = parameters.get(name, default)
    return default if value is None else str(value).strip()


def param_int(parameters: dict[str, Any], name: str, default: int) -> int:
    value = parameters.get(name, default)
    try:
        return int(str(value).strip(), 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Parameter {name!r} must be an integer, got {value!r}") from exc


def param_float(parameters: dict[str, Any], name: str, default: float) -> float:
    value = parameters.get(name, default)
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Parameter {name!r} must be a number, got {value!r}") from exc


def param_bool(parameters: dict[str, Any], name: str, default: bool = False) -> bool:
    value = parameters.get(name, default)
    if isinstance(value, str):
        return value.strip().casefold() in {"1", "true", "yes", "on"}
    return bool(value)


def param_list(parameters: dict[str, Any], name: str) -> list[Any]:
    value = parameters.get(name)
    if value is None or value == "":
        return []
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("["):
            loaded = json.loads(stripped)
            return list(loaded) if isinstance(loaded, list) else [loaded]
        return [item.strip() for item in re.split(r"[,\n;]", stripped) if item.strip()]
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def param_dict(parameters: dict[str, Any], name: str) -> dict[str, Any]:
    value = parameters.get(name)
    if value is None or value == "":
        return {}
    if isinstance(value, str):
        loaded = json.loads(value)
        if not isinstance(loaded, dict):
            raise TypeError(f"Parameter {name!r} must be a JSON object")
        return loaded
    if isinstance(value, dict):
        return value
    raise ValueError(f"Parameter {name!r} must be an object")


def evidence(path: Path | str, description: str, kind: str = "file") -> dict[str, str]:
    return {"path": str(path), "description": description, "type": kind}
