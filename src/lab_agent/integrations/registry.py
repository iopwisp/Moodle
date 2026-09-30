"""Capability registry with automatic discovery of built-in and external integrations.

Discovery sources (in order):

1. every module in ``lab_agent/integrations/`` that defines
   ``create_adapters(services) -> list[adapter]`` - adding a file there is
   enough to publish new capabilities;
2. Python entry points in the group ``doneasik_lab_agent.integrations`` whose
   object is an adapter factory (returns one adapter or a list);
3. ``*.py`` files in directories listed in ``config.plugins.directories``.

Nothing in the runner, planner, database or reports needs to change when a new
integration is added.
"""

from __future__ import annotations

import importlib
import importlib.util
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

from ..tools.screenshot import take_screenshot
from .base import AppSpec, Capability, ExecutionContext, IntegrationAdapter, IntegrationResult

PLUGIN_GROUP = "doneasik_lab_agent.integrations"

_LEGACY_ALIASES = {
    "hash_inputs": "core.hash_inputs",
    "screenshot": "core.screenshot",
    "manual_review": "core.manual_review",
    "browser": "browser.visit",
    "desktop": "desktop.profile",
    "autopsy_e2e": "autopsy.e2e",
}

_INFRASTRUCTURE = {"base", "registry", "sessions"}


@dataclass
class Services:
    """Shared services handed to adapter factories."""

    screenshot_fn: Callable[..., Any] = take_screenshot
    config: Any = None
    extra: dict[str, Any] = field(default_factory=dict)


class IntegrationRegistry:
    """Resolve capability names to adapters and execute them safely."""

    def __init__(self) -> None:
        self._adapters: dict[str, IntegrationAdapter] = {}
        self._capabilities: dict[str, tuple[IntegrationAdapter, Capability]] = {}
        self.sources: dict[str, str] = {}
        self.load_errors: list[dict[str, str]] = []

    def register(self, adapter: IntegrationAdapter, source: str = "runtime") -> None:
        if not getattr(adapter, "name", ""):
            raise ValueError("Integration adapters must declare a non-empty name")
        if adapter.name in self._adapters:
            raise ValueError(f"Duplicate integration name: {adapter.name}")
        capabilities = adapter.capabilities()
        for capability in capabilities:
            if capability.name in self._capabilities:
                raise ValueError(f"Duplicate capability: {capability.name}")
            if not capability.name.startswith(adapter.name + "."):
                raise ValueError(f"Capability {capability.name} must be namespaced as '{adapter.name}.<action>'")
        self._adapters[adapter.name] = adapter
        for capability in capabilities:
            self._capabilities[capability.name] = (adapter, capability)
        self.sources[adapter.name] = source

    def normalize(self, name: str) -> str:
        name = name.strip()
        return _LEGACY_ALIASES.get(name, name)

    def has(self, name: str) -> bool:
        return self.normalize(name) in self._capabilities

    def capability(self, name: str) -> Capability:
        normalized = self.normalize(name)
        try:
            return self._capabilities[normalized][1]
        except KeyError as exc:
            raise ValueError(f"Unsupported capability: {name}") from exc

    def capabilities(self) -> list[Capability]:
        return [capability for _, capability in self._capabilities.values()]

    def adapters(self) -> list[IntegrationAdapter]:
        return list(self._adapters.values())

    def adapter(self, name: str) -> IntegrationAdapter | None:
        return self._adapters.get(name)

    def adapter_for(self, capability: str) -> IntegrationAdapter:
        normalized = self.normalize(capability)
        try:
            return self._capabilities[normalized][0]
        except KeyError as exc:
            raise ValueError(f"Unsupported capability: {capability}") from exc

    def applications(self) -> list[AppSpec]:
        specs: list[AppSpec] = []
        for adapter in self._adapters.values():
            hook = getattr(adapter, "applications", None)
            if callable(hook):
                specs.extend(hook())
        return specs

    def catalog(self) -> str:
        lines = []
        for adapter in self._adapters.values():
            lines.append(f"[{adapter.name}]")
            lines.extend(c.as_prompt_line() for _, c in self._capabilities.values() if c.tool == adapter.name or
                         c.name.startswith(adapter.name + "."))
        return "\n".join(lines)

    def validate_parameters(self, name: str, parameters: dict[str, Any]) -> list[str]:
        """Return problems with ``parameters`` for capability ``name`` (empty when valid)."""
        capability = self.capability(name)
        declared = {param.name: param for param in capability.params()}
        problems = [f"missing required parameter '{p.name}'" for p in declared.values()
                    if p.required and (parameters.get(p.name) in (None, ""))]
        unknown = sorted(set(parameters) - set(declared))
        if unknown and declared is not None:
            problems.append(f"unknown parameter(s) {unknown}; declared: {sorted(declared) or 'none'}")
        for key, param in declared.items():
            if key in parameters and param.choices and str(parameters[key]) not in param.choices:
                problems.append(f"parameter '{key}' must be one of {list(param.choices)}")
        return problems

    def execute(
        self,
        name: str,
        parameters: dict[str, Any],
        context: ExecutionContext,
    ) -> IntegrationResult:
        normalized = self.normalize(name)
        try:
            adapter, _ = self._capabilities[normalized]
        except KeyError as exc:
            raise ValueError(f"Unsupported capability: {name}") from exc
        return adapter.execute(normalized, parameters, context)

    def shutdown(self) -> None:
        for adapter in self._adapters.values():
            hook = getattr(adapter, "shutdown", None)
            if callable(hook):
                try:
                    hook()
                except Exception:  # noqa: BLE001, S110 - shutdown is best effort
                    pass

    # ------------------------------------------------------------- discovery
    def _add_from_factory(self, factory: Callable[..., Any], services: Services, source: str) -> None:
        try:
            try:
                produced = factory(services)
            except TypeError:
                produced = factory()
            adapters = produced if isinstance(produced, (list, tuple)) else [produced]
            for adapter in adapters:
                self.register(adapter, source)
        except Exception as exc:  # noqa: BLE001 - a broken plugin must not break the agent
            self.load_errors.append({"source": source, "error": f"{type(exc).__name__}: {exc}"})


def _builtin_modules() -> list[str]:
    package = importlib.import_module(__package__ or "lab_agent.integrations")
    names = sorted(info.name for info in pkgutil.iter_modules(package.__path__) if info.name not in _INFRASTRUCTURE)
    # core first so its capabilities head the catalog
    return sorted(names, key=lambda name: (name != "core", name))


def _load_builtin(registry: IntegrationRegistry, services: Services) -> None:
    for module_name in _builtin_modules():
        qualified = f"{__package__}.{module_name}"
        try:
            module = importlib.import_module(qualified)
        except Exception as exc:  # noqa: BLE001
            registry.load_errors.append({"source": qualified, "error": f"{type(exc).__name__}: {exc}"})
            continue
        factory = getattr(module, "create_adapters", None)
        if callable(factory):
            registry._add_from_factory(factory, services, f"builtin:{module_name}")


def _load_external_adapters(registry: IntegrationRegistry, services: Services | None = None) -> None:
    """Load adapters published by optional packages via Python entry points."""
    services = services or Services()
    for entry_point in entry_points().select(group=PLUGIN_GROUP):
        try:
            factory = entry_point.load()
        except Exception as exc:  # noqa: BLE001
            registry.load_errors.append({"source": f"entry_point:{entry_point.name}", "error": str(exc)})
            continue
        registry._add_from_factory(factory, services, f"entry_point:{entry_point.name}")


def _load_directory_plugins(registry: IntegrationRegistry, directories: list[str], services: Services) -> None:
    for directory in directories:
        folder = Path(directory).expanduser()
        if not folder.is_dir():
            registry.load_errors.append({"source": f"directory:{folder}", "error": "not a directory"})
            continue
        for file in sorted(folder.glob("*.py")):
            if file.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(f"lab_agent_plugin_{file.stem}", file)
                if spec is None or spec.loader is None:
                    raise ImportError("cannot load module spec")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            except Exception as exc:  # noqa: BLE001
                registry.load_errors.append({"source": f"file:{file}", "error": f"{type(exc).__name__}: {exc}"})
                continue
            factory = getattr(module, "create_adapters", None)
            if callable(factory):
                registry._add_from_factory(factory, services, f"file:{file.name}")
            else:
                registry.load_errors.append({"source": f"file:{file}", "error": "no create_adapters() function"})


def build_registry(
    screenshot_fn: Callable[..., Any] = take_screenshot,
    config: Any = None,
) -> IntegrationRegistry:
    """Build built-ins and discover third-party integrations."""
    if config is None:
        from ..config import get_config

        config = get_config()
    services = Services(screenshot_fn=screenshot_fn, config=config)
    registry = IntegrationRegistry()
    _load_builtin(registry, services)
    plugins = getattr(config, "plugins", None)
    if plugins is None or plugins.entry_points:
        _load_external_adapters(registry, services)
    if plugins is not None and plugins.directories:
        _load_directory_plugins(registry, list(plugins.directories), services)
    return registry
