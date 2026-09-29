"""Capability registry and optional third-party plugin discovery."""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

from .autopsy import AutopsyAdapter
from .base import Capability, ExecutionContext, IntegrationAdapter, IntegrationResult
from .browser import BrowserAdapter
from .core import CoreAdapter
from .desktop import DesktopAdapter

PLUGIN_GROUP = "doneasik_lab_agent.integrations"

_LEGACY_ALIASES = {
    "hash_inputs": "core.hash_inputs",
    "screenshot": "core.screenshot",
    "manual_review": "core.manual_review",
    "browser": "browser.visit",
    "desktop": "desktop.profile",
    "autopsy_e2e": "autopsy.e2e",
}


class IntegrationRegistry:
    """Resolve capability names to adapters and execute them safely."""

    def __init__(self) -> None:
        self._adapters: dict[str, IntegrationAdapter] = {}
        self._capabilities: dict[str, tuple[IntegrationAdapter, Capability]] = {}

    def register(self, adapter: IntegrationAdapter) -> None:
        if adapter.name in self._adapters:
            raise ValueError(f"Duplicate integration name: {adapter.name}")
        self._adapters[adapter.name] = adapter
        for capability in adapter.capabilities():
            if capability.name in self._capabilities:
                raise ValueError(f"Duplicate capability: {capability.name}")
            self._capabilities[capability.name] = (adapter, capability)

    def normalize(self, name: str) -> str:
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
        return list(self._capabilities.values()) and [
            capability for _, capability in self._capabilities.values()
        ]

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


def _load_external_adapters(registry: IntegrationRegistry) -> None:
    """Load adapters published by optional packages via Python entry points."""
    try:
        discovered = entry_points(group=PLUGIN_GROUP)
    except TypeError:
        discovered = entry_points().select(group=PLUGIN_GROUP)
    for entry_point in discovered:
        adapter_factory = entry_point.load()
        adapter = adapter_factory() if isinstance(adapter_factory, type) else adapter_factory()
        registry.register(adapter)


def build_registry(screenshot_fn: Any = None) -> IntegrationRegistry:
    """Build the default registry and discover third-party adapters."""
    registry = IntegrationRegistry()
    registry.register(CoreAdapter(screenshot_fn=screenshot_fn or __import__(
        "lab_agent.tools.screenshot", fromlist=["take_screenshot"]
    ).take_screenshot))
    registry.register(BrowserAdapter())
    registry.register(DesktopAdapter())
    registry.register(AutopsyAdapter())
    _load_external_adapters(registry)
    return registry
