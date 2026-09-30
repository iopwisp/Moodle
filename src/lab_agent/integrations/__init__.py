"""Pluggable integrations for application-specific lab automation.

Each integration publishes named capabilities (``<tool>.<action>``). The
workflow runner executes capabilities through the registry instead of
containing application-specific conditionals.  See ``docs/plugin_development.md``.
"""

from .base import (
    AppSpec,
    BaseIntegration,
    Capability,
    CapabilityBlocked,
    ExecutionContext,
    IntegrationAdapter,
    IntegrationResult,
    Param,
)
from .registry import IntegrationRegistry, Services, build_registry

__all__ = [
    "AppSpec", "BaseIntegration", "Capability", "CapabilityBlocked", "ExecutionContext", "IntegrationAdapter",
    "IntegrationRegistry", "IntegrationResult", "Param", "Services", "build_registry",
]
