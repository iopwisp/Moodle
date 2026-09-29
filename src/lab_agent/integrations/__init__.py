"""Pluggable integrations for application-specific lab automation.

Each integration publishes named capabilities. The workflow runner executes
capabilities through the registry instead of containing application-specific
conditionals.
"""

from .base import Capability, ExecutionContext, IntegrationResult
from .registry import build_registry

__all__ = ["Capability", "ExecutionContext", "IntegrationResult", "build_registry"]
