"""Generic YAML-driven desktop application adapter."""

from __future__ import annotations

from typing import Any

from ..automation import desktop_operation
from .base import Capability, ExecutionContext, IntegrationResult


class DesktopAdapter:
    name = "desktop"

    def capabilities(self) -> list[Capability]:
        return [
            Capability(
                name="desktop.profile",
                tool="desktop",
                description=(
                    "Run a declared Windows UI Automation operation from an application profile"
                ),
                parameters=("profile", "operation"),
                evidence_types=("screenshot",),
            ),
        ]

    def execute(
        self,
        capability: str,
        parameters: dict[str, Any],
        context: ExecutionContext,
    ) -> IntegrationResult:
        if capability != "desktop.profile":
            raise ValueError(f"Unsupported desktop capability: {capability}")
        profile = str(parameters.get("profile", "")).strip()
        operation = str(parameters.get("operation", "launch")).strip()
        if not profile:
            raise ValueError("desktop.profile requires a profile parameter.")
        result = desktop_operation(context.workspace, profile, operation, context.assignment)
        return IntegrationResult(
            verified=bool(result.get("verified")),
            details=result,
            evidence=[{
                "path": str(result["screenshot"]),
                "description": f"{result['profile']} {result['operation']} desktop evidence",
                "type": "screenshot",
            }],
        )
