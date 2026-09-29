"""Autopsy integration.

Application-specific orchestration stays here; the core runner only knows the
capability contract.
"""

from __future__ import annotations

from typing import Any

from ..automation import autopsy_e2e_operation
from .base import Capability, ExecutionContext, IntegrationResult


class AutopsyAdapter:
    name = "autopsy"

    def capabilities(self) -> list[Capability]:
        return [
            Capability(
                name="autopsy.e2e",
                tool="autopsy",
                description=(
                    "Create a forensic case, add a disk image, run ingest, open the "
                    "resulting case in the GUI, and capture verified evidence"
                ),
                parameters=("data_source",),
                evidence_types=("screenshot", "log"),
            ),
        ]

    def execute(
        self,
        capability: str,
        parameters: dict[str, Any],
        context: ExecutionContext,
    ) -> IntegrationResult:
        if capability != "autopsy.e2e":
            raise ValueError(f"Unsupported Autopsy capability: {capability}")
        result = autopsy_e2e_operation(
            context.workspace,
            context.assignment,
            data_source=parameters.get("data_source"),
        )
        return IntegrationResult(
            verified=bool(result.get("verified")),
            details=result,
            evidence=[
                {
                    "path": str(result["screenshot"]),
                    "description": "Verified Autopsy forensic workflow result",
                    "type": "screenshot",
                },
                {
                    "path": str(result["command_log"]),
                    "description": "Autopsy command-line ingest execution log",
                    "type": "log",
                },
            ],
        )
