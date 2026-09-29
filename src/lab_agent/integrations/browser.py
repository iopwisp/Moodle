"""Browser integration exposed through the same capability registry as desktop tools."""

from __future__ import annotations

from typing import Any

from ..automation import browser_operation
from .base import Capability, ExecutionContext, IntegrationResult


class BrowserAdapter:
    name = "browser"

    def capabilities(self) -> list[Capability]:
        return [
            Capability(
                name="browser.visit",
                tool="browser",
                description="Open an authorized local lab URL with Playwright and capture the page",
                parameters=("url",),
                evidence_types=("screenshot",),
            ),
        ]

    def execute(
        self,
        capability: str,
        parameters: dict[str, Any],
        context: ExecutionContext,
    ) -> IntegrationResult:
        if capability != "browser.visit":
            raise ValueError(f"Unsupported browser capability: {capability}")
        url = str(parameters.get("url", "")).strip()
        if not url:
            raise ValueError("browser.visit requires a non-empty url parameter.")
        result = browser_operation(context.workspace, url, context.allowed_targets)
        return IntegrationResult(
            verified=bool(result.get("verified")),
            details=result,
            evidence=[{
                "path": str(result["screenshot"]),
                "description": f"Browser result: {result['title']}",
                "type": "screenshot",
            }],
        )
