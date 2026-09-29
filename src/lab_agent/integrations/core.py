"""Core capabilities that do not belong to a third-party application."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..tools.screenshot import take_screenshot
from ..workspace import calculate_hashes
from .base import Capability, ExecutionContext, IntegrationResult

ScreenshotFn = Callable[..., Path]


class CoreAdapter:
    name = "core"

    def __init__(self, screenshot_fn: ScreenshotFn = take_screenshot) -> None:
        self._screenshot_fn = screenshot_fn

    def capabilities(self) -> list[Capability]:
        return [
            Capability(
                name="core.hash_inputs",
                tool="core",
                description="Calculate MD5, SHA-1, and SHA-256 for supplied input files",
                evidence_types=("hash",),
            ),
            Capability(
                name="core.screenshot",
                tool="core",
                description="Capture the current interactive desktop",
                evidence_types=("screenshot",),
            ),
            Capability(
                name="core.manual_review",
                tool="core",
                description="Pause because a requested operation cannot be safely automated",
            ),
        ]

    def execute(
        self,
        capability: str,
        parameters: dict[str, Any],
        context: ExecutionContext,
    ) -> IntegrationResult:
        if capability == "core.hash_inputs":
            hashes = {
                path.name: calculate_hashes(path)
                for path in (context.workspace / "input").rglob("*")
                if path.is_file()
            }
            output = context.workspace / "results" / "input_hashes.json"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(hashes, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            return IntegrationResult(
                verified=True,
                details={"hashes": hashes, "output": str(output)},
                evidence=[{
                    "path": str(output),
                    "description": "SHA-256 and related hashes for supplied input files",
                    "type": "hash",
                }],
            )

        if capability == "core.screenshot":
            screenshot = self._screenshot_fn(context.workspace, name=parameters.get("name"))
            return IntegrationResult(
                verified=True,
                details={"screenshot": str(screenshot)},
                evidence=[{
                    "path": str(screenshot),
                    "description": parameters.get("description", "Captured desktop evidence"),
                    "type": "screenshot",
                }],
            )

        if capability == "core.manual_review":
            return IntegrationResult(
                verified=False,
                blocked=True,
                details={"reason": parameters.get("reason", "Manual verification required")},
            )

        raise ValueError(f"Unsupported core capability: {capability}")
