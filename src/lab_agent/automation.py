"""Backward-compatible helpers kept for scripts written against lab-agent 0.2.

New code should call capabilities through the integration registry.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .integrations.base import ExecutionContext


def urls_from_text(text: str) -> list[str]:
    return [url.rstrip(".,;") for url in re.findall(r"https?://[^\s<>()\[\]{}\"']+", text)]


def _context(workspace: Path, assignment: str, allowed_targets: set[str] | None = None) -> ExecutionContext:
    return ExecutionContext(workspace, assignment, set(allowed_targets or set()))


def desktop_operation(workspace: Path, profile_name: str, operation: str, assignment: str) -> dict[str, Any]:
    """Run a profile operation through the generic desktop integration."""
    from .integrations.desktop import DesktopAdapter

    result = DesktopAdapter().profile({"profile": profile_name, "operation": operation}, _context(workspace, assignment))
    return {**result.details, "screenshot": result.evidence[0]["path"] if result.evidence else None, "verified": result.verified}


def browser_operation(workspace: Path, url: str, allowed_targets: set[str]) -> dict[str, Any]:
    from .integrations.browser import BrowserAdapter

    adapter = BrowserAdapter()
    try:
        result = adapter.visit({"url": url}, _context(workspace, workspace.name, allowed_targets))
    finally:
        adapter.shutdown()
    return {**result.details, "screenshot": result.evidence[0]["path"], "verified": result.verified}


def autopsy_e2e_operation(workspace: Path, assignment: str, data_source: str | None = None) -> dict[str, Any]:
    from .integrations.autopsy import AutopsyAdapter

    result = AutopsyAdapter().e2e({"data_source": data_source} if data_source else {}, _context(workspace, assignment))
    return {**result.details, "verified": result.verified, "evidence": result.evidence}
