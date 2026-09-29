"""Small process manager for launching and inspecting desktop applications."""

from __future__ import annotations

import subprocess
from pathlib import Path


def launch_application(executable: str, args: list[str] | None = None, cwd: Path | None = None) -> subprocess.Popen[bytes]:
    """Launch a configured application without shell interpretation."""
    return subprocess.Popen([executable, *(args or [])], cwd=cwd, close_fds=True)


def is_running(process: subprocess.Popen[bytes]) -> bool:
    return process.poll() is None
