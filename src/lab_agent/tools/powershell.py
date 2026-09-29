"""Logged PowerShell execution, explicitly gated because PowerShell is unrestricted."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from ..models import ExecutionRecord


def run_powershell(workspace: Path, command: str, *, allow_unsafe: bool = False, timeout: int = 120) -> ExecutionRecord:
    if not allow_unsafe:
        raise PermissionError("Arbitrary PowerShell is disabled. Re-run with --allow-unsafe after reviewing the command.")
    if timeout < 1 or timeout > 3600:
        raise ValueError("Timeout must be between 1 and 3600 seconds.")
    executable = "powershell.exe" if __import__("os").name == "nt" else "pwsh"
    started = time.monotonic()
    try:
        result = subprocess.run([executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                                cwd=workspace, capture_output=True, text=True, timeout=timeout, check=False)
        record = ExecutionRecord(command=command, working_directory=str(workspace.resolve()), stdout=result.stdout,
                                 stderr=result.stderr, exit_code=result.returncode, duration_seconds=time.monotonic() - started)
    except subprocess.TimeoutExpired as exc:
        record = ExecutionRecord(command=command, working_directory=str(workspace.resolve()),
                                 stdout=_decode(exc.stdout), stderr=_decode(exc.stderr) + "\nTimed out",
                                 exit_code=None, duration_seconds=time.monotonic() - started)
    logs = workspace / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    with (logs / "commands.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(record.model_dump_json() + "\n")
    return record


def _decode(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value
