"""Process management for launching and inspecting desktop applications."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..credentials import redact


def launch_application(executable: str, args: list[str] | None = None, cwd: Path | None = None) -> subprocess.Popen[bytes]:
    """Launch a configured application without shell interpretation."""
    return subprocess.Popen([executable, *(args or [])], cwd=cwd, close_fds=True)


def is_running(process: subprocess.Popen[bytes]) -> bool:
    return process.poll() is None


def process_running(image_name: str) -> bool:
    """True when a process with this executable name is running."""
    target = image_name.casefold()
    if not target.endswith(".exe") and os.name == "nt":
        target += ".exe"
    try:
        if os.name == "nt":
            output = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=20, check=False
            ).stdout
            return any(line.split(",")[0].strip('"').casefold() == target for line in output.splitlines() if line)
        output = subprocess.run(["ps", "-A", "-o", "comm="], capture_output=True, text=True, timeout=20, check=False).stdout
        return any(Path(line.strip()).name.casefold() == target for line in output.splitlines())
    except (OSError, subprocess.SubprocessError):
        return False


@dataclass
class CommandResult:
    command: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    extra: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "command": redact(self.command),
            "exit_code": self.exit_code,
            "stdout": redact(self.stdout[-20000:]),
            "stderr": redact(self.stderr[-20000:]),
            "duration_seconds": round(self.duration_seconds, 3),
            "timed_out": self.timed_out,
            **self.extra,
        }


def run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 600,
    log_file: Path | None = None,
    input_text: str | None = None,
) -> CommandResult:
    """Run an argument vector (never through a shell), capture output and log it."""
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command, cwd=cwd, capture_output=True, timeout=timeout, check=False, input=input_text.encode() if input_text else None,
        )
        result = CommandResult(
            command, completed.returncode,
            completed.stdout.decode("utf-8", errors="replace"),
            completed.stderr.decode("utf-8", errors="replace"),
            time.monotonic() - started,
        )
    except subprocess.TimeoutExpired as exc:
        result = CommandResult(
            command, None,
            (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else str(exc.stdout or ""),
            ((exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else str(exc.stderr or "")) + "\nTimed out",
            time.monotonic() - started, timed_out=True,
        )
    if log_file is not None:
        import json
        from datetime import UTC, datetime

        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"timestamp": datetime.now(UTC).isoformat(), "cwd": str(cwd) if cwd else None,
                                     **result.to_dict()}, ensure_ascii=False) + "\n")
    return result
