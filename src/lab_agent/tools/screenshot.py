"""Optional desktop screenshot adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path


def take_screenshot(workspace: Path, *, name: str | None = None) -> Path:
    try:
        import pyautogui
    except ImportError as exc:
        raise RuntimeError("Screenshot capture requires the optional 'gui' extra: pip install -e .[gui]") from exc
    folder = workspace / "screenshots"
    folder.mkdir(parents=True, exist_ok=True)
    filename = name or datetime.now(UTC).strftime("capture_%Y%m%d_%H%M%S.png")
    if Path(filename).name != filename or not filename.lower().endswith(".png"):
        raise ValueError("Screenshot name must be a plain .png filename.")
    output = folder / filename
    pyautogui.screenshot().save(output)
    return output
