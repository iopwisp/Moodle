"""Screenshot capture: a specific application window when possible, else the desktop.

Every capture is validated as a real image before it is returned, so callers
never receive an empty or placeholder file.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class ScreenshotUnavailable(RuntimeError):
    """No interactive desktop / capture backend is available."""


def _output(workspace: Path, name: str | None) -> Path:
    folder = workspace / "screenshots"
    folder.mkdir(parents=True, exist_ok=True)
    filename = name or datetime.now(UTC).strftime("capture_%Y%m%d_%H%M%S_%f.png")
    if Path(filename).name != filename or not filename.lower().endswith(".png"):
        raise ValueError("Screenshot name must be a plain .png filename.")
    return folder / filename


def _grab(bbox: tuple[int, int, int, int] | None) -> Any:
    try:
        from PIL import ImageGrab

        return ImageGrab.grab(bbox=bbox, all_screens=True)
    except Exception as exc:  # noqa: BLE001 - backend specific failures
        try:
            import pyautogui

            if bbox is None:
                return pyautogui.screenshot()
            left, top, right, bottom = bbox
            return pyautogui.screenshot(region=(left, top, right - left, bottom - top))
        except Exception as fallback:
            raise ScreenshotUnavailable(
                "Screenshot capture requires an interactive desktop session and Pillow/pyautogui "
                f"({exc}; {fallback})"
            ) from fallback


def find_window_rect(title_re: str, *, focus: bool = True, timeout: float = 5.0) -> tuple[int, int, int, int] | None:
    """Locate a top-level window by title regex, optionally bring it to front, return its rect."""
    try:
        from pywinauto import Desktop
    except ImportError:
        return None
    pattern = re.compile(title_re)
    deadline = time.monotonic() + timeout
    while True:
        try:
            for window in Desktop(backend="uia").windows():
                title = window.window_text()
                if title and pattern.search(title) and window.is_visible():
                    if focus:
                        try:
                            if window.is_minimized():
                                window.restore()
                            window.set_focus()
                            time.sleep(0.4)
                        except Exception:  # noqa: BLE001, S110 - focus is best effort
                            pass
                    rect = window.rectangle()
                    if rect.width() > 10 and rect.height() > 10:
                        return (rect.left, rect.top, rect.right, rect.bottom)
        except Exception:  # noqa: BLE001, S110 - UIA enumeration can race with closing windows
            pass
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.5)


def validate_image(path: Path) -> None:
    from PIL import Image

    with Image.open(path) as image:
        image.verify()


def take_screenshot(
    workspace: Path,
    *,
    name: str | None = None,
    window_title_re: str | None = None,
    require_window: bool = False,
) -> Path:
    """Capture the target window (focused first) or the full desktop."""
    output = _output(workspace, name)
    bbox = None
    if window_title_re:
        bbox = find_window_rect(window_title_re)
        if bbox is None and require_window:
            raise ScreenshotUnavailable(f"Window matching {window_title_re!r} is not visible.")
    image = _grab(bbox)
    image.save(output)
    validate_image(output)
    return output
