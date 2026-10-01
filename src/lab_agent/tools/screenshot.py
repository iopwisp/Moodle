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


def capture_window(handle: int) -> Any | None:
    """The window's own pixels via ``PrintWindow`` - correct even when another window covers it.

    A screen grab of the window rectangle captures whatever is on top (a terminal, a messenger) whenever
    Windows refuses to bring the window to the foreground, which it often does for background processes.
    Returns ``None`` when the window cannot render itself (blank result), so the caller can fall back.
    """
    try:
        import ctypes
        from ctypes import wintypes

        from PIL import Image
    except ImportError:
        return None
    if not hasattr(ctypes, "windll"):
        return None
    user32, gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
    try:
        user32.SetProcessDPIAware()
    except Exception:  # noqa: BLE001, S110 - already set
        pass
    rect = wintypes.RECT()
    if not user32.GetWindowRect(handle, ctypes.byref(rect)):
        return None
    width, height = rect.right - rect.left, rect.bottom - rect.top
    if width <= 10 or height <= 10:
        return None
    window_dc = user32.GetWindowDC(handle)
    memory_dc = gdi32.CreateCompatibleDC(window_dc)
    bitmap = gdi32.CreateCompatibleBitmap(window_dc, width, height)
    gdi32.SelectObject(memory_dc, bitmap)
    try:
        if not user32.PrintWindow(handle, memory_dc, 2):  # PW_RENDERFULLCONTENT
            return None

        class BITMAPINFOHEADER(ctypes.Structure):
            _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
                        ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                        ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                        ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD)]

        header = BITMAPINFOHEADER(ctypes.sizeof(BITMAPINFOHEADER), width, -height, 1, 32, 0, 0, 0, 0, 0, 0)
        buffer = ctypes.create_string_buffer(width * height * 4)
        if not gdi32.GetDIBits(memory_dc, bitmap, 0, height, buffer, ctypes.byref(header), 0):
            return None
        image = Image.frombuffer("RGB", (width, height), buffer.raw, "raw", "BGRX", 0, 1)
    finally:
        gdi32.DeleteObject(bitmap)
        gdi32.DeleteDC(memory_dc)
        user32.ReleaseDC(handle, window_dc)
    grey = image.convert("L")
    if grey.getextrema()[0] == grey.getextrema()[1]:
        return None  # one flat colour: the window did not render itself
    # A DPI-unaware window (Java/Swing) renders at its logical size into the physical-size bitmap; the rest
    # stays black. Keep only the rendered part.
    content = grey.point(lambda value: 255 if value else 0).getbbox()
    return image.crop(content) if content else image


def find_window(title_re: str, timeout: float = 5.0) -> Any | None:
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
                    return window
        except Exception:  # noqa: BLE001, S110 - UIA enumeration can race with closing windows
            pass
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.5)


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


def _is_foreground(handle: int) -> bool:
    try:
        import ctypes

        return int(ctypes.windll.user32.GetForegroundWindow()) == handle
    except Exception:  # noqa: BLE001 - not on Windows
        return True


def validate_image(path: Path) -> None:
    from PIL import Image

    with Image.open(path) as image:
        image.verify()


def _window_image(window_title_re: str, attempts: int = 3) -> Any | None:
    """The window's own pixels, or a screen grab of it while it is verifiably in front; never anything else."""
    for attempt in range(attempts):
        window = find_window(window_title_re, timeout=5.0 if attempt == 0 else 2.0)
        if window is None:
            return None
        try:
            if window.is_minimized():
                window.restore()
                time.sleep(0.6)
            image = capture_window(int(window.handle))
            if image is not None:
                return image
            bbox = find_window_rect(window_title_re, timeout=1.0)
            if bbox is not None and _is_foreground(int(window.handle)):
                return _grab(bbox)
        except Exception:  # noqa: BLE001, S110 - windows can close or move between calls; try again
            pass
        time.sleep(1.0)
    return None


def take_screenshot(
    workspace: Path,
    *,
    name: str | None = None,
    window_title_re: str | None = None,
    require_window: bool = True,
) -> Path:
    """Capture the target window, or the full desktop when no window is asked for.

    When a window is asked for, the result shows that window or the call fails: a desktop grab in its place
    could put a terminal, a messenger or a notification into a student's report as "evidence".
    ``require_window=False`` restores the old fallback to the full desktop.
    """
    output = _output(workspace, name)
    image = _window_image(window_title_re) if window_title_re else None
    if image is None and window_title_re and require_window:
        raise ScreenshotUnavailable(f"No clean capture of the window matching {window_title_re!r}: it is not open, "
                                    "or it neither renders itself nor comes to the front.")
    if image is None:
        image = _grab(None)
    image.save(output)
    validate_image(output)
    return output
