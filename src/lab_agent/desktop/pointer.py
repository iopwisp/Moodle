"""Real mouse and keyboard input for canvases that have no accessibility controls (Packet Tracer's workspace).

Every action names the window it is meant for and is refused when that window cannot be brought to the
foreground - otherwise clicks and keys would land in whatever the user has in front (a terminal, a chat).
Typed text and shortcuts switch the target window to the US keyboard layout first: with a Russian layout
active, ``Ctrl+A`` is not Select All in Qt applications and typed Latin letters come out as Cyrillic.

Coordinates are physical screen pixels: the process is made DPI-aware so they match UI Automation
rectangles and ``PrintWindow`` captures on scaled displays.
"""

from __future__ import annotations

import os
import time
from typing import Any, Protocol


class InputRefused(RuntimeError):
    """The target window is not in front, so no input was sent."""


class Pointer(Protocol):
    def click(self, x: int, y: int, *, window: Any = None, double: bool = False) -> None: ...
    def drag(self, start: tuple[int, int], end: tuple[int, int], *, window: Any = None) -> None: ...
    def type_text(self, text: str, *, window: Any = None) -> None: ...
    def press(self, *keys: str, window: Any = None) -> None: ...


def make_dpi_aware() -> None:
    if os.name != "nt":
        return
    import ctypes

    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # per-monitor
    except Exception:  # noqa: BLE001 - already set, or an older Windows
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:  # noqa: BLE001, S110
            pass


def _handle(window: Any) -> int | None:
    if window is None:
        return None
    if isinstance(window, int):
        return window
    handle = getattr(window, "handle", None)
    return int(handle) if handle else None


class RealPointer:
    """pyautogui input guarded by a foreground check."""

    def __init__(self, *, pause: float = 0.12) -> None:
        try:
            import pyautogui
        except ImportError as exc:
            raise RuntimeError("Canvas automation requires the gui extra: pip install -e .[gui]") from exc
        make_dpi_aware()
        pyautogui.FAILSAFE = True  # moving the mouse into a screen corner aborts
        pyautogui.PAUSE = pause
        self._gui = pyautogui

    # -- window handling -----------------------------------------------------------
    def _front(self, window: Any) -> None:
        handle = _handle(window)
        if handle is None or os.name != "nt":
            return
        import ctypes

        user32 = ctypes.windll.user32
        if user32.GetForegroundWindow() != handle:
            self._gui.press("alt")  # lets a background process call SetForegroundWindow
            user32.ShowWindow(handle, 9 if user32.IsIconic(handle) else 5)
            user32.SetForegroundWindow(handle)
            time.sleep(0.4)
        foreground = user32.GetForegroundWindow()
        if foreground != handle and user32.GetAncestor(foreground, 3) != handle:  # GA_ROOTOWNER: its own popup
            title = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(foreground, title, 256)
            raise InputRefused(f"The target window is not in front (foreground: {title.value!r}); no input was sent. "
                               "Unlock the screen and leave the mouse and keyboard alone, then resume.")

    def _english(self, window: Any) -> None:
        handle = _handle(window)
        if handle is None or os.name != "nt":
            return
        import ctypes

        user32 = ctypes.windll.user32
        layout = user32.LoadKeyboardLayoutW("00000409", 1)
        user32.PostMessageW(user32.GetForegroundWindow() or handle, 0x0050, 0, layout)  # WM_INPUTLANGCHANGEREQUEST
        time.sleep(0.25)

    # -- input --------------------------------------------------------------------
    def click(self, x: int, y: int, *, window: Any = None, double: bool = False) -> None:
        self._front(window)
        if double:
            self._gui.doubleClick(x, y)
        else:
            self._gui.click(x, y)

    def drag(self, start: tuple[int, int], end: tuple[int, int], *, window: Any = None) -> None:
        self._front(window)
        self._gui.moveTo(*start)
        self._gui.mouseDown()
        time.sleep(0.25)
        self._gui.moveTo(*end, duration=0.5)
        time.sleep(0.25)
        self._gui.mouseUp()

    def type_text(self, text: str, *, window: Any = None) -> None:
        self._front(window)
        self._english(window)
        if not text.isascii():
            raise ValueError("Only ASCII text can be typed into the canvas application")
        self._gui.write(text, interval=0.03)

    def press(self, *keys: str, window: Any = None) -> None:
        self._front(window)
        self._english(window)
        for key in keys:
            self._gui.hotkey(*key.split("+"))
