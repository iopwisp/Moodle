"""Input posted to a window's message queue: clicks, drags and keys that need neither focus nor the real mouse.

Qt 5 programs read the button state of client-area mouse messages from ``wParam`` and hand posted keys to the
focus widget of the window that receives them, so a posted click or a typed command reaches the intended widget
while the student keeps working in another program.  Verified on Packet Tracer 8.2.2 (Qt 5.15.16, 150 % scaling):
canvas clicks open device windows, event-filter check boxes toggle, device-window tabs switch, a dock separator of
the main window drags, table rows get selected, and ``WM_CHAR`` text types into the PC Command Prompt.

Not usable for: title-bar (non-client) actions - Qt reads the real mouse state there - and OLE drag and drop,
which polls the physical mouse.  Those still need :class:`~lab_agent.desktop.pointer.RealPointer`.
"""

from __future__ import annotations

import os
import time
from typing import Any, Protocol

WM_CLOSE, WM_KEYDOWN, WM_KEYUP, WM_CHAR = 0x0010, 0x0100, 0x0101, 0x0102
WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_LBUTTONUP = 0x0200, 0x0201, 0x0202
MK_LBUTTON = 0x0001
KEYS = {"enter": 0x0D, "esc": 0x1B, "escape": 0x1B, "backspace": 0x08, "tab": 0x09, "space": 0x20,
        "end": 0x23, "home": 0x24, "left": 0x25, "up": 0x26, "right": 0x27, "down": 0x28, "delete": 0x2E}


class Poster(Protocol):
    """What the Packet Tracer automation needs; tests use an in-memory fake."""

    def click(self, window: Any, x: int, y: int) -> None: ...
    def drag(self, window: Any, start: tuple[int, int], end: tuple[int, int]) -> None: ...
    def type_text(self, window: Any, text: str) -> None: ...
    def press(self, window: Any, *keys: str) -> None: ...
    def close(self, window: Any) -> None: ...
    def resize(self, window: Any, width: int, height: int) -> None: ...


def window_handle(window: Any) -> int | None:
    """Win32 handle of a pywinauto wrapper (top-level windows have ``handle``, child dialogs ``element_info.handle``)."""
    for getter in (lambda: window.handle, lambda: window.element_info.handle):
        try:
            value = getter()
        except Exception:  # noqa: BLE001, S112 - fakes and alien Qt widgets have no handle
            continue
        if value:
            return int(value)
    return None


def restore_minimized(title_part: str) -> int:
    """Un-minimize (without activating) every top-level window whose title contains ``title_part``.

    A minimized Packet Tracer shows UI Automation a bare "Cisco Packet Tracer" title and no controls, so its project
    window cannot even be found until it is restored.  Returns how many windows were restored.
    """
    if os.name != "nt":
        return 0
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    found: list[int] = []

    def visit(handle: int, _: int) -> bool:
        if user32.IsWindowVisible(handle) and user32.IsIconic(handle):
            title = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(handle, title, 512)
            if title_part.casefold() in title.value.casefold():
                found.append(handle)
        return True

    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)(visit), 0)
    for handle in found:
        user32.ShowWindow(handle, 4)  # SW_SHOWNOACTIVATE
    if found:
        time.sleep(0.8)
    return len(found)


class MessagePoster:
    """Posts mouse and keyboard messages to a window; screen coordinates are converted to its client area."""

    def __init__(self, *, pause: float = 0.03) -> None:
        if os.name != "nt":
            raise RuntimeError("Posted window messages are only available on Windows.")
        import ctypes

        self._user32 = ctypes.windll.user32
        self._ctypes = ctypes
        self.pause = pause

    def _handle(self, window: Any) -> int:
        handle = window if isinstance(window, int) else window_handle(window)
        if not handle:
            raise ValueError("This window has no Win32 handle; messages cannot be posted to it.")
        return handle

    def _lparam(self, handle: int, x: int, y: int) -> int:
        from ctypes import wintypes

        origin = wintypes.POINT(0, 0)
        self._user32.ClientToScreen(handle, self._ctypes.byref(origin))
        return ((y - origin.y) & 0xFFFF) << 16 | ((x - origin.x) & 0xFFFF)

    def _post(self, handle: int, message: int, wparam: int, lparam: int) -> None:
        if not self._user32.PostMessageW(handle, message, wparam, lparam):
            raise OSError(f"PostMessage {message:#06x} to window {handle} failed")

    def click(self, window: Any, x: int, y: int) -> None:
        handle = self._handle(window)
        point = self._lparam(handle, x, y)
        self._post(handle, WM_MOUSEMOVE, 0, point)
        self._post(handle, WM_LBUTTONDOWN, MK_LBUTTON, point)
        self._post(handle, WM_LBUTTONUP, 0, point)
        time.sleep(self.pause)

    def drag(self, window: Any, start: tuple[int, int], end: tuple[int, int], steps: int = 10) -> None:
        handle = self._handle(window)
        self._post(handle, WM_MOUSEMOVE, 0, self._lparam(handle, *start))
        self._post(handle, WM_LBUTTONDOWN, MK_LBUTTON, self._lparam(handle, *start))
        time.sleep(self.pause)
        for index in range(1, steps + 1):
            x = start[0] + (end[0] - start[0]) * index // steps
            y = start[1] + (end[1] - start[1]) * index // steps
            self._post(handle, WM_MOUSEMOVE, MK_LBUTTON, self._lparam(handle, x, y))
            time.sleep(self.pause)
        self._post(handle, WM_LBUTTONUP, 0, self._lparam(handle, *end))
        time.sleep(self.pause * 3)

    def type_text(self, window: Any, text: str) -> None:
        handle = self._handle(window)
        for char in text:
            self._post(handle, WM_CHAR, ord(char), 1)
            time.sleep(0.005)

    def press(self, window: Any, *keys: str) -> None:
        handle = self._handle(window)
        for key in keys:
            code = KEYS[key.casefold()]
            scan = self._user32.MapVirtualKeyW(code, 0)
            self._post(handle, WM_KEYDOWN, code, 1 | scan << 16)
            self._post(handle, WM_KEYUP, code, 1 | scan << 16 | 3 << 30)
            time.sleep(self.pause)

    def close(self, window: Any) -> None:
        self._post(self._handle(window), WM_CLOSE, 0, 0)

    def resize(self, window: Any, width: int, height: int) -> None:
        # SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE: the student's foreground window stays in front
        self._user32.SetWindowPos(self._handle(window), 0, 0, 0, int(width), int(height), 0x0002 | 0x0004 | 0x0010)
        time.sleep(0.4)


class PostedPointer:
    """The canvas pointer protocol (:class:`~lab_agent.desktop.pointer.RealPointer`'s methods) over posted messages.

    A drag becomes a click on the source and a click on the target: Packet Tracer places the chosen model where the
    canvas is clicked next (its drag itself is OLE and needs the physical mouse).  A click that lands on a popup menu
    of the same program - the port menu after a cable end - goes to that menu.
    """

    def __init__(self, driver: Any, poster: Any = None, *, pause: float = 0.3) -> None:
        self.driver = driver
        self.poster = poster or MessagePoster()
        self.pause = pause

    def _target(self, window: Any, x: int, y: int) -> Any:
        menu = self.driver.find_window({"class_name": "QMenu"}, timeout=0)
        if menu is not None:
            try:
                same = window is None or menu.process_id() == window.process_id()
            except Exception:  # noqa: BLE001 - fakes have no process
                same = True
            left, top, right, bottom = self.driver.rectangle(menu)
            if same and left <= x < right and top <= y < bottom:
                return menu
        return window

    def click(self, x: int, y: int, *, window: Any = None, double: bool = False) -> None:
        target = self._target(window, x, y)
        self.poster.click(target, x, y)
        if double:
            self.poster.click(target, x, y)

    def drag(self, start: tuple[int, int], end: tuple[int, int], *, window: Any = None) -> None:
        self.poster.click(window, *start)
        time.sleep(self.pause)
        self.poster.click(window, *end)

    def type_text(self, text: str, *, window: Any = None) -> None:
        self.poster.type_text(window, text)

    def press(self, *keys: str, window: Any = None) -> None:
        self.poster.press(window, *keys)
