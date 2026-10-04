"""UI Automation driver abstraction.

Selectors are dictionaries using accessibility properties only - never screen
coordinates::

    {"title": "OK", "control_type": "Button"}
    {"title_re": ".*Wireshark.*"}
    {"automation_id": "caseNameTextField"}
    {"any": [{"title": "Later"}, {"title": "Not now"}]}   # alternatives

:class:`PywinautoDriver` implements the protocol with pywinauto's UIA backend;
tests use an in-memory fake with the same interface.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Protocol

SELECTOR_KEYS = {"title", "title_re", "automation_id", "auto_id", "control_type", "class_name", "found_index", "process"}


class ElementNotFound(LookupError):
    """A window or control matching a selector did not appear before the timeout."""


def validate_selector(selector: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(selector, dict) or not selector:
        raise ValueError(f"Selector must be a non-empty mapping, got {selector!r}")
    if "any" in selector:
        options = selector["any"]
        if not isinstance(options, list) or not options:
            raise ValueError("'any' selector needs a non-empty list of alternatives")
        return {"any": [validate_selector(option) for option in options]}
    unknown = set(selector) - SELECTOR_KEYS
    if unknown:
        raise ValueError(f"Unsupported selector keys {sorted(unknown)}; allowed: {sorted(SELECTOR_KEYS)}")
    for forbidden in ("x", "y", "coords"):
        if forbidden in selector:
            raise ValueError("Coordinates are not accepted as selectors")
    return selector


def alternatives(selector: dict[str, Any]) -> list[dict[str, Any]]:
    selector = validate_selector(selector)
    return list(selector["any"]) if "any" in selector else [selector]


def element_matches(info: dict[str, Any], selector: dict[str, Any]) -> bool:
    """Match a flattened element description (see ``snapshot``) against one selector."""
    name = str(info.get("name", ""))
    if "title" in selector and name != str(selector["title"]):
        return False
    if "title_re" in selector and not re.search(str(selector["title_re"]), name):
        return False
    auto_id = selector.get("automation_id", selector.get("auto_id"))
    if auto_id is not None and str(info.get("automation_id", "")) != str(auto_id):
        return False
    if "control_type" in selector and str(info.get("control_type", "")).casefold() != str(selector["control_type"]).casefold():
        return False
    return not ("class_name" in selector and str(info.get("class_name", "")) != str(selector["class_name"]))


_MODIFIER_VK = {"^": 0x11, "+": 0x10, "%": 0x12}


def parse_chord(keys: str) -> tuple[list[int], int] | None:
    """``"^+s"`` -> ([VK_CONTROL, VK_SHIFT], VK_S); ``None`` for anything else (e.g. ``{ENTER}``)."""
    modifiers: list[int] = []
    index = 0
    while index < len(keys) and keys[index] in _MODIFIER_VK:
        modifiers.append(_MODIFIER_VK[keys[index]])
        index += 1
    rest = keys[index:]
    if modifiers and len(rest) == 1 and rest.isascii() and rest.isalnum():
        return modifiers, ord(rest.upper())
    return None


class UIDriver(Protocol):
    def list_windows(self) -> list[dict[str, Any]]: ...
    def find_window(self, selector: dict[str, Any], timeout: float = 10) -> Any | None: ...
    def find_control(self, window: Any, selector: dict[str, Any], timeout: float = 10) -> Any | None: ...
    def snapshot(self, window: Any, max_depth: int = 6, limit: int = 400) -> list[dict[str, Any]]: ...
    def click(self, control: Any, *, double: bool = False) -> None: ...
    def type_text(self, control: Any | None, text: str, *, replace: bool = True) -> None: ...
    def select(self, control: Any, value: str) -> None: ...
    def hotkey(self, keys: str) -> None: ...
    def focus(self, window: Any) -> None: ...
    def read_text(self, control: Any) -> str: ...
    def read_value(self, control: Any) -> str: ...
    def close(self, window: Any) -> None: ...
    def window_title(self, window: Any) -> str: ...


def fingerprint(elements: list[dict[str, Any]], title: str = "") -> str:
    """Stable digest of what is visible, used for state-change / stuck detection."""
    digest = hashlib.sha256(title.encode("utf-8", errors="replace"))
    for item in elements:
        digest.update(f"{item.get('control_type')}|{item.get('name')}|{item.get('automation_id')}|{item.get('enabled')}".encode(
            "utf-8", errors="replace"))
    return digest.hexdigest()[:16]


class PywinautoDriver:
    """Windows UI Automation driver (pywinauto UIA backend)."""

    def __init__(self) -> None:
        try:
            from pywinauto import Desktop, keyboard
        except ImportError as exc:
            raise RuntimeError("Desktop automation requires the gui extra: pip install -e .[gui]") from exc
        self._desktop = Desktop(backend="uia")
        self._keyboard = keyboard

    @staticmethod
    def _criteria(selector: dict[str, Any]) -> dict[str, Any]:
        # found_index=0 picks the first match; pywinauto otherwise raises for
        # "ambiguous" matches such as a button and its own text element.
        criteria: dict[str, Any] = {"found_index": 0}
        for key, value in selector.items():
            if key in {"automation_id", "auto_id"}:
                criteria["auto_id"] = value
            elif key == "process":
                continue
            elif key == "title_re":
                # pywinauto anchors title_re at the start (re.match); selectors mean "anywhere in the title", as in
                # the fake driver - "Create_a_Simple_Network" must match "Cisco Packet Tracer - ...\Create_a_Simple_Network.pka".
                criteria[key] = f".*(?:{value})"
            else:
                criteria[key] = value
        return criteria

    def list_windows(self) -> list[dict[str, Any]]:
        rows = []
        for window in self._desktop.windows():
            try:
                rows.append({
                    "name": window.window_text(), "class_name": window.class_name(),
                    "process_id": window.process_id(), "visible": window.is_visible(),
                })
            except Exception:  # noqa: BLE001, S112 - windows may close while enumerating
                continue
        return rows

    def find_window(self, selector: dict[str, Any], timeout: float = 10) -> Any | None:
        deadline = time.monotonic() + timeout
        while True:
            for option in alternatives(selector):
                try:
                    spec = self._desktop.window(**self._criteria(option))
                    if spec.exists(timeout=0):
                        wrapper = spec.wrapper_object()
                        if wrapper.is_visible():
                            return wrapper
                except Exception:  # noqa: BLE001, S112 - ambiguous/closing windows
                    continue
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.5)

    @staticmethod
    def _info(element: Any) -> dict[str, Any]:
        info = element.element_info
        return {"name": info.name or "", "control_type": info.control_type or "", "automation_id": info.automation_id or "",
                "class_name": info.class_name or "", "visible": True}

    def _scan(self, window: Any, option: dict[str, Any], limit: int = 5000) -> Any | None:
        """Match on accessible properties (element_info), like :meth:`snapshot` reports them.

        pywinauto's own ``title`` criterion compares against the control *text*
        (for Edit controls the typed value), not the accessible name, so name
        selectors such as ``{"title": "Display filter entry"}`` must be matched here.
        """
        wanted_index = int(option.get("found_index", 0))
        matches = 0
        try:
            descendants = window.descendants(control_type=option["control_type"]) if option.get("control_type") else window.descendants()
        except Exception:  # noqa: BLE001 - window closed while scanning
            return None
        for element in descendants[:limit]:
            try:
                if element_matches(self._info(element), option):
                    if matches == wanted_index:
                        return element
                    matches += 1
            except Exception:  # noqa: BLE001, S112 - stale element
                continue
        return None

    def find_control(self, window: Any, selector: dict[str, Any], timeout: float = 10) -> Any | None:
        deadline = time.monotonic() + timeout
        while True:
            for option in alternatives(selector):
                if set(option) <= {"automation_id", "auto_id", "control_type", "found_index"}:
                    try:  # fast path: native lookup is exact for automation ids
                        spec = window.child_window(**self._criteria(option))
                        if spec.exists(timeout=0):
                            return spec.wrapper_object()
                    except Exception:  # noqa: BLE001, S110
                        pass
                found = self._scan(window, option)
                if found is not None:
                    return found
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.4)

    def snapshot(self, window: Any, max_depth: int = 6, limit: int = 400) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []

        def walk(element: Any, depth: int) -> None:
            if len(rows) >= limit or depth > max_depth:
                return
            try:
                info = element.element_info
                rect = element.rectangle()
                rows.append({
                    "index": len(rows), "depth": depth, "name": info.name or "",
                    "control_type": info.control_type or "", "automation_id": info.automation_id or "",
                    "class_name": info.class_name or "", "enabled": bool(element.is_enabled()),
                    "visible": bool(element.is_visible()),
                    "rect": [rect.left, rect.top, rect.right, rect.bottom],
                })
                for child in element.children():
                    walk(child, depth + 1)
            except Exception:  # noqa: BLE001 - stale elements are skipped
                return

        walk(window, 0)
        return rows

    def click(self, control: Any, *, double: bool = False) -> None:
        if double:
            control.double_click_input()
            return
        try:
            control.invoke()
        except Exception:  # noqa: BLE001 - not every control supports the Invoke pattern
            control.click_input()

    def type_text(self, control: Any | None, text: str, *, replace: bool = True) -> None:
        if control is not None and replace:
            try:
                control.set_edit_text(text)  # UIA ValuePattern: independent of the keyboard layout
                if self.read_value(control) == text:
                    return
            except Exception:  # noqa: BLE001, S110 - fall back to keystrokes
                pass
        if control is not None:
            control.set_focus()
        # vk_packet sends Unicode characters, so a non-Latin layout cannot change the text.
        escaped = "".join("{" + ch + "}" if ch in "+^%~(){}[]" else ch for ch in text)
        self._keyboard.send_keys(escaped, with_spaces=True, with_newlines=True, pause=0.01, vk_packet=True)
        if control is not None and replace:
            value = self.read_value(control)
            if value and value != text:
                raise RuntimeError(f"typed text was altered by the input method: {value!r} != {text!r}")

    def select(self, control: Any, value: str) -> None:
        control.select(value)

    def hotkey(self, keys: str) -> None:
        """Send a shortcut; letter/digit chords use virtual-key codes so they work under any keyboard layout."""
        chord = parse_chord(keys)
        if chord is None:
            self._keyboard.send_keys(keys)
            return
        import ctypes

        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        modifiers, key = chord
        for vk in modifiers:
            user32.keybd_event(vk, 0, 0, 0)
        user32.keybd_event(key, 0, 0, 0)
        user32.keybd_event(key, 0, 2, 0)
        for vk in reversed(modifiers):
            user32.keybd_event(vk, 0, 2, 0)

    def focus(self, window: Any) -> None:
        if window.is_minimized():
            window.restore()
        window.set_focus()

    def read_text(self, control: Any) -> str:
        parts: list[str] = []
        for getter in ("window_text", "get_value", "legacy_properties"):
            try:
                value = getattr(control, getter)()
            except Exception:  # noqa: BLE001, S112
                continue
            if isinstance(value, dict):
                value = value.get("Value", "")
            if value:
                parts.append(str(value))
        try:
            texts = control.texts()
            parts.extend(str(t) for t in texts if t)
        except Exception:  # noqa: BLE001, S110
            pass
        return "\n".join(dict.fromkeys(parts))

    def read_value(self, control: Any) -> str:
        try:
            return str(control.get_value())
        except Exception:  # noqa: BLE001
            return self.read_text(control)

    def close(self, window: Any) -> None:
        window.close()

    def window_title(self, window: Any) -> str:
        return str(window.window_text())
