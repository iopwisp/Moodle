"""Test doubles: screenshots, a UI Automation driver and application behaviour.

They reproduce the *observable* behaviour the agent verifies (windows,
controls, console text, files) so that CI can exercise the complete pipeline
without Windows GUI applications.  Real-application runs are separate
(``tests/test_real_environment.py``) and skipped when the apps are absent.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from PIL import Image

from lab_agent.desktop.uia import alternatives, element_matches


def fake_screenshot(workspace: Path, *, name: str | None = None, window_title_re: str | None = None) -> Path:
    output = workspace / "screenshots" / (name or "screen.png")
    output.parent.mkdir(parents=True, exist_ok=True)
    Image.new("RGB", (96, 64), color=(30, 78, 120)).save(output)
    return output


@dataclass
class FakeControl:
    name: str
    control_type: str = "Button"
    automation_id: str = ""
    class_name: str = ""
    enabled: bool = True
    visible: bool = True
    text: str = ""
    on_click: Callable[[], None] | None = None
    on_type: Callable[[str], None] | None = None

    def info(self, index: int) -> dict[str, Any]:
        return {"index": index, "depth": 1, "name": self.name, "control_type": self.control_type,
                "automation_id": self.automation_id, "class_name": self.class_name, "enabled": self.enabled,
                "visible": self.visible, "rect": [0, 0, 10, 10]}


@dataclass
class FakeWindow:
    name: str
    controls: list[FakeControl] = field(default_factory=list)
    class_name: str = "FakeWindow"
    visible: bool = True
    closed: bool = False

    def info(self) -> dict[str, Any]:
        return {"name": self.name, "class_name": self.class_name, "visible": self.visible, "control_type": "Window"}


class FakeDriver:
    """In-memory implementation of :class:`lab_agent.desktop.uia.UIDriver`."""

    def __init__(self) -> None:
        self.windows: list[FakeWindow] = []
        self.hotkeys: list[str] = []
        self.focused: FakeWindow | None = None
        self.focused_control: FakeControl | None = None
        self.hotkey_handlers: dict[str, Callable[[], None]] = {}
        self.actions: list[tuple[str, str]] = []

    def add_window(self, window: FakeWindow) -> FakeWindow:
        self.windows.append(window)
        return window

    def list_windows(self) -> list[dict[str, Any]]:
        return [w.info() for w in self.windows if not w.closed]

    def find_window(self, selector: dict[str, Any], timeout: float = 10) -> FakeWindow | None:
        for option in alternatives(selector):
            for window in self.windows:
                if not window.closed and window.visible and element_matches(window.info(), option):
                    return window
        return None

    def find_control(self, window: FakeWindow, selector: dict[str, Any], timeout: float = 10) -> FakeControl | None:
        for option in alternatives(selector):
            for index, control in enumerate(window.controls):
                if control.visible and element_matches(control.info(index), option):
                    return control
        return None

    def snapshot(self, window: FakeWindow, max_depth: int = 6, limit: int = 400) -> list[dict[str, Any]]:
        return [control.info(index) for index, control in enumerate(window.controls)][:limit]

    def click(self, control: FakeControl, *, double: bool = False) -> None:
        self.actions.append(("double_click" if double else "click", control.name))
        self.focused_control = control
        if control.on_click:
            control.on_click()

    def type_text(self, control: FakeControl | None, text: str, *, replace: bool = True) -> None:
        target = control or self.focused_control
        self.actions.append(("type", text))
        if target is None:
            return
        self.focused_control = target
        if target.on_type:
            target.on_type(text)
        else:
            target.text = text if replace else target.text + text

    def select(self, control: FakeControl, value: str) -> None:
        control.text = value

    def hotkey(self, keys: str) -> None:
        self.hotkeys.append(keys)
        handler = self.hotkey_handlers.get(keys)
        if handler:
            handler()
        elif keys == "{ENTER}" and self.focused_control is not None and self.focused_control.on_type:
            self.focused_control.on_type("\n")

    def focus(self, window: FakeWindow) -> None:
        self.focused = window

    def read_text(self, control: FakeControl | FakeWindow) -> str:
        return getattr(control, "text", "") or getattr(control, "name", "")

    def read_value(self, control: FakeControl) -> str:
        return control.text

    def close(self, window: FakeWindow) -> None:
        window.closed = True

    def window_title(self, window: FakeWindow) -> str:
        return window.name


class FakeIOSConsole:
    """Very small Cisco IOS / PT Command Prompt imitation for CLI tests."""

    def __init__(self, hostname: str, *, pc: bool = False, ping_ok: bool = True) -> None:
        self.hostname = hostname
        self.pc = pc
        self.ping_ok = ping_ok
        self.control = FakeControl("console", "Edit", on_type=self._type)
        self.buffer = ""
        self.running: list[str] = []
        self.ip: str | None = None

    def _type(self, text: str) -> None:
        if text != "\n":
            self.buffer += text
            return
        line, self.buffer = self.buffer.strip(), ""
        self.control.text += f"\n{self.hostname}# {line}\n" + self.respond(line)

    def respond(self, line: str) -> str:
        if not line:
            return ""
        if self.pc:
            match = re.match(r"ipconfig (\S+) (\S+)", line)
            if match:
                self.ip = match.group(1)
                return ""
            if line == "ipconfig":
                return f"IPv4 Address......: {self.ip or '0.0.0.0'}\n"
            if line.startswith("ping "):
                received = 4 if self.ping_ok else 0
                return f"Ping statistics for {line.split()[1]}:\n    Packets: Sent = 4, Received = {received}, Lost = {4 - received}\n"
            return "Invalid Command.\n"
        if line.startswith("bogus"):
            return "% Invalid input detected at '^' marker.\n"
        if line == "show running-config":
            return "Building configuration...\n" + "\n".join(self.running) + "\nend\n"
        if line in {"enable", "configure terminal", "end", "terminal length 0", "write memory", "exit"}:
            return ""
        self.running.append(line.strip())
        return ""


def pt_device_window(driver: FakeDriver, name: str, console: FakeIOSConsole) -> FakeWindow:
    window = FakeWindow(name, [FakeControl("Physical", "TabItem"), FakeControl("Config", "TabItem"),
                               FakeControl("CLI", "TabItem"), FakeControl("Desktop", "TabItem"),
                               FakeControl("Command Prompt", "TabItem"), console.control])
    return driver.add_window(window)
