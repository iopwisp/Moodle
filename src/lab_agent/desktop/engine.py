"""Profile-driven desktop automation engine.

An operation is a list of actions executed against UI Automation selectors::

    - {type: launch}                                   # start/attach the app
    - {type: wait_until, window: {title_re: "New Case"}, timeout: 20}
    - {type: type, control: {automation_id: caseName}, text: "{case_name}"}
    - {type: click, control: {title: "Next", control_type: Button}}
    - {type: hotkey, keys: "^s"}
    - {type: read_text, control: {automation_id: console}, into: console_text}
    - {type: assert_text, control: {...}, contains: "Received = 4"}
    - {type: save, keys: "^s", dialog: {title_re: "Save"}, path_control: {control_type: Edit}, path: "{output}"}
    - {type: close}

Values in ``text``/``keys``/``path`` are templated with ``{name}`` from the
operation variables; a missing variable is an error (never an empty string).
"""

from __future__ import annotations

import string
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .uia import ElementNotFound, UIDriver, validate_selector

ACTION_TYPES = {
    "launch", "wait", "wait_until", "wait_gone", "click", "double_click", "type", "select", "hotkey",
    "focus", "focus_window", "read_text", "read_value", "find_window", "find_control", "close",
    "save", "assert_text", "assert_exists",
}


class _StrictFormatter(string.Formatter):
    def get_value(self, key: Any, args: Any, kwargs: Any) -> Any:
        if isinstance(key, str) and key not in kwargs:
            raise KeyError(f"Profile template variable {{{key}}} was not provided")
        return super().get_value(key, args, kwargs)


def render(value: str, variables: dict[str, Any]) -> str:
    return _StrictFormatter().vformat(str(value), (), variables)


def render_tree(value: Any, variables: dict[str, Any]) -> Any:
    """Render every string inside nested lists/dicts (used for profile goals)."""
    if isinstance(value, str):
        return render(value, variables)
    if isinstance(value, list):
        return [render_tree(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: render_tree(item, variables) for key, item in value.items()}
    return value


def render_selector(selector: dict[str, Any], variables: dict[str, Any]) -> dict[str, Any]:
    if "any" in selector:
        return {"any": [render_selector(option, variables) for option in selector["any"]]}
    return {key: render(value, variables) if isinstance(value, str) else value for key, value in selector.items()}


@dataclass
class OperationResult:
    operation: str
    actions: list[dict[str, Any]] = field(default_factory=list)
    values: dict[str, str] = field(default_factory=dict)
    window_title: str = ""
    pid: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"operation": self.operation, "actions": self.actions, "values": self.values,
                "window_title": self.window_title, "pid": self.pid}


class ProfileEngine:
    def __init__(self, driver: UIDriver, profile: dict[str, Any], *, launcher: Any = None, sleep: Any = time.sleep) -> None:
        self.driver = driver
        self.profile = profile
        self.launcher = launcher
        self.sleep = sleep
        self.window: Any = None

    @property
    def window_selector(self) -> dict[str, Any]:
        selector = self.profile.get("window") or {}
        if not selector:
            raise ValueError(f"Profile {self.profile.get('name')} declares no main window selector")
        return validate_selector(selector)

    def attach(self, timeout: float | None = None) -> Any:
        wait = float(timeout if timeout is not None else self.profile.get("window_timeout_seconds", 30))
        self.window = self.driver.find_window(self.window_selector, timeout=wait)
        if self.window is None:
            raise ElementNotFound(f"{self.profile.get('name')} window {self.window_selector} did not appear within {wait}s")
        return self.window

    def _window_for(self, action: dict[str, Any], variables: dict[str, Any]) -> Any:
        if action.get("window"):
            selector = render_selector(validate_selector(action["window"]), variables)
            window = self.driver.find_window(selector, timeout=float(action.get("timeout", 15)))
            if window is None:
                raise ElementNotFound(f"window {selector} not found")
            return window
        return self.window if self.window is not None else self.attach()

    def _control(self, action: dict[str, Any], variables: dict[str, Any], key: str = "control") -> Any:
        window = self._window_for(action, variables)
        if not action.get(key):
            return window
        selector = render_selector(validate_selector(action[key]), variables)
        control = self.driver.find_control(window, selector, timeout=float(action.get("timeout", 15)))
        if control is None:
            raise ElementNotFound(f"control {selector} not found in {self.driver.window_title(window)!r}")
        return control

    def run(self, operation: str, variables: dict[str, Any]) -> OperationResult:
        operations = self.profile.get("operations", {})
        if operation not in operations:
            available = ", ".join(sorted(operations)) or "none"
            raise ValueError(f"Operation {operation!r} is not in the {self.profile.get('name')} profile. Available operations: {available}.")
        result = OperationResult(operation)
        for index, action in enumerate(operations[operation] or []):
            kind = str(action.get("type", ""))
            if kind not in ACTION_TYPES:
                raise ValueError(f"Unsupported profile action {kind!r} (step {index}) in {operation}")
            started = time.monotonic()
            outcome = self._run_action(kind, action, variables, result)
            result.actions.append({"index": index, "type": kind, "seconds": round(time.monotonic() - started, 2), **outcome})
        if self.window is not None:
            try:
                result.window_title = self.driver.window_title(self.window)
            except Exception:  # noqa: BLE001, S110 - window may have been closed by the operation
                pass
        return result

    def _run_action(self, kind: str, action: dict[str, Any], variables: dict[str, Any], result: OperationResult) -> dict[str, Any]:
        if kind == "launch":
            existing = self.driver.find_window(self.window_selector, timeout=0)
            if existing is not None and not action.get("new_instance"):
                self.window = existing
                return {"attached": True}
            if self.launcher is None:
                raise RuntimeError("Profile operation requires launching the application but no launcher is configured")
            args = [render(arg, variables) for arg in action.get("args", [])]
            process = self.launcher(args)
            result.pid = getattr(process, "pid", None)
            self.sleep(float(self.profile.get("launch_wait_seconds", 3)))
            self.attach()
            return {"launched": True, "pid": result.pid}
        if kind == "wait":
            self.sleep(min(float(action.get("seconds", 1)), 120.0))
            return {}
        if kind in {"wait_until", "find_window"}:
            if action.get("control"):
                self._control(action, variables)
            else:
                self._window_for(action, variables)
            return {"found": True}
        if kind == "wait_gone":
            selector = render_selector(validate_selector(action["window"]), variables)
            deadline = time.monotonic() + float(action.get("timeout", 30))
            while self.driver.find_window(selector, timeout=0) is not None:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"window {selector} still open")
                self.sleep(0.5)
            return {"gone": True}
        if kind in {"focus", "focus_window"}:
            self.driver.focus(self._window_for(action, variables))
            return {}
        if kind == "find_control":
            self._control(action, variables)
            return {"found": True}
        if kind in {"click", "double_click"}:
            self.driver.click(self._control(action, variables), double=kind == "double_click")
            return {}
        if kind == "type":
            control = self._control(action, variables) if action.get("control") else None
            self.driver.type_text(control, render(action["text"], variables), replace=bool(action.get("replace", True)))
            return {"chars": len(render(action["text"], variables))}
        if kind == "select":
            self.driver.select(self._control(action, variables), render(action["value"], variables))
            return {}
        if kind == "hotkey":
            if action.get("window") or self.window is not None:
                self.driver.focus(self._window_for(action, variables))
            self.driver.hotkey(render(action["keys"], variables))
            return {}
        if kind in {"read_text", "read_value"}:
            control = self._control(action, variables)
            text = self.driver.read_text(control) if kind == "read_text" else self.driver.read_value(control)
            key = str(action.get("into", kind))
            result.values[key] = text
            variables[key] = text
            return {"into": key, "chars": len(text)}
        if kind == "assert_text":
            text = self.driver.read_text(self._control(action, variables))
            expected = render(action["contains"], variables)
            if expected not in text:
                raise AssertionError(f"expected {expected!r} in control text")
            return {"matched": expected}
        if kind == "assert_exists":
            self._control(action, variables)
            return {"exists": True}
        if kind == "save":
            self.driver.focus(self._window_for({}, variables))
            self.driver.hotkey(render(action.get("keys", "^s"), variables))
            if action.get("dialog"):
                dialog_action = {"window": action["dialog"], "timeout": action.get("timeout", 15)}
                path_control = self._control({**dialog_action, "control": action.get("path_control", {"control_type": "Edit"})}, variables)
                target = render(action["path"], variables)
                self.driver.type_text(path_control, target)
                self.driver.hotkey("{ENTER}")
                deadline = time.monotonic() + float(action.get("timeout", 15))
                while not Path(target).exists():
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"saved file {target} did not appear")
                    self.sleep(0.5)
                return {"saved": target}
            return {}
        if kind == "close":
            window = self._window_for(action, variables)
            self.driver.close(window)
            if window is self.window:
                self.window = None
            return {}
        raise ValueError(f"Unhandled action {kind}")
