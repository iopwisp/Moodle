"""Application lifecycle management shared by desktop integrations.

``discover -> launch -> wait ready -> use -> verify -> save -> close``

:class:`ManagedApplication` resolves the executable (config, environment
variable, discovery), launches or attaches to the application, waits for its
main window through UI Automation, detects blocking dialogs declared in the
profile (login walls, licence prompts), runs profile operations and captures
window-targeted screenshots.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .desktop.engine import OperationResult, ProfileEngine
from .desktop.profiles import load_profile
from .desktop.uia import UIDriver
from .integrations.base import AppSpec, CapabilityBlocked, ExecutionContext
from .tools.process import launch_application


def default_driver() -> UIDriver:
    from .desktop.uia import PywinautoDriver

    return PywinautoDriver()


class ManagedApplication:
    def __init__(
        self,
        name: str,
        context: ExecutionContext,
        *,
        spec: AppSpec | None = None,
        profile_name: str | None = None,
        driver_factory: Callable[[], UIDriver] | None = None,
        launcher: Callable[..., Any] | None = None,
    ) -> None:
        self.name = name
        self.context = context
        self.spec = spec
        version = None
        info = context.environment.get(name) if isinstance(context.environment, dict) else None
        if isinstance(info, dict):
            version = info.get("version")
        self.profile: dict[str, Any] = load_profile(profile_name or name, version)
        self._driver_factory = driver_factory
        self._driver: UIDriver | None = None
        self._launcher = launcher
        self.process: subprocess.Popen[bytes] | None = None
        self.window: Any = None
        # Set when several instances may be open (e.g. the student's own Packet Tracer next to the one the agent
        # opened): every lookup, screenshot and close then targets this window only.
        self.selector_override: dict[str, Any] | None = None

    # ------------------------------------------------------------------ discovery
    def executable(self) -> str:
        path = self.context.app_path(self.name)
        env_var = self.profile.get("executable_env") or (self.spec.env_var if self.spec else None)
        if not path and env_var and os.environ.get(env_var):
            path = os.environ[env_var]
        if not path and self.spec is not None:
            from .environment import discover_app

            info = discover_app(self.spec, self.context.config)
            path = info.path if info.available else None
        if not path:
            raise CapabilityBlocked(
                f"{self.profile.get('display_name', self.name)} is not installed or not configured. "
                f"Set {env_var or 'applications.' + self.name} to its executable (see `lab-agent doctor`)."
            )
        if not Path(path).is_file():
            raise CapabilityBlocked(f"Configured executable does not exist: {path}")
        return path

    # ------------------------------------------------------------------ driver
    @property
    def driver(self) -> UIDriver:
        if self._driver is None:
            try:
                self._driver = (self._driver_factory or default_driver)()
            except RuntimeError as exc:
                raise CapabilityBlocked(str(exc)) from exc
        return self._driver

    @property
    def window_selector(self) -> dict[str, Any]:
        if self.selector_override:
            return dict(self.selector_override)
        selector = self.profile.get("window")
        if not selector:
            raise ValueError(f"Profile {self.name} has no window selector")
        return dict(selector)

    # ------------------------------------------------------------------ lifecycle
    def running_window(self) -> Any:
        return self.driver.find_window(self.window_selector, timeout=0)

    def launch(self, args: list[str] | None = None, *, reuse: bool = True) -> Any:
        if reuse:
            existing = self.running_window()
            if existing is not None:
                self.window = existing
                self.context.log("application.attached", {"application": self.name})
                self.dismiss_popups()
                self.check_blockers()
                return existing
        executable = self.executable()
        self.process = (self._launcher or launch_application)(executable, args or [], cwd=self.context.workspace)
        self.context.log("application.launched", {"application": self.name, "pid": getattr(self.process, "pid", None),
                                                   "args": args or []})
        return self.wait_ready()

    def wait_ready(self, timeout: float | None = None) -> Any:
        wait = float(timeout if timeout is not None else self.profile.get("window_timeout_seconds", 60))
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if self.context.cancelled():
                raise InterruptedError("Execution stopped by the user.")
            self.check_blockers()
            window = self.driver.find_window(self.window_selector, timeout=1)
            if window is not None:
                self.window = window
                settle = float(self.profile.get("ready_settle_seconds", 1))
                if settle:
                    self.context.sleep(settle)
                self.dismiss_popups()
                self.check_blockers()  # login walls often appear after the main window
                return window
            if self.process is not None and self.process.poll() is not None and not self.profile.get("launcher_exits"):
                raise RuntimeError(f"{self.name} exited during start-up with code {self.process.returncode}")
        raise TimeoutError(f"{self.name} main window {self.window_selector} did not appear within {wait:.0f}s")

    def dismiss_popups(self) -> list[str]:
        """Close known pop-ups (update notices...) declared under ``dismiss`` in the profile."""
        closed: list[str] = []
        for rule in self.profile.get("dismiss", []) or []:
            dialog = self.driver.find_window(rule["window"], timeout=0)
            if dialog is None:
                continue
            control = self.driver.find_control(dialog, rule["control"], timeout=2)
            if control is not None:
                self.driver.click(control)
                closed.append(self.driver.window_title(dialog))
                self.context.log("application.popup_dismissed", {"application": self.name, "window": closed[-1]})
        return closed

    def check_blockers(self) -> None:
        """Raise CapabilityBlocked when a declared blocking dialog (e.g. a login wall) is visible."""
        for blocker in self.profile.get("blockers", []) or []:
            if self.driver.find_window(blocker["window"], timeout=0) is not None:
                raise CapabilityBlocked(blocker.get("reason", f"{self.name} shows a dialog that requires the user"))

    def engine(self) -> ProfileEngine:
        return ProfileEngine(self.driver, self.profile,
                             launcher=lambda args: (self._launcher or launch_application)(self.executable(), args,
                                                                                          cwd=self.context.workspace),
                             sleep=self.context.sleep)

    def run_operation(self, operation: str, variables: dict[str, Any] | None = None) -> OperationResult:
        engine = self.engine()
        engine.window = self.window
        values = {"assignment": self.context.assignment, "workspace": str(self.context.workspace), **(variables or {})}
        result = engine.run(operation, values)
        self.window = engine.window
        return result

    def has_operation(self, operation: str) -> bool:
        return operation in (self.profile.get("operations") or {})

    def screenshot(self, name: str) -> Path:
        title_re = self.window_selector.get("title_re") or self.window_selector.get("title")
        return self.context.screenshot(name, window_title_re=str(title_re) if title_re else None)

    def close(self, timeout: float = 10) -> bool:
        """Close the main window; terminate the process tree *this object launched* if it refuses."""
        window = self.window or self.running_window()
        if window is not None:
            self.driver.close(window)
        self.window = None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.driver.find_window(self.window_selector, timeout=0) is None:
                return True
            time.sleep(0.5)
        if self.process is not None and self.process.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(self.process.pid), "/T", "/F"], capture_output=True, check=False)
            else:
                self.process.kill()
            self.context.log("application.terminated", {"application": self.name, "pid": self.process.pid})
            return True
        return False
