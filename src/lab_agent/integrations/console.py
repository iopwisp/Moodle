"""Console integration: text-mode tools (TestDisk, PhotoRec, shells) in real console windows.

The program runs in its own conhost window; keys go into its input buffer and the screen is read back
as text, so no keyboard focus is needed and the user may keep working (see :mod:`lab_agent.tools.console`).
Every keystroke step saves the resulting screen as evidence and can wait for an expected text, which is
how a step is verified: by what the program actually shows.

Safety: disk tools only get an image file inside the assignment workspace (never a physical disk), and a
shell is a way to run arbitrary commands, so shells follow ``policy.powershell.arbitrary`` like
``powershell.run_script``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..tools.console import ConsoleError, ConsoleSession, parse_keys
from .base import (
    AppSpec,
    BaseIntegration,
    Capability,
    CapabilityBlocked,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_float,
    param_int,
    param_list,
    param_str,
)

CONSOLE_APPS: dict[str, AppSpec] = {
    "testdisk": AppSpec("testdisk", "TestDisk", env_var="LAB_AGENT_TESTDISK_PATH",
                        executables=("testdisk_win.exe", "testdisk"), install_globs=("testdisk*/testdisk_win.exe",),
                        capabilities=("console.*",)),
    "photorec": AppSpec("photorec", "PhotoRec", env_var="LAB_AGENT_PHOTOREC_PATH",
                        executables=("photorec_win.exe", "photorec"), install_globs=("testdisk*/photorec_win.exe",),
                        capabilities=("console.*",)),
}
SHELLS = {"pwsh": ("pwsh.exe",), "powershell": ("powershell.exe",), "cmd": ("cmd.exe",)}
# testdisk_win.exe / photorec_win.exe request administrator rights in their manifest; image files do not need them.
RUN_AS_INVOKER = {"testdisk", "photorec"}
_TITLE_RE = re.compile(r"^[A-Za-z0-9 _.-]{1,60}$")
_FLAG_RE = re.compile(r"^[/-][A-Za-z][A-Za-z0-9_-]*$")  # /log, /debug, -h; "/dev/sda" is a path, not a flag


class ConsoleAdapter(BaseIntegration):
    name = "console"
    APPLICATIONS = tuple(CONSOLE_APPS.values())
    CAPABILITIES = (
        Capability("console.start", "console",
                   "Start a text-mode program (testdisk, photorec, or a shell when allowed) in its own console window",
                   (Param("program", "str", True, "testdisk | photorec | pwsh | powershell | cmd"),
                    Param("args", "list", False, "arguments; disk tools need an image file inside the workspace"),
                    Param("title", "str", False, "window title, also the session name (default: program)"),
                    Param("cols", "int"), Param("lines", "int"),
                    Param("cwd", "path", False, "working folder inside the workspace (default: workspace)"),
                    Param("wait_for", "str", False, "regex the first screen must show")),
                   ("command_output",), "the program is running and its first screen was read", risk="elevated",
                   keywords=("testdisk", "photorec", "console", "консоль", "partition", "раздел")),
        Capability("console.keys", "console", "Type keys into a console program and record the screen it shows",
                   (Param("keys", "str", True, "text with {ENTER} {UP} {DOWN} {ESC} {TAB} {F1}.. named keys"),
                    Param("session", "str"), Param("wait_for", "str", False, "regex expected on screen afterwards"),
                    Param("timeout", "float")),
                   ("command_output",), "the screen after the keys was saved and shows wait_for when given"),
        Capability("console.read", "console", "Save the current console screen as text",
                   (Param("session", "str"), Param("expect", "str", False, "regex that must be on screen")),
                   ("command_output",), "screen saved and matches expect when given"),
        Capability("console.screenshot", "console", "Screenshot of the console window (its own pixels, even if covered)",
                   (Param("session", "str"), Param("name", "str")), ("screenshot",), "valid window screenshot"),
        Capability("console.close", "console", "Close the console program and its window",
                   (Param("session", "str"),), (), "the program is no longer running"),
    )

    def __init__(self) -> None:
        self._sessions: dict[str, ConsoleSession] = {}

    # ------------------------------------------------------------------ sessions
    def _state_path(self, context: ExecutionContext) -> Path:
        return context.folder("working") / "console_sessions.json"

    def _save_sessions(self, context: ExecutionContext) -> None:
        state = {name: {"pid": s.pid, "title": s.title, "program": s.program, "host_pid": s.host_pid}
                 for name, s in self._sessions.items()}
        self._state_path(context).write_text(json.dumps(state, indent=2), encoding="utf-8")

    def _session(self, parameters: dict[str, Any], context: ExecutionContext) -> tuple[str, ConsoleSession]:
        name = param_str(parameters, "session")
        if not name and len(self._sessions) == 1:
            name = next(iter(self._sessions))
        if name not in self._sessions and self._state_path(context).is_file():  # reattach after a resume
            saved = json.loads(self._state_path(context).read_text(encoding="utf-8"))
            if not name and len(saved) == 1:
                name = next(iter(saved))
            if name in saved:
                self._sessions[name] = ConsoleSession(**saved[name])
        session = self._sessions.get(name)
        if session is None:
            raise CapabilityBlocked(f"No console session {name or '(default)'} is open; run console.start first.")
        if not session.alive():
            self._sessions.pop(name, None)
            self._save_sessions(context)
            raise CapabilityBlocked(f"The console program {session.program} has exited; start it again with console.start.")
        return name, session

    def _record(self, context: ExecutionContext, name: str, screen: str, label: str) -> Path:
        stamp = f"{context.step_id or 0:02d}_{context.stamp()}"
        return context.save_result(f"console_{re.sub(r'[^A-Za-z0-9]+', '_', name)}_{label}_{stamp}.txt", screen + "\n")

    def _program(self, program: str, args: list[str], context: ExecutionContext) -> tuple[str, list[str]]:
        if program in SHELLS:
            policy = getattr(getattr(context.config, "policy", None), "powershell", None)
            if not getattr(policy, "arbitrary", False):
                raise CapabilityBlocked(
                    f"A {program} console runs arbitrary commands, which is disabled (policy.powershell.arbitrary=false). "
                    "Enable it explicitly in config.yaml to drive a shell window.")
            from ..environment import discover_app

            executable = discover_app(AppSpec(program, program, executables=SHELLS[program]), context.config).path
            if not executable:
                raise CapabilityBlocked(f"{SHELLS[program][0]} is not installed.")
            return executable, args
        spec = CONSOLE_APPS.get(program)
        if spec is None:
            raise ValueError(f"Unknown console program {program!r}; known: {', '.join([*CONSOLE_APPS, *SHELLS])}")
        executable = context.app_path(program)
        if not executable:
            from ..environment import discover_app

            executable = discover_app(spec, context.config).path
        if not executable:
            raise CapabilityBlocked(f"{spec.display_name} was not found; set {spec.env_var} or applications.{program} "
                                    "in config.yaml (TestDisk/PhotoRec: https://www.cgsecurity.org).")
        images = [a for a in args if not _FLAG_RE.fullmatch(a)]
        if not images:
            raise ValueError(f"{spec.display_name} must be given a disk image file from the workspace, never a physical disk.")
        resolved = [str(context.resolve(a, base="working")) if a in images else a for a in args]
        return executable, resolved

    # ------------------------------------------------------------------ capabilities
    def start(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        program = param_str(parameters, "program").lower()
        title = param_str(parameters, "title") or program
        if not _TITLE_RE.fullmatch(title):
            raise ValueError("title may contain letters, digits, spaces, '.', '_' and '-' only (max 60)")
        executable, args = self._program(program, [str(a) for a in param_list(parameters, "args")], context)
        cwd = context.resolve(param_str(parameters, "cwd") or ".", must_exist=False)
        old = self._sessions.pop(title, None)
        if old is not None:
            old.close()
        try:
            session = ConsoleSession.launch(executable, args, cwd=cwd, title=title, cols=param_int(parameters, "cols", 120),
                                            lines=param_int(parameters, "lines", 32), run_as_invoker=program in RUN_AS_INVOKER)
        except ConsoleError as exc:
            return IntegrationResult.failed(str(exc), program=program)
        self._sessions[title] = session
        self._save_sessions(context)
        expected = param_str(parameters, "wait_for")
        try:
            screen = session.wait_until(expected, timeout=30) if expected else session.screen()
        except TimeoutError as exc:
            return IntegrationResult.failed(str(exc), program=program, pid=session.pid)
        output = self._record(context, title, screen, "start")
        return IntegrationResult(True, {"program": program, "pid": session.pid, "session": title, "screen": screen[-2000:]},
                                 [evidence(output, f"{program} first screen", "command_output")],
                                 checks=self._checks(output, context, expected))

    def keys(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        name, session = self._session(parameters, context)
        text = param_str(parameters, "keys") if parameters.get("keys") is not None else ""
        parse_keys(text)
        expected = param_str(parameters, "wait_for")
        screen = session.send(text)
        if expected:
            try:
                screen = session.wait_until(expected, timeout=param_float(parameters, "timeout", 30))
            except TimeoutError as exc:
                output = self._record(context, name, session.screen(), "keys")
                return IntegrationResult(False, {"reason": str(exc).splitlines()[0], "keys": text},
                                         [evidence(output, f"Screen after {text!r}", "command_output")])
        output = self._record(context, name, screen, "keys")
        return IntegrationResult(True, {"keys": text, "session": name, "screen": screen[-2000:]},
                                 [evidence(output, f"Screen after {text!r}", "command_output")],
                                 checks=self._checks(output, context, expected))

    def read(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        name, session = self._session(parameters, context)
        screen = session.screen()
        expected = param_str(parameters, "expect")
        output = self._record(context, name, screen, "read")
        ok = not expected or re.search(expected, screen, re.MULTILINE) is not None
        return IntegrationResult(ok, {"session": name, "screen": screen[-2000:],
                                      **({} if ok else {"reason": f"{expected!r} is not on the screen"})},
                                 [evidence(output, "Console screen", "command_output")],
                                 checks=self._checks(output, context, expected))

    def screenshot(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        name, session = self._session(parameters, context)
        filename = param_str(parameters, "name") or f"console_{re.sub(r'[^A-Za-z0-9]+', '_', name)}_{context.stamp()}.png"
        if Path(filename).name != filename or not filename.lower().endswith(".png"):
            raise ValueError("name must be a plain .png file name")
        picture = context.folder("screenshots") / filename
        try:
            session.screenshot(picture)
        except ConsoleError as exc:
            return IntegrationResult.failed(str(exc))
        return IntegrationResult(True, {"session": name}, [evidence(picture, f"{session.program} window", "screenshot")],
                                 checks=[{"type": "image_valid", "path": f"screenshots/{filename}"}])

    def close(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        try:
            name, session = self._session(parameters, context)
        except CapabilityBlocked:
            return IntegrationResult(True, {"already_closed": True})
        session.close()
        self._sessions.pop(name, None)
        self._save_sessions(context)
        for _ in range(20):
            if not session.alive():
                return IntegrationResult(True, {"session": name})
            context.sleep(0.25)
        return IntegrationResult.failed(f"{session.program} (pid {session.pid}) is still running", session=name)

    @staticmethod
    def _checks(output: Path, context: ExecutionContext, expected: str) -> list[dict[str, Any]]:
        relative = output.relative_to(context.workspace).as_posix()
        checks: list[dict[str, Any]] = [{"type": "file_exists", "path": relative}]
        if expected:
            checks.append({"type": "text_contains", "path": relative, "regex": expected})
        return checks

    def shutdown(self) -> None:
        # Sessions stay open on purpose: the student may want to look at the final screen. console.close ends them.
        self._sessions.clear()


def create_adapters(services: Any) -> list[ConsoleAdapter]:
    return [ConsoleAdapter()]

