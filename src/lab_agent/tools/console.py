"""Drive console (text-mode) programs in real conhost windows without taking keyboard focus.

Keys are written straight into the console input buffer (``WriteConsoleInputW``), the screen is
read back with ``ReadConsoleOutputCharacterW`` and screenshots come from the window itself
(``PrintWindow``), so the user may keep working while TestDisk, PhotoRec or PowerShell is driven.

A process can be attached to only one console at a time, and the agent must keep its own, so every
console operation runs in a short-lived helper process::

    python -m lab_agent.tools.console <pid> screen
    python -m lab_agent.tools.console <pid> keys <token>...
    python -m lab_agent.tools.console <pid> shot <file.png>

Key syntax (see :func:`parse_keys`): plain text is typed as is, ``{ENTER}``, ``{UP}``, ``{F2}`` ...
press a named key, ``{{`` and ``}}`` type literal braces.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

NAMED_KEYS: dict[str, tuple[int, str]] = {
    "ENTER": (0x0D, "\r"), "ESC": (0x1B, "\x1b"), "TAB": (0x09, "\t"), "BACKSPACE": (0x08, "\b"),
    "SPACE": (0x20, " "), "UP": (0x26, "\0"), "DOWN": (0x28, "\0"), "LEFT": (0x25, "\0"), "RIGHT": (0x27, "\0"),
    "PGUP": (0x21, "\0"), "PGDN": (0x22, "\0"), "HOME": (0x24, "\0"), "END": (0x23, "\0"), "DELETE": (0x2E, "\0"),
    **{f"F{n}": (0x6F + n, "\0") for n in range(1, 13)},
}
_TOKEN_RE = re.compile(r"\{\{|\}\}|\{([A-Za-z0-9]+)\}|[^{}]+|[{}]")


class ConsoleError(RuntimeError):
    """The console could not be launched, attached or read."""


def parse_keys(text: str) -> list[tuple[int, str]]:
    """Turn ``"y{ENTER}"`` into ``[(VK, char), ...]`` events; unknown ``{NAME}`` raises ``ValueError``."""
    events: list[tuple[int, str]] = []
    for match in _TOKEN_RE.finditer(text):
        token, name = match.group(0), match.group(1)
        if token in ("{{", "}}"):
            events.append((0, token[0]))
        elif name is not None:
            key = NAMED_KEYS.get(name.upper())
            if key is None:
                raise ValueError(f"Unknown key {{{name}}}; known: {', '.join(NAMED_KEYS)}")
            events.append(key)
        elif token in ("{", "}"):
            raise ValueError(f"Unbalanced brace in key text {text!r}; type a literal brace as {{{{ or }}}}")
        else:
            events.extend((ord(c.upper()) if c.isascii() and c.isalnum() else 0, c) for c in token)
    return events


def launcher_script(command: list[str], *, title: str, cols: int, lines: int, cwd: Path,
                    run_as_invoker: bool = False) -> str:
    """The ``.cmd`` file conhost runs: window title and size first, then the program itself."""
    def quote(part: str) -> str:
        return f'"{part}"' if (" " in part or not part) and not part.startswith('"') else part

    body = ["@echo off", "chcp 65001 >nul", f"title {title}", f"mode con: cols={cols} lines={lines}", f'cd /d "{cwd}"']
    if run_as_invoker:
        # Some tools (testdisk_win.exe) ask for administrator rights in their manifest although image files do not
        # need them. The variable must be set inside the launched cmd: it is not inherited from conhost.exe.
        body.append("set __COMPAT_LAYER=RunAsInvoker")
    body.append(" ".join(quote(part) for part in command))
    return "\r\n".join(body) + "\r\n"


def process_tree() -> list[tuple[int, int, str]]:
    """``(pid, parent_pid, exe_name)`` for every process (Windows Toolhelp snapshot)."""
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snapshot = k32.CreateToolhelp32Snapshot(0x2, 0)
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    rows: list[tuple[int, int, str]] = []
    try:
        ok = k32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            rows.append((entry.th32ProcessID, entry.th32ParentProcessID, entry.szExeFile))
            ok = k32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snapshot)
    return rows


def find_descendant(root_pid: int, exe_name: str, rows: list[tuple[int, int, str]] | None = None) -> int | None:
    """Newest-first search for a process named ``exe_name`` started (indirectly) by ``root_pid``."""
    rows = process_tree() if rows is None else rows
    children: dict[int, list[tuple[int, str]]] = {}
    for pid, parent, exe in rows:
        if pid != parent:
            children.setdefault(parent, []).append((pid, exe))
    stack, seen = [root_pid], {root_pid}
    target = exe_name.casefold()
    while stack:
        for pid, exe in children.get(stack.pop(), []):
            if pid in seen:
                continue
            if exe.casefold() == target:
                return pid
            seen.add(pid)
            stack.append(pid)
    return None


@dataclass
class ConsoleSession:
    """A program running in its own conhost window, addressed by the program's process id."""

    pid: int
    title: str
    program: str
    host_pid: int | None = None
    helper_timeout: float = 30.0
    extra: dict[str, str] = field(default_factory=dict)

    # -- launching ------------------------------------------------------------
    @classmethod
    def launch(cls, executable: str, args: list[str], *, cwd: Path, title: str, cols: int = 120, lines: int = 32,
               run_as_invoker: bool = False, start_timeout: float = 20.0) -> ConsoleSession:
        if os.name != "nt":
            raise ConsoleError("Console automation needs Windows (conhost).")
        cwd.mkdir(parents=True, exist_ok=True)
        launcher = cwd / f"_console_{re.sub(r'[^A-Za-z0-9]+', '_', title)[:40]}.cmd"
        launcher.write_text(launcher_script([executable, *args], title=title, cols=cols, lines=lines, cwd=cwd,
                                            run_as_invoker=run_as_invoker), encoding="utf-8")
        # conhost.exe explicitly: with Windows Terminal as the default terminal a plain new console would open
        # as a terminal tab, whose window cannot be read with PrintWindow or addressed by its console.
        host = subprocess.Popen(["conhost.exe", "cmd.exe", "/c", str(launcher)], cwd=cwd,
                                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
        exe_name = Path(executable).name
        if not exe_name.lower().endswith(".exe"):
            exe_name += ".exe"
        deadline = time.monotonic() + start_timeout
        while time.monotonic() < deadline:
            pid = find_descendant(host.pid, exe_name)
            if pid:
                session = cls(pid=pid, title=title, program=exe_name, host_pid=host.pid)
                session.wait_until(lambda screen: bool(screen.strip()), timeout=max(1.0, deadline - time.monotonic()))
                return session
            if host.poll() is not None:
                raise ConsoleError(f"{exe_name} exited immediately (console host exit code {host.returncode}).")
            time.sleep(0.25)
        raise ConsoleError(f"{exe_name} did not start within {start_timeout:.0f} s.")

    # -- helper calls -----------------------------------------------------------
    def _helper(self, *args: str) -> dict[str, object]:
        completed = subprocess.run([sys.executable, "-m", "lab_agent.tools.console", str(self.pid), *args],
                                   capture_output=True, text=True, encoding="utf-8", timeout=self.helper_timeout,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)
        try:
            answer: dict[str, object] = json.loads(completed.stdout.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError) as exc:
            raise ConsoleError(f"console helper failed: {completed.stderr.strip()[-400:] or completed.stdout[-400:]}") from exc
        if not answer.get("ok"):
            raise ConsoleError(str(answer.get("error", "console helper failed")))
        return answer

    def alive(self) -> bool:
        return any(pid == self.pid for pid, _, _ in process_tree())

    def screen(self) -> str:
        return str(self._helper("screen")["screen"])

    def send(self, keys: str) -> str:
        parse_keys(keys)  # reject bad syntax before anything is typed
        return str(self._helper("keys", keys)["screen"])

    def screenshot(self, path: Path) -> Path:
        self._helper("shot", str(path))
        return path

    def wait_until(self, predicate: object, *, timeout: float = 30.0, interval: float = 0.5) -> str:
        """Poll the screen until ``predicate(screen)`` (callable) or regex ``predicate`` matches."""
        check = predicate if callable(predicate) else (lambda text: re.search(str(predicate), text, re.MULTILINE) is not None)
        deadline = time.monotonic() + timeout
        last = ""
        while True:
            try:
                last = self.screen()
            except ConsoleError:
                if not self.alive():
                    raise
            if check(last):
                return last
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Console text did not appear within {timeout:.0f} s. Last screen:\n{last}")
            time.sleep(interval)

    def close(self) -> None:
        for pid in (self.pid, self.host_pid):
            if pid:
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False)


# ---------------------------------------------------------------------------- helper process (attached to the console)
def _attach(pid: int):  # type: ignore[no-untyped-def]
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.FreeConsole()
    if not k32.AttachConsole(pid):
        raise ConsoleError(f"AttachConsole({pid}) failed with Windows error {ctypes.get_last_error()}")
    k32.CreateFileW.restype = wintypes.HANDLE
    read_write, share, open_existing = 0xC0000000, 3, 3
    conin = k32.CreateFileW("CONIN$", read_write, share, None, open_existing, 0, None)
    conout = k32.CreateFileW("CONOUT$", read_write, share, None, open_existing, 0, None)
    return k32, conin, conout


def _read_screen(k32, conout) -> str:  # type: ignore[no-untyped-def]
    import ctypes
    from ctypes import wintypes

    class CSBI(ctypes.Structure):
        _fields_ = [("dwSize", wintypes._COORD), ("dwCursorPosition", wintypes._COORD), ("wAttributes", wintypes.WORD),
                    ("srWindow", wintypes.SMALL_RECT), ("dwMaximumWindowSize", wintypes._COORD)]

    info = CSBI()
    if not k32.GetConsoleScreenBufferInfo(conout, ctypes.byref(info)):
        raise ConsoleError("GetConsoleScreenBufferInfo failed")
    window = info.srWindow
    width = window.Right - window.Left + 1
    rows = []
    for y in range(window.Top, window.Bottom + 1):
        buffer = ctypes.create_unicode_buffer(width)
        read = wintypes.DWORD()
        k32.ReadConsoleOutputCharacterW(conout, buffer, width, wintypes._COORD(window.Left, y), ctypes.byref(read))
        rows.append(buffer.value.rstrip())
    return "\n".join(rows).rstrip()


def _write_keys(k32, conin, events: list[tuple[int, str]]) -> None:  # type: ignore[no-untyped-def]
    import ctypes
    from ctypes import wintypes

    class KEY_EVENT_RECORD(ctypes.Structure):
        _fields_ = [("bKeyDown", wintypes.BOOL), ("wRepeatCount", wintypes.WORD), ("wVirtualKeyCode", wintypes.WORD),
                    ("wVirtualScanCode", wintypes.WORD), ("uChar", wintypes.WCHAR), ("dwControlKeyState", wintypes.DWORD)]

    class INPUT_RECORD(ctypes.Structure):
        class _U(ctypes.Union):
            _fields_ = [("KeyEvent", KEY_EVENT_RECORD), ("_pad", ctypes.c_byte * 16)]
        _fields_ = [("EventType", wintypes.WORD), ("Event", _U)]

    for vk, char in events:
        records = (INPUT_RECORD * 2)()
        for index, down in enumerate((True, False)):
            records[index].EventType = 1  # KEY_EVENT
            key = records[index].Event.KeyEvent
            key.bKeyDown, key.wRepeatCount, key.wVirtualKeyCode, key.uChar = down, 1, vk, char
        written = wintypes.DWORD()
        if not k32.WriteConsoleInputW(conin, records, 2, ctypes.byref(written)):
            raise ConsoleError("WriteConsoleInputW failed")
        # Text-mode UIs redraw after navigation keys; typed characters can go faster.
        time.sleep(0.02 if char.isprintable() and vk not in {v for v, _ in NAMED_KEYS.values() if v != 0x20} else 0.35)


def _helper_main(argv: list[str]) -> dict[str, object]:
    pid, command, args = int(argv[0]), argv[1], argv[2:]
    k32, conin, conout = _attach(pid)
    if command == "screen":
        return {"ok": True, "screen": _read_screen(k32, conout)}
    if command == "keys":
        _write_keys(k32, conin, parse_keys(args[0]))
        time.sleep(0.8)
        return {"ok": True, "screen": _read_screen(k32, conout)}
    if command == "shot":
        from .screenshot import capture_window

        image = capture_window(k32.GetConsoleWindow())
        if image is None:
            raise ConsoleError("PrintWindow could not capture the console window")
        image.save(args[0])
        return {"ok": True, "path": args[0], "size": list(image.size)}
    raise ConsoleError(f"unknown console command {command!r}")


if __name__ == "__main__":
    try:
        result = _helper_main(sys.argv[1:])
    except Exception as exc:  # noqa: BLE001 - reported to the parent as JSON
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
