from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from lab_agent.integrations.base import CapabilityBlocked, ExecutionContext
from lab_agent.tools import console as console_tool
from lab_agent.tools.console import NAMED_KEYS, find_descendant, launcher_script, parse_keys
from lab_agent.verification import CheckContext, run_checks


# ---------------------------------------------------------------------------- key syntax and launcher
def test_parse_keys_mixes_text_and_named_keys() -> None:
    events = parse_keys("y{ENTER}{down}{{x}}")
    assert events[0] == (ord("Y"), "y")
    assert events[1] == NAMED_KEYS["ENTER"] and events[2] == NAMED_KEYS["DOWN"]
    assert [char for _, char in events[3:]] == ["{", "x", "}"]


@pytest.mark.parametrize("bad", ["{NOPE}", "a{b", "x}"])
def test_parse_keys_rejects_unknown_keys_and_stray_braces(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_keys(bad)


def test_launcher_sets_title_size_and_run_as_invoker_inside_cmd(tmp_path: Path) -> None:
    script = launcher_script([r"C:\Tools\testdisk 7\testdisk_win.exe", "/log", "img.dd"], title="TD", cols=100,
                             lines=30, cwd=tmp_path, run_as_invoker=True)
    lines = script.splitlines()
    assert "title TD" in lines and "mode con: cols=100 lines=30" in lines
    assert lines.index("set __COMPAT_LAYER=RunAsInvoker") < len(lines) - 1  # set before the program starts
    assert lines[-1] == r'"C:\Tools\testdisk 7\testdisk_win.exe" /log img.dd'


def test_find_descendant_walks_the_process_tree() -> None:
    rows = [(10, 1, "conhost.exe"), (11, 10, "cmd.exe"), (12, 11, "testdisk_win.exe"), (13, 1, "testdisk_win.exe")]
    assert find_descendant(10, "TESTDISK_WIN.EXE", rows) == 12
    assert find_descendant(11, "notepad.exe", rows) is None


# ---------------------------------------------------------------------------- adapter with a fake console
class FakeSession:
    """Stands in for ConsoleSession: a scripted text UI that reacts to keys."""

    instances: list[FakeSession] = []

    def __init__(self, pid: int = 4242, title: str = "t", program: str = "testdisk_win.exe", host_pid: int | None = 1,
                 **_: object) -> None:
        self.pid, self.title, self.program, self.host_pid = pid, title, program, host_pid
        self.text = "TestDisk 7.2, Data Recovery Utility\nSelect a media"
        self.running = True
        self.typed: list[str] = []
        FakeSession.instances.append(self)

    @classmethod
    def launch(cls, executable: str, args: list[str], **kwargs: object) -> FakeSession:
        session = cls(title=str(kwargs["title"]))
        session.launched = (executable, args, kwargs)  # type: ignore[attr-defined]
        return session

    def alive(self) -> bool:
        return self.running

    def screen(self) -> str:
        return self.text

    def send(self, keys: str) -> str:
        parse_keys(keys)
        self.typed.append(keys)
        if keys == "{ENTER}":
            self.text = "Please select the partition table type\n>[Intel  ] Intel/PC partition"
        return self.text

    def wait_until(self, predicate: object, *, timeout: float = 30.0, interval: float = 0.5) -> str:
        if re.search(str(predicate), self.text, re.MULTILINE):
            return self.text
        raise TimeoutError(f"Console text did not appear within {timeout:.0f} s. Last screen:\n{self.text}")

    def screenshot(self, path: Path) -> Path:
        from PIL import Image

        Image.new("RGB", (640, 400), "black").save(path)
        return path

    def close(self) -> None:
        self.running = False


@pytest.fixture
def console_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, config) -> ExecutionContext:  # type: ignore[no-untyped-def]
    FakeSession.instances.clear()
    monkeypatch.setattr("lab_agent.integrations.console.ConsoleSession", FakeSession)
    testdisk = tmp_path / "tools" / "testdisk_win.exe"
    testdisk.parent.mkdir()
    testdisk.write_bytes(b"MZ")
    monkeypatch.setenv("LAB_AGENT_TESTDISK_PATH", str(testdisk))
    (tmp_path / "ws" / "working").mkdir(parents=True)
    (tmp_path / "ws" / "working" / "disk.img").write_bytes(b"\0" * 1024)
    return ExecutionContext(tmp_path / "ws", "A4", step_id=3, config=config)


def _passed(result, context: ExecutionContext) -> bool:  # type: ignore[no-untyped-def]
    return result.verified and (not result.checks or run_checks(result.checks, CheckContext(context.workspace)).passed)


def test_testdisk_session_records_each_screen(console_context: ExecutionContext, registry) -> None:  # type: ignore[no-untyped-def]
    started = registry.execute("console.start", {"program": "testdisk", "args": ["/log", "disk.img"], "title": "TD",
                                                 "wait_for": "TestDisk 7"}, console_context)
    assert _passed(started, console_context)
    executable, args, options = FakeSession.instances[0].launched  # type: ignore[attr-defined]
    assert executable.endswith("testdisk_win.exe") and options["run_as_invoker"] is True
    assert args[0] == "/log" and Path(args[1]) == (console_context.workspace / "working" / "disk.img").resolve()

    keys = registry.execute("console.keys", {"keys": "{ENTER}", "wait_for": "partition table type"}, console_context)
    assert _passed(keys, console_context)
    saved = console_context.workspace / keys.evidence[0]["path"]
    assert "Intel/PC partition" in Path(saved).read_text(encoding="utf-8")

    assert _passed(registry.execute("console.read", {"expect": r"^>\[Intel"}, console_context), console_context)
    shot = registry.execute("console.screenshot", {"name": "td.png"}, console_context)
    assert _passed(shot, console_context)
    assert registry.execute("console.close", {}, console_context).verified
    assert not FakeSession.instances[0].running


def test_missing_expected_text_fails_with_the_screen_as_evidence(console_context: ExecutionContext, registry) -> None:  # type: ignore[no-untyped-def]
    registry.execute("console.start", {"program": "testdisk", "args": ["disk.img"]}, console_context)
    result = registry.execute("console.keys", {"keys": "{ESC}", "wait_for": "Analyse"}, console_context)
    assert not result.verified and "did not appear" in result.reason
    assert result.evidence and Path(console_context.workspace / result.evidence[0]["path"]).is_file()


def test_disk_tools_never_get_a_physical_disk(console_context: ExecutionContext, registry) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError, match="disk image"):
        registry.execute("console.start", {"program": "testdisk", "args": ["/log"]}, console_context)
    with pytest.raises(PermissionError):
        registry.execute("console.start", {"program": "testdisk", "args": [r"\\.\PhysicalDrive0" if os.name == "nt"
                                                                             else "/dev/sda"]}, console_context)


def test_shell_console_follows_the_arbitrary_command_policy(console_context: ExecutionContext, registry) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(CapabilityBlocked, match="arbitrary"):
        registry.execute("console.start", {"program": "pwsh"}, console_context)
    with pytest.raises(ValueError, match="Unknown console program"):
        registry.execute("console.start", {"program": "notepad", "args": ["disk.img"]}, console_context)


def test_keys_without_a_session_are_blocked(console_context: ExecutionContext, registry) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(CapabilityBlocked, match="console.start"):
        registry.execute("console.keys", {"keys": "{ENTER}"}, console_context)


def test_session_is_found_again_after_a_resume(console_context: ExecutionContext, registry, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    registry.execute("console.start", {"program": "testdisk", "args": ["disk.img"], "title": "TD"}, console_context)
    from lab_agent.integrations.registry import build_registry

    fresh = build_registry(config=console_context.config)  # a new process: no sessions in memory
    assert fresh.execute("console.read", {"session": "TD"}, console_context).verified


# ---------------------------------------------------------------------------- real TestDisk (opt-in)
REAL = os.environ.get("LAB_AGENT_REAL_APPS") == "1" and os.name == "nt"


@pytest.mark.skipif(not REAL, reason="set LAB_AGENT_REAL_APPS=1 on Windows with TestDisk installed")
def test_real_testdisk_console(tmp_path: Path, config, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    import glob

    from lab_agent.integrations.registry import build_registry

    # The autouse fixture hides install roots from discovery, so point at TestDisk explicitly.
    found = glob.glob(r"C:\Tools\testdisk*\testdisk_win.exe")
    if not os.environ.get("LAB_AGENT_TESTDISK_PATH") and not found:
        pytest.skip("TestDisk is not installed (set LAB_AGENT_TESTDISK_PATH)")
    monkeypatch.setenv("LAB_AGENT_TESTDISK_PATH", os.environ.get("LAB_AGENT_TESTDISK_PATH") or found[0])
    (tmp_path / "working").mkdir()
    (tmp_path / "working" / "blank.img").write_bytes(b"\0" * 1024 * 1024)
    context = ExecutionContext(tmp_path, "real", config=config)
    registry = build_registry(config=config)
    try:
        started = registry.execute("console.start", {"program": "testdisk", "args": ["/log", "blank.img"],
                                                     "wait_for": "TestDisk 7"}, context)
        assert started.verified, started.reason
        assert registry.execute("console.keys", {"keys": "{ENTER}", "wait_for": "(?i)partition table type"}, context).verified
        assert registry.execute("console.screenshot", {"name": "real.png"}, context).verified
    finally:
        registry.execute("console.close", {}, context)
    assert console_tool.find_descendant(started.details["pid"], "testdisk_win.exe") is None
