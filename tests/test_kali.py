from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from PIL import Image, ImageDraw

from lab_agent.config import AgentConfig, KaliConfig, load_config
from lab_agent.integrations import kali
from lab_agent.integrations.base import CapabilityBlocked, ExecutionContext
from lab_agent.integrations.registry import build_registry
from lab_agent.policy import PolicyEngine
from lab_agent.tools.kali_guest import SSH_BOOTSTRAP, SSH_OBSERVE, TERMINAL_WORKER
from lab_agent.tools.process import CommandResult
from lab_agent.verification import CheckContext, run_checks


@pytest.fixture
def context(tmp_path):
    return ExecutionContext(tmp_path, "Kali lab", step_id=7, config=AgentConfig())


@pytest.fixture
def adapter(monkeypatch):
    item = kali.KaliAdapter()
    monkeypatch.setattr(item, "_info", lambda p, c: {
        "name": "Kali lab", "VMState": "running", "macaddress1": "080027123456"})
    monkeypatch.setattr(item, "_app", lambda c, spec: spec.name)
    return item


def fake_capture(context, vm, name):
    path = context.folder("screenshots") / name
    Image.new("RGB", (640, 480), (50, 80, 130)).save(path)
    return path


def test_discovery_and_policy():
    registry = build_registry()
    assert registry.has("kali.run") and registry.has("kali.screenshot")
    cap = registry.capability("kali.run")
    assert not cap.interactive and cap.risk == "unsafe" and cap.network
    policy = PolicyEngine(AgentConfig())
    assert policy.check(cap, {"host": "127.0.0.1"}).confirmation_required
    assert not policy.check(cap, {"host": "example.org"}).allowed


def test_unauthorized_host_is_rejected_before_execution(adapter, context, monkeypatch):
    monkeypatch.setattr(kali, "run_command", lambda *a, **k: pytest.fail("SSH must not run"))
    with pytest.raises(PermissionError):
        adapter.run({"vm": "Kali lab", "host": "example.org", "user": "kali", "command": "id"}, context)


@pytest.mark.parametrize("extra", [
    {"host": "-oProxyCommand=evil"}, {"user": "kali;evil"}, {"port": 0},
    {"timeout": 0}, {"cwd": "relative"}, {"command": ""},
    {"command": "", "script": "../../outside.sh"},
])
def test_invalid_parameters_cannot_reach_ssh(adapter, context, monkeypatch, extra):
    monkeypatch.setattr(kali, "run_command", lambda *a, **k: pytest.fail("SSH must not run"))
    with pytest.raises((ValueError, PermissionError)):
        adapter.run({"vm": "Kali lab", "host": "127.0.0.1", "user": "kali", "command": "id", **extra}, context)


def test_command_result_expectation_and_no_reexecution(adapter, context, monkeypatch):
    calls = []

    def ssh(argv, **kwargs):
        calls.append(argv)
        payload = json.loads(kwargs["input_text"])
        assert payload["command"] == "printf 'a;$(id)'"  # unchanged literal, no local shell
        assert "BatchMode=yes" in argv and "StrictHostKeyChecking=yes" in argv
        assert "-T" in argv and argv[-2] == "127.0.0.1"
        return CommandResult(argv, 0, json.dumps({"exit_code": 0, "stdout": "a;$(id)", "timed_out": False, "terminal_visible": True}), "", 0.01)

    monkeypatch.setattr(kali, "run_command", ssh)
    monkeypatch.setattr(adapter, "_capture", fake_capture)
    p = {"vm": "Kali lab", "host": "127.0.0.1", "user": "kali", "command": "printf 'a;$(id)'", "expect": "a;$(id)"}
    first = adapter.run(p, context)
    assert first.verified
    assert run_checks(first.checks, CheckContext(context.workspace)).passed
    monkeypatch.setattr(adapter, "_capture", lambda *a: pytest.fail("Reuse the original screenshot; another command may now be on screen"))
    second = adapter.run(p, context)
    assert second.verified and len(calls) == 1
    mismatch = adapter.run({**p, "expect": "not present"}, context)
    assert not mismatch.verified and len(calls) == 1
    assert not run_checks(mismatch.checks, CheckContext(context.workspace)).passed


def test_saved_connection_defaults_are_subject_to_network_policy(adapter, context, monkeypatch):
    context.config.kali = KaliConfig(vm="Kali lab", host="unauthorized.example", port=2222)
    monkeypatch.setattr(kali, "run_command", lambda *a, **k: pytest.fail("SSH must not run"))
    with pytest.raises(PermissionError):
        adapter.run({"command": "id"}, context)


def test_connection_configuration_and_environment(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("kali:\n  vm: Test Kali\n  host: 127.0.0.1\n  port: 2222\n  user: student\n", encoding="utf-8")
    monkeypatch.setenv("LAB_AGENT_KALI_SSH_KEY", str(tmp_path / "key"))
    configuration = load_config(path)
    assert configuration.kali.vm == "Test Kali" and configuration.kali.port == 2222
    assert configuration.kali.user == "student" and configuration.kali.identity_file == str(tmp_path / "key")


@pytest.mark.parametrize("exit_code,timed_out", [(1, False), (-9, True)])
def test_guest_failure_never_completes(adapter, context, monkeypatch, exit_code, timed_out):
    monkeypatch.setattr(adapter, "_capture", fake_capture)
    monkeypatch.setattr(kali, "run_command", lambda argv, **k: CommandResult(
        argv, 0, json.dumps({"exit_code": exit_code, "stdout": "actual failure", "timed_out": timed_out, "terminal_visible": True}), "", 0.01))
    result = adapter.run({"vm": "Kali lab", "host": "127.0.0.1", "user": "kali", "command": "false"}, context)
    assert not result.verified
    assert any(e["type"] == "screenshot" for e in result.evidence)
    assert not run_checks(result.checks, CheckContext(context.workspace)).passed


def test_lost_ssh_result_is_not_retried(adapter, context, monkeypatch):
    calls = []
    monkeypatch.setattr(adapter, "_capture", fake_capture)

    def fail(argv, **kwargs):
        calls.append(argv)
        return CommandResult(argv, 255, "", "Connection lost", 0.01)

    monkeypatch.setattr(kali, "run_command", fail)
    p = {"vm": "Kali lab", "host": "127.0.0.1", "user": "kali", "command": "id"}
    assert adapter.run(p, context).blocked
    with pytest.raises(CapabilityBlocked, match="uncertain"):
        adapter.run(p, context)
    assert len(calls) == 1


def test_hidden_guest_terminal_does_not_complete(adapter, context, monkeypatch):
    monkeypatch.setattr(adapter, "_capture", fake_capture)
    monkeypatch.setattr(kali, "run_command", lambda argv, **k: CommandResult(
        argv, 0, json.dumps({"exit_code": 0, "stdout": "uid=1000", "timed_out": False,
                             "terminal_visible": False}), "", 0))
    result = adapter.run({"vm": "Kali lab", "host": "127.0.0.1", "user": "kali", "command": "id"}, context)
    assert not result.verified
    assert not run_checks(result.checks, CheckContext(context.workspace)).passed


def test_screenshot_failure_preserves_guest_result(adapter, context, monkeypatch):
    captures, calls = [], []

    def capture(ctx, vm, name):
        captures.append(name)
        if len(captures) == 2:
            raise CapabilityBlocked("No guest pixels")
        return fake_capture(ctx, vm, name)

    def ssh(argv, **kwargs):
        payload = json.loads(kwargs["input_text"])
        if "command" not in payload:
            return CommandResult(argv, 0, json.dumps({"terminal_visible": True}), "", 0)
        calls.append(argv)
        return CommandResult(argv, 0, json.dumps({"exit_code": 0, "stdout": "uid=1000", "timed_out": False,
                                                "terminal_visible": True, "title": "DoneAsik test"}), "", 0)

    monkeypatch.setattr(adapter, "_capture", capture)
    monkeypatch.setattr(kali, "run_command", ssh)
    p = {"vm": "Kali lab", "host": "127.0.0.1", "user": "kali", "command": "id"}
    result = adapter.run(p, context)
    assert result.blocked and not result.verified and result.evidence
    assert adapter.run(p, context).verified and len(calls) == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows PrintWindow")
def test_capture_never_uses_desktop_or_activates_window(context, monkeypatch):
    class Window:
        handle = 42

        def is_minimized(self):
            return False

    seen = []
    image = Image.new("RGB", (640, 480), "white")
    ImageDraw.Draw(image).rectangle((200, 200, 300, 300), fill="black")
    monkeypatch.setattr(kali.shots, "find_window", lambda pattern, **k: seen.append(pattern) or Window())
    monkeypatch.setattr(kali.shots, "capture_window", lambda handle: image)
    monkeypatch.setattr(kali.shots, "_grab", lambda *a: pytest.fail("No desktop grabs"))
    path = kali.KaliAdapter._capture(context, "Kali (lab)", "host.png")
    assert path.is_file()
    import re
    assert re.search(seen[0], "Kali (lab) [Running] - Oracle VirtualBox")
    assert not re.search(seen[0], "Oracle VirtualBox Manager")
    monkeypatch.setattr(kali.shots, "capture_window", lambda handle: None)
    with pytest.raises(CapabilityBlocked):
        kali.KaliAdapter._capture(context, "Kali (lab)", "missing.png")
    assert not (context.workspace / "screenshots/missing.png").exists()


@pytest.mark.skipif(os.name == "nt", reason="Guest Linux process groups/bash")
def test_real_guest_worker_collects_command_exit_and_timeout(tmp_path):
    for command, timeout, expected in [("printf observed; exit 3", 3, 3), ("sleep 10", 1, -9)]:
        job = {"command": command, "cwd": str(tmp_path), "timeout": timeout, "directory": str(tmp_path)}
        completed = subprocess.run([sys.executable, "-c", TERMINAL_WORKER, json.dumps(job)], capture_output=True, timeout=8, check=False)
        assert completed.returncode == 0
        data = json.loads((tmp_path / "result.json").read_text())
        assert data["exit_code"] == expected
        assert data["timed_out"] == (expected == -9)
        if expected == 3:
            assert data["stdout"] == "observed" and b"observed" in completed.stdout


def test_guest_helpers_are_valid_python():
    compile(TERMINAL_WORKER, "guest_worker", "exec")
    compile(SSH_BOOTSTRAP, "guest_bootstrap", "exec")
    compile(SSH_OBSERVE, "guest_observe", "exec")


@pytest.mark.skipif(os.name == "nt", reason="Guest Linux X11 CLI stand-ins")
def test_bootstrap_runs_worker_and_rejects_wrong_vm(tmp_path):
    # Real Linux subprocesses, with only the X server / terminal replaced.
    terminal = tmp_path / "xterm"
    terminal.write_text(
        "#!/usr/bin/env python3\nimport os,sys\n"
        "from pathlib import Path\n"
        "Path(os.environ['TEST_TITLE']).write_text(sys.argv[sys.argv.index('-T')+1])\n"
        "argv=sys.argv[sys.argv.index('-e')+1:]\nos.execvp(argv[0],argv)\n")
    xprop = tmp_path / "xprop"
    xprop.write_text(
        "#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\n"
        "assert '-id' not in sys.argv or sys.argv[sys.argv.index('-id')+1] == '0x123'\n"
        "print('window id # 0x123, 0x0' if '-root' in sys.argv else Path(os.environ['TEST_TITLE']).read_text())\n")
    terminal.chmod(0o755)
    xprop.chmod(0o755)
    environment = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
                       TEST_TITLE=str(tmp_path / "title"))
    macs = [p.read_text().strip().replace(":", "").lower()
            for p in Path("/sys/class/net").glob("*/address")]
    job = {"command": "printf bootstrap-observed", "cwd": str(tmp_path), "timeout": 3,
           "worker": TERMINAL_WORKER, "title": "DoneAsik test", "display": ":0", "vm_macs": macs}
    result = subprocess.run([sys.executable, "-c", SSH_BOOTSTRAP], input=json.dumps(job).encode(),
                            capture_output=True, env=environment, timeout=10, check=False)
    assert result.returncode == 0, result.stderr.decode()
    observed = json.loads(result.stdout)
    assert observed["stdout"] == "bootstrap-observed" and observed["exit_code"] == 0
    assert observed["terminal_visible"] is True
    rejected = subprocess.run([sys.executable, "-c", SSH_BOOTSTRAP],
                              input=json.dumps({**job, "vm_macs": ["ffffffffffff"]}).encode(),
                              capture_output=True, env=environment, timeout=10, check=False)
    assert rejected.returncode != 0 and b"do not match" in rejected.stderr
