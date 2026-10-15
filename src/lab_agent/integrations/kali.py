"""Kali in VirtualBox: SSH commands and strict Windows window screenshots."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import uuid
from pathlib import Path
from typing import Any

from ..config import AgentConfig
from ..policy import PolicyEngine
from ..tools import screenshot as shots
from ..tools.kali_guest import SSH_BOOTSTRAP, SSH_OBSERVE, TERMINAL_WORKER
from ..tools.process import CommandResult, run_command
from .base import (
    AppSpec,
    BaseIntegration,
    Capability,
    CapabilityBlocked,
    ExecutionContext,
    IntegrationResult,
    Narrative,
    Param,
    StepFacts,
    evidence,
    param_int,
    param_str,
)

VM = Param("vm", "str", description="exact registered VirtualBox VM name or UUID; defaults to config.kali.vm")
VBOX = AppSpec(
    "virtualbox", "VirtualBox (VBoxManage)", env_var="LAB_AGENT_VIRTUALBOX_PATH",
    executables=("VBoxManage.exe", "VBoxManage"),
    install_globs=("Oracle/VirtualBox/VBoxManage.exe",),
    version_args=("--version",), capabilities=("kali.*",),
)
SSH = AppSpec(
    "ssh", "OpenSSH client", env_var="LAB_AGENT_SSH_PATH",
    executables=("ssh.exe", "ssh"), capabilities=("kali.run",),
)


class KaliAdapter(BaseIntegration):
    name = "kali"
    APPLICATIONS = (VBOX, SSH)
    CAPABILITIES = (
        Capability("kali.list_vms", "kali", "List registered VirtualBox virtual machines",
                   evidence_types=("command_output",)),
        Capability("kali.status", "kali", "Read the actual state of a VirtualBox VM",
                   (VM,), ("command_output",)),
        Capability("kali.start", "kali", "Start or resume a VirtualBox VM with its Windows GUI",
                   (VM,), ("command_output",), "observed VMState is running", risk="elevated"),
        Capability("kali.screenshot", "kali",
                   "Capture the VirtualBox window in Windows using PrintWindow; includes host window frame",
                   (VM,), ("screenshot",), "valid real host window image; no desktop fallback"),
        Capability("kali.run", "kali",
                   "Run an authorized lab command over SSH in the guest X11 terminal and capture its Windows VirtualBox window",
                   (VM, Param("host", "str", description="authorized SSH host; defaults to config.kali.host"),
                    Param("user", "str", description="logged-in Kali user; defaults to config.kali.user"),
                    Param("port", "int", default=22),
                    Param("command", "str", description="bash command; alternatively provide script"),
                    Param("script", "path", description="UTF-8 bash script inside the workspace"),
                    Param("identity_file", "str", description="SSH private key path on Windows; never copied"),
                    Param("display", "str", default=":0"),
                    Param("xauthority", "str", description="guest Xauthority path if nonstandard"),
                    Param("cwd", "str", description="absolute guest working directory"),
                    Param("timeout", "int", default=120),
                    Param("expect", "str", description="required literal substring of observed output"),
                    Param("execution_id", "str", description="reuse to recover evidence without repeating a command")),
                   ("command_output", "screenshot"),
                   "guest exit code zero, expected output if supplied, actual Windows window screenshot",
                   risk="unsafe", network=True, requires=("app:virtualbox", "app:ssh"),
                   keywords=("kali", "linux", "virtualbox", "ssh", "виртуалка", "кали")),
    )

    @staticmethod
    def _app(context: ExecutionContext, spec: AppSpec) -> str:
        path = context.app_path(spec.name) or os.environ.get(spec.env_var or "")
        if not path:
            path = next((p for exe in spec.executables if (p := shutil.which(exe))), None)
        if not path and spec.name == "virtualbox":
            candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Oracle/VirtualBox/VBoxManage.exe"
            path = str(candidate) if candidate.is_file() else None
        if not path:
            raise CapabilityBlocked(f"{spec.display_name} is not installed; see docs/kali.md.")
        return path

    def _vbox(self, context: ExecutionContext, *args: str) -> CommandResult:
        return run_command([self._app(context, VBOX), *args], timeout=60,
                           log_file=context.folder("logs") / "commands.jsonl")

    @staticmethod
    def _parameters(parameters: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
        defaults = (context.config or AgentConfig()).kali.model_dump()
        return {**{key: value for key, value in defaults.items() if value != ""}, **parameters}

    def _info(self, parameters: dict[str, Any], context: ExecutionContext) -> dict[str, str]:
        parameters = self._parameters(parameters, context)
        vm = param_str(parameters, "vm")
        if not vm:
            raise CapabilityBlocked("Select a registered VM with vm=... or set kali.vm in config.yaml.")
        if vm.startswith("-") or any(c in vm for c in "\r\n\x00"):
            raise ValueError("vm must be an exact registered VM name or UUID.")
        result = self._vbox(context, "showvminfo", vm, "--machinereadable")
        if result.exit_code != 0:
            raise CapabilityBlocked(f"VirtualBox cannot read VM {vm!r}: {result.stderr}")
        info = {}
        for line in result.stdout.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                info[key] = value.strip('"')
        if not info.get("name") or not info.get("VMState"):
            raise CapabilityBlocked("VirtualBox returned no VM name/state.")
        return info

    @staticmethod
    def _record(context: ExecutionContext, label: str, data: Any) -> Path:
        return context.save_result(f"kali_{label}_{uuid.uuid4().hex[:12]}.json", data)

    def list_vms(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        result = self._vbox(context, "list", "vms")
        path = self._record(context, "vms", result.to_dict())
        return IntegrationResult(result.exit_code == 0, result.to_dict(),
                                 [evidence(path, "Registered VirtualBox VMs", "command_output")],
                                 checks=[{"type": "json_value", "path": str(path), "key": "exit_code", "equals": 0}])

    def status(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        info = self._info(parameters, context)
        path = self._record(context, "state", {k: info[k] for k in ("name", "VMState")})
        return IntegrationResult(True, {"vm": info["name"], "state": info["VMState"]},
                                 [evidence(path, "Observed VirtualBox VM state", "command_output")],
                                 checks=[{"type": "file_exists", "path": str(path)}])

    def start(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        parameters = self._parameters(parameters, context)
        info = self._info(parameters, context)
        if info["VMState"] != "running":
            if info["VMState"] not in {"poweroff", "saved", "aborted"}:
                raise CapabilityBlocked(f"VM is {info['VMState']}; start/resume it manually.")
            result = self._vbox(context, "startvm", param_str(parameters, "vm"), "--type", "gui")
            if result.exit_code != 0:
                raise CapabilityBlocked(f"Cannot start VM: {result.stderr}")
            info = self._info(parameters, context)
        path = self._record(context, "started", {k: info[k] for k in ("name", "VMState")})
        return IntegrationResult(info["VMState"] == "running", {"vm": info["name"], "state": info["VMState"]},
                                 [evidence(path, "VM state after start", "command_output")],
                                 checks=[{"type": "json_value", "path": str(path), "key": "VMState", "equals": "running"}])

    @staticmethod
    def _capture(context: ExecutionContext, vm_name: str, name: str) -> Path:
        # Deliberately bypass the generic screenshot fallback and injected legacy
        # screenshot callbacks: those may capture the desktop or steal focus.
        if os.name != "nt":
            raise CapabilityBlocked("Kali evidence requires Windows PrintWindow.")
        pattern = r"^" + re.escape(vm_name) + r"(?:\s+\[.*\])?\s+[-–]\s+(?:Oracle\s+)?(?:VM\s+)?VirtualBox\s*$"
        window = shots.find_window(pattern, timeout=5)
        if window is None or window.is_minimized():
            raise CapabilityBlocked("Open the VM's VirtualBox window in normal window mode and leave it unminimized.")
        image = shots.capture_window(int(window.handle))
        if image is None:
            raise CapabilityBlocked("PrintWindow could not capture VirtualBox. No screenshot was substituted.")
        width, height = image.size
        center = image.crop((width // 5, height // 5, width * 4 // 5, height * 4 // 5)).convert("L")
        if width < 300 or height < 200 or center.getextrema()[0] == center.getextrema()[1]:
            raise CapabilityBlocked("VirtualBox rendered no usable guest display through PrintWindow.")
        path = shots._output(context.workspace, name)
        image.save(path)
        shots.validate_image(path)
        return path

    def screenshot(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        info = self._info(parameters, context)
        path = self._capture(context, info["name"], f"kali_{uuid.uuid4().hex[:12]}.png")
        return IntegrationResult(True, {"vm": info["name"], "capture": "Windows PrintWindow"},
                                 [evidence(path, "VirtualBox window captured in Windows", "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(path)}])

    def run(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        parameters = self._parameters(parameters, context)
        config = context.config or AgentConfig()
        decision = PolicyEngine(config, context.allowed_targets).check(self.CAPABILITIES[-1], parameters)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        host, user = param_str(parameters, "host"), param_str(parameters, "user")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", host) or host.startswith("-"):
            raise ValueError("Invalid SSH host.")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", user):
            raise ValueError("Invalid Kali user.")
        port, timeout = param_int(parameters, "port", 22), param_int(parameters, "timeout", 120)
        if not 1 <= port <= 65535 or not 1 <= timeout <= 3600:
            raise ValueError("port must be 1..65535 and timeout 1..3600 seconds.")
        command, script = param_str(parameters, "command"), param_str(parameters, "script")
        if bool(command) == bool(script):
            raise ValueError("Supply exactly one of command or script.")
        if script:
            command = context.resolve(script).read_text(encoding="utf-8-sig").replace("\r\n", "\n")
        if not command.strip() or "\x00" in command:
            raise ValueError("Command is empty or contains NUL.")
        cwd = param_str(parameters, "cwd")
        if cwd and not cwd.startswith("/"):
            raise ValueError("cwd must be an absolute path in Kali.")
        info = self._info(parameters, context)
        if info["VMState"] != "running":
            raise CapabilityBlocked("VM is not running; use kali.start and log into the Kali desktop first.")
        vm_macs = [value.lower() for key, value in info.items()
                   if re.fullmatch(r"macaddress\d+", key) and re.fullmatch(r"[0-9A-Fa-f]{12}", value)]
        if not vm_macs:
            raise CapabilityBlocked("VirtualBox returned no network adapter MAC addresses to identify the SSH guest.")
        argv = [self._app(context, SSH), "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
                "-o", "ClearAllForwardings=yes", "-p", str(port), "-l", user]
        identity = param_str(parameters, "identity_file")
        if identity:
            key = Path(identity).expanduser().resolve()
            if not key.is_file():
                raise CapabilityBlocked("SSH private key file not found. See docs/kali.md.")
            argv += ["-o", "IdentitiesOnly=yes", "-i", str(key)]
        execution_id = param_str(parameters, "execution_id") or str(context.step_id or uuid.uuid4().hex)
        fingerprint = hashlib.sha256(json.dumps(
            [execution_id, info["name"], vm_macs, host, user, port, command, cwd,
             param_str(parameters, "display", ":0"), param_str(parameters, "xauthority"), timeout],
            ensure_ascii=False).encode()).hexdigest()[:24]
        checkpoint = context.folder("working") / f"kali_{fingerprint}.json"
        cached_picture: Path | None = None
        if checkpoint.exists():
            saved = json.loads(checkpoint.read_text(encoding="utf-8"))
            if saved.get("status") != "finished":
                raise CapabilityBlocked("Previous SSH execution has an uncertain result; inspect Kali before using a new execution_id.")
            observed = saved["observed"]
            if saved.get("screenshot") and observed.get("terminal_visible") is True:
                candidate = context.resolve(saved["screenshot"], must_exist=False)
                if (candidate.is_file() and hashlib.sha256(candidate.read_bytes()).hexdigest()
                        == saved.get("screenshot_sha256")):
                    shots.validate_image(candidate)
                    cached_picture = candidate
            if cached_picture is None:
                if not observed.get("title"):
                    raise CapabilityBlocked("Saved result has no terminal identity for screenshot recovery.")
                probe = run_command(
                    [*argv, host, "python3 -c " + shlex.quote(SSH_OBSERVE)], timeout=15,
                    input_text=json.dumps({"title": observed["title"], "vm_macs": vm_macs,
                                           "display": param_str(parameters, "display", ":0"),
                                           "xauthority": param_str(parameters, "xauthority")}),
                    log_file=context.folder("logs") / "commands.jsonl",
                )
                try:
                    visible = probe.exit_code == 0 and json.loads(probe.stdout).get("terminal_visible") is True
                except ValueError:
                    visible = False
                if not visible:
                    raise CapabilityBlocked("The saved command's terminal is no longer visible. Show that terminal in Kali before recovering its screenshot.")
                observed["terminal_visible"] = True
        else:
            # Verify capture availability BEFORE changing anything in the guest.
            self._capture(context, info["name"], f"kali_before_{fingerprint}.png")
            job = {"command": command, "cwd": cwd, "timeout": timeout, "vm_macs": vm_macs,
                   "display": param_str(parameters, "display", ":0"),
                   "xauthority": param_str(parameters, "xauthority"),
                   "title": f"DoneAsik {fingerprint}", "worker": TERMINAL_WORKER}
            try:
                with checkpoint.open("x", encoding="utf-8") as stream:
                    json.dump({"status": "pending", "execution_id": execution_id,
                               "vm": info["name"], "host": host}, stream)
            except FileExistsError as exc:
                raise CapabilityBlocked("This command is already being executed; inspect its saved result.") from exc
            result = run_command(
                [*argv, host, "python3 -c " + shlex.quote(SSH_BOOTSTRAP)],
                timeout=timeout + 40, input_text=json.dumps(job),
                log_file=context.folder("logs") / "commands.jsonl",
            )
            if result.exit_code != 0:
                path = self._record(context, "ssh_error", result.to_dict())
                return IntegrationResult(False, {"reason": "SSH/guest terminal failed; see docs/kali.md. Inspect the guest before retrying.",
                                                 "stderr": result.stderr, "timed_out": result.timed_out,
                                                 "execution_id": execution_id},
                                         [evidence(path, "SSH failure", "command_output")], blocked=True)
            try:
                observed = json.loads(result.stdout)
                if (not isinstance(observed, dict) or type(observed.get("exit_code")) is not int
                        or not isinstance(observed.get("stdout"), str)
                        or type(observed.get("timed_out")) is not bool
                        or type(observed.get("terminal_visible")) is not bool):
                    raise ValueError("Invalid guest result")
            except (ValueError, TypeError) as exc:
                raise CapabilityBlocked("SSH returned no valid command result; inspect Kali before retrying.") from exc
            temporary = checkpoint.with_suffix(".tmp")
            temporary.write_text(json.dumps({"status": "finished", "observed": observed}), encoding="utf-8")
            temporary.replace(checkpoint)
        record = self._record(context, "command", {"vm": info["name"], "host": host, "user": user,
                                                   "command": command, **observed})
        files = [evidence(record, "Observed command and output from Kali", "command_output")]
        checks: list[dict[str, Any]] = [
            {"type": "json_value", "path": str(record), "key": "exit_code", "equals": 0},
            {"type": "json_value", "path": str(record), "key": "timed_out", "equals": False},
            {"type": "json_value", "path": str(record), "key": "terminal_visible", "equals": True},
        ]
        expect = param_str(parameters, "expect")
        matched = not expect or expect in observed["stdout"]
        if expect:
            output = context.save_result(f"kali_output_{uuid.uuid4().hex[:12]}.txt", observed["stdout"] or "\n")
            files.append(evidence(output, "Kali command output", "command_output"))
            checks.append({"type": "text_contains", "path": str(output), "value": expect})
        try:
            if cached_picture is not None:
                picture = cached_picture
            else:
                context.sleep(0.5)  # allow the guest terminal's last paint to reach the host
                picture = self._capture(context, info["name"], f"kali_{fingerprint}.png")
        except CapabilityBlocked as exc:
            return IntegrationResult(False, {"reason": str(exc), **observed, "execution_id": execution_id},
                                     files, blocked=True, checks=checks)
        snapshot = {"status": "finished", "observed": observed,
                    "screenshot": str(picture.resolve().relative_to(context.workspace.resolve())),
                    "screenshot_sha256": hashlib.sha256(picture.read_bytes()).hexdigest()}
        temporary = checkpoint.with_suffix(".tmp")
        temporary.write_text(json.dumps(snapshot), encoding="utf-8")
        temporary.replace(checkpoint)
        files.append(evidence(picture, "Kali command result in the Windows VirtualBox window", "screenshot"))
        checks.append({"type": "image_valid", "path": str(picture)})
        verified = (observed["exit_code"] == 0 and not observed["timed_out"]
                    and observed["terminal_visible"] and matched)
        return IntegrationResult(verified, {"vm": info["name"], "execution_id": execution_id,
                                           "capture": "Windows PrintWindow", **observed,
                                           **({"reason": "Command failed, timed out, terminal is hidden or expected output is absent."} if not verified else {})},
                                 files, checks=checks)

    def narrate_run(self, facts: StepFacts, language: str) -> Narrative:
        russian = language == "ru"
        command = facts.parameters.get("command") or facts.parameters.get("script", "")
        if facts.completed:
            text = (f"В виртуальной машине Kali Linux выполнена команда {command}. Результат показан на снимке окна VirtualBox."
                    if russian else f"The command {command} was executed in the Kali Linux virtual machine. The result is shown in the VirtualBox window screenshot.")
        else:
            text = ("Выполнение команды не подтверждено: " if russian else "Command completion was not confirmed: ") + facts.reason
        return Narrative("Kali Linux", [text], figure_caption="VirtualBox — Kali Linux",
                         outcome_explained=not facts.completed)


def create_adapters(services: Any) -> list[KaliAdapter]:
    return [KaliAdapter()]
