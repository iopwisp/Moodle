"""PowerShell integration with an allowlist.

Safe capabilities build their command from validated parameters (the AI never
supplies PowerShell text).  ``powershell.run_script`` executes an arbitrary
command and is ``risk="unsafe"``: the policy engine denies it unless
``policy.powershell.arbitrary: true`` is set in config.yaml, and even then each
use needs an explicit user approval.  Plan parameters cannot switch this on.
"""

from __future__ import annotations

import os
import re
import shutil
from typing import Any

from ..tools.process import run_command
from ..workspace import file_hash
from .base import (
    BaseIntegration,
    Capability,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_int,
    param_str,
)

_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class PowerShellAdapter(BaseIntegration):
    name = "powershell"
    CAPABILITIES = (
        Capability("powershell.get_file_hash", "powershell", "Run Get-FileHash on a workspace file and cross-check it",
                   (Param("path", "path", True), Param("algorithm", "str", False, choices=("SHA256", "SHA1", "MD5"))),
                   ("command_output",), "PowerShell digest equals the independently computed digest",
                   keywords=("get-filehash", "powershell")),
        Capability("powershell.system_info", "powershell", "Record OS, PowerShell and hardware information for the report",
                   (), ("command_output",), "command succeeded and output saved", keywords=("system info", "версия ос")),
        Capability("powershell.list_directory", "powershell", "List a workspace directory with sizes and timestamps",
                   (Param("path", "path", False),), ("command_output",), "listing saved"),
        Capability("powershell.test_connection", "powershell", "Test TCP connectivity to localhost or an authorized host",
                   (Param("host", "str", True), Param("port", "int", True)), ("command_output",),
                   "TcpTestSucceeded is True", network=True),
        Capability("powershell.run_script", "powershell",
                   "Run an arbitrary PowerShell command (disabled unless explicitly enabled and approved)",
                   (Param("command", "str", True),), ("command_output",), "exit code 0", risk="unsafe"),
    )

    def _exe(self) -> str:
        for candidate in ("pwsh.exe", "powershell.exe", "pwsh"):
            found = shutil.which(candidate)
            if found:
                return found
        return "powershell.exe" if os.name == "nt" else "pwsh"

    def _run(self, context: ExecutionContext, script: str, timeout: float = 120) -> Any:
        return run_command([self._exe(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                           cwd=context.workspace, timeout=timeout, log_file=context.folder("logs") / "commands.jsonl")

    def get_file_hash(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        target = context.resolve(param_str(parameters, "path"), base="input")
        algorithm = (param_str(parameters, "algorithm", "SHA256") or "SHA256").upper()
        result = self._run(context, f"(Get-FileHash -LiteralPath {_ps_quote(str(target))} -Algorithm {algorithm}).Hash")
        reported = result.stdout.strip().lower()
        expected = file_hash(target, algorithm.lower())
        output = context.save_result(f"get_filehash_{target.name}.txt",
                                     f"PS> Get-FileHash -Algorithm {algorithm} {target.name}\n{result.stdout}\n"
                                     f"independent {algorithm}: {expected}\n")
        ok = result.exit_code == 0 and reported == expected
        return IntegrationResult(ok, {"exit_code": result.exit_code, "hash": reported, "expected": expected,
                                      **({} if ok else {"reason": result.stderr.strip()[:200] or "hash mismatch"})},
                                 [evidence(output, f"Get-FileHash {target.name}", "command_output")],
                                 checks=[{"type": "command_exit_code", "equals": 0}])

    def system_info(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        script = ("$o=Get-CimInstance Win32_OperatingSystem; "
                  "'OS: ' + $o.Caption + ' ' + $o.Version; 'PowerShell: ' + $PSVersionTable.PSVersion; "
                  "'Machine: ' + $env:COMPUTERNAME; 'Memory GB: ' + [math]::Round($o.TotalVisibleMemorySize/1MB,1)")
        result = self._run(context, script)
        output = context.save_result("system_info.txt", result.stdout)
        ok = result.exit_code == 0 and "OS:" in result.stdout
        return IntegrationResult(ok, {"exit_code": result.exit_code, **({} if ok else {"reason": result.stderr[:200]})},
                                 [evidence(output, "System information", "command_output")],
                                 checks=[{"type": "text_contains", "path": "results/system_info.txt", "value": "OS:"}])

    def list_directory(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        target = context.resolve(param_str(parameters, "path") or ".")
        result = self._run(context, f"Get-ChildItem -LiteralPath {_ps_quote(str(target))} -Recurse | "
                                    "Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize | Out-String -Width 300")
        output = context.save_result(f"listing_{target.name or 'workspace'}.txt", result.stdout)
        return IntegrationResult(result.exit_code == 0, {"exit_code": result.exit_code},
                                 [evidence(output, f"Directory listing of {target.name}", "command_output")])

    def test_connection(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        host = param_str(parameters, "host")
        port = param_int(parameters, "port", 80)
        if not _HOST_RE.fullmatch(host) or not 0 < port < 65536:
            raise ValueError("host/port are invalid")
        result = self._run(context, f"(Test-NetConnection -ComputerName {_ps_quote(host)} -Port {port} -WarningAction SilentlyContinue).TcpTestSucceeded")
        succeeded = result.stdout.strip().lower() == "true"
        output = context.save_result(f"test_connection_{host}_{port}.txt", result.stdout + result.stderr)
        return IntegrationResult(succeeded, {"host": host, "port": port, "succeeded": succeeded,
                                             **({} if succeeded else {"reason": f"{host}:{port} not reachable"})},
                                 [evidence(output, f"Test-NetConnection {host}:{port}", "command_output")])

    def run_script(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        command = param_str(parameters, "command")
        if not command:
            raise ValueError("command is required")
        result = self._run(context, command, timeout=600)
        output = context.save_result(f"powershell_step_{context.step_id or 0:02d}.txt",
                                     f"PS> {command}\n\nexit code: {result.exit_code}\n\n{result.stdout}\n{result.stderr}")
        return IntegrationResult(result.exit_code == 0, {**result.to_dict(), **({} if result.exit_code == 0 else
                                                                               {"reason": f"exit code {result.exit_code}"})},
                                 [evidence(output, "PowerShell command output", "command_output")],
                                 checks=[{"type": "command_exit_code", "equals": 0}])


def create_adapters(services: Any) -> list[PowerShellAdapter]:
    return [PowerShellAdapter()]

