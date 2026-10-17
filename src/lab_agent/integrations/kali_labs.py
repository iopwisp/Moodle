"""Reusable local web/password labs on the existing Kali SSH + PrintWindow bridge."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
import zlib
from pathlib import Path
from typing import Any

from ..config import AgentConfig
from ..policy import PolicyEngine
from ..tools import kali_lab_guest
from .base import (
    BaseIntegration,
    Capability,
    ExecutionContext,
    IntegrationResult,
    Narrative,
    Param,
    StepFacts,
    evidence,
    param_int,
    param_str,
)
from .kali import VM, KaliAdapter

COMMON = (VM, Param("execution_id", description="reuse to recover without repeating a job"))


def _cap(action: str, description: str, parameters: tuple[Param, ...]) -> Capability:
    return Capability("kali_labs." + action, "kali_labs", description,
                      (*COMMON, *parameters), ("command_output", "screenshot"),
                      "completed guest job, real terminal output and Windows PrintWindow evidence",
                      risk="unsafe", network=True, requires=("app:virtualbox", "app:ssh"),
                      keywords=("kali", "dvwa", "nikto", "john", "xss", "md5"))


class KaliLabsAdapter(BaseIntegration):
    name = "kali_labs"
    CAPABILITIES = (
        _cap("preflight", "Inventory Kali lab tools, GVM feed and Hashcat backend without installing anything", ()),
        _cap("nikto", "Scan an HTTP service on a literal guest loopback IP; preserve partial scans as incomplete",
             (Param("url", "url", required=True), Param("seconds", "int", default=60),
              Param("sql_only", "bool", default=False))),
        _cap("passwords", "Crack a workspace copy of educational raw MD5 hashes in Kali; verify recovered candidates",
             (Param("hashes", "path", required=True),
              Param("engine", choices=("john", "hashcat"), default="john"),
              Param("wordlist", description="absolute guest path, .gz allowed",
                    default="/usr/share/wordlists/rockyou.txt.gz"),
              Param("seconds", "int", default=60))),
        _cap("dvwa", "Test SQL read-only enumeration or harmless reflected XSS on local DVWA; terminal evidence",
             (Param("url", "url", required=True),
              Param("case", choices=("sql", "reflected_xss"), default="sql"),
              Param("level", choices=("low", "medium", "high"), default="low"))),
    )

    def _run(self, parameters: dict[str, Any], job: dict[str, Any],
             context: ExecutionContext) -> IntegrationResult:
        requested_id = param_str(parameters, "execution_id")
        if requested_id and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", requested_id):
            raise ValueError("execution_id must contain 1-64 letters, digits, underscores or hyphens")
        capability = next(c for c in self.CAPABILITIES if c.name.endswith("." + job["job"]))
        decision = PolicyEngine(context.config or AgentConfig(), context.allowed_targets).check(
            capability, parameters)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        packed = base64.b64encode(zlib.compress(Path(kali_lab_guest.__file__).read_bytes())).decode()
        payload = base64.b64encode(json.dumps(job).encode()).decode()
        bootstrap = "import base64,zlib;exec(zlib.decompress(base64.b64decode(" + repr(packed) + ")))"
        command = "python3 -c " + shlex.quote(bootstrap) + " " + shlex.quote(payload)
        # Stable across retries and separate from other capabilities sharing the same plan step.
        execution_id = requested_id or hashlib.sha256(
            json.dumps([context.step_id, job], sort_keys=True).encode()).hexdigest()[:24]
        run_parameters = {"command": command, "timeout": job.get("seconds", 60) + 75,
                          "execution_id": "labs-" + execution_id}
        if parameters.get("vm"):
            run_parameters["vm"] = parameters["vm"]
        result = KaliAdapter().run(run_parameters, context)
        lines = result.details.get("stdout", "").splitlines()
        records = [line[len(kali_lab_guest.MARKER):] for line in lines
                   if line.startswith(kali_lab_guest.MARKER)]
        if len(records) != 1:
            result.verified = False
            result.details["reason"] = result.reason or "Guest returned no unique structured lab result."
            return result
        try:
            observed = json.loads(records[0])
            if not isinstance(observed, dict) or observed.get("status") not in {
                "completed", "partial", "blocked", "failed",
            }:
                raise ValueError("Invalid status")
        except (ValueError, TypeError) as exc:
            result.verified = False
            result.details["reason"] = "Invalid guest lab result: " + str(exc)
            return result
        transport_verified = result.verified
        result.verified = transport_verified and observed["status"] == "completed"
        result.blocked = result.blocked or observed["status"] == "blocked"
        result.details["lab"] = observed
        if not result.verified:
            summary = observed.get("summary", "Lab job did not complete.")
            result.details["reason"] = (result.reason + " " + summary
                                        if not transport_verified else summary)
        prefix = "kali_lab_" + execution_id
        record = context.save_result(prefix + ".json", observed)
        result.evidence.append(evidence(record, "Structured observed Kali lab result", "command_output"))
        result.checks.append({"type": "json_value", "path": str(record),
                              "key": "status", "equals": "completed"})
        # Guest paths never become host paths. Only these fixed export names are accepted.
        files = observed.get("files", {})
        for name in ("nikto.txt", "nikto.csv", "passwords.txt", "dvwa.txt"):
            content = files.get(name) if isinstance(files, dict) else None
            if isinstance(content, str) and content.strip():
                path = context.save_result(prefix + "_" + name, content)
                result.evidence.append(evidence(path, "Kali lab export: " + name, "file"))
        result.report_sections.append({"heading": capability.description,
                                       "text": observed.get("summary", "")})
        return result

    @staticmethod
    def _seconds(parameters: dict[str, Any]) -> int:
        value = param_int(parameters, "seconds", 60)
        if not 5 <= value <= 600:
            raise ValueError("seconds must be between 5 and 600")
        return value

    def preflight(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        return self._run(parameters, {"job": "preflight"}, context)

    def nikto(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        raw = parameters.get("sql_only", False)
        if str(raw).lower() not in {"true", "false"}:
            raise ValueError("sql_only must be true or false")
        return self._run(parameters, {
            "job": "nikto", "url": kali_lab_guest.local_url(param_str(parameters, "url")),
            "seconds": self._seconds(parameters), "sql_only": str(raw).lower() == "true",
        }, context)

    def passwords(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        path = context.resolve(param_str(parameters, "hashes"))
        if path.stat().st_size > 1024 * 1024:
            raise ValueError("The educational hash input is limited to 1 MiB.")
        text = path.read_text(encoding="utf-8-sig").strip()
        if not text or any(not re.fullmatch(r"(?:[A-Za-z0-9_.-]+:)?[0-9a-fA-F]{32}", line)
                           for line in text.splitlines()):
            raise ValueError("Expected raw MD5 or username:MD5, one entry per line.")
        engine = param_str(parameters, "engine", "john")
        if engine not in {"john", "hashcat"}:
            raise ValueError("engine must be john or hashcat")
        wordlist = param_str(parameters, "wordlist", "/usr/share/wordlists/rockyou.txt.gz")
        if not wordlist.startswith("/") or "\x00" in wordlist:
            raise ValueError("wordlist must be an absolute path inside Kali")
        return self._run(parameters, {
            "job": "passwords", "engine": engine, "hashes_b64": base64.b64encode(text.encode()).decode(),
            "wordlist": wordlist, "seconds": self._seconds(parameters),
        }, context)

    def dvwa(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        case, level = param_str(parameters, "case", "sql"), param_str(parameters, "level", "low")
        if case not in {"sql", "reflected_xss"} or level not in {"low", "medium", "high"}:
            raise ValueError("Unsupported DVWA case/security level")
        if case == "sql" and level != "low":
            raise ValueError("The read-only SQL example supports Low security only.")
        return self._run(parameters, {
            "job": "dvwa", "url": kali_lab_guest.local_url(param_str(parameters, "url")),
            "case": case, "level": level,
        }, context)

    def narrate(self, facts: StepFacts, language: str) -> Narrative:
        observed = facts.details.get("lab", {})
        summary = observed.get("summary") or facts.reason or "No verified result."
        text = ("В Kali Linux получен следующий результат: " + summary
                if language == "ru" else "The Kali lab returned the following result: " + summary)
        return Narrative("Проверка в Kali Linux" if language == "ru" else "Kali Linux lab",
                         [text], figure_caption=("Окно терминала Kali в VirtualBox"
                         if language == "ru" else "Kali terminal in the VirtualBox window"),
                         show_code=False, outcome_explained=not facts.completed)


def create_adapters(services: Any) -> list[KaliLabsAdapter]:
    return [KaliLabsAdapter()]
