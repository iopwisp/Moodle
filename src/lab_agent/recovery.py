"""Failure classification and bounded recovery strategies.

``classify`` maps an exception / failed verification to a :class:`FailureKind`.
:class:`RecoveryEngine` then decides, within ``execution.max_attempts``:

* retryable kinds (timeout, window/element missing, application closed,
  verification failed, network) -> call the adapter's optional
  ``recover(capability, parameters, context, kind)`` hook (restart app, reopen
  project, re-read state) and retry;
* after a failed verification, optionally ask the AI advisor once for
  corrected parameters (validated against the capability declaration);
* blocking kinds (missing application/credential, policy) -> BLOCKED, never
  retried in a loop;
* everything else -> FAILED with the reason.
"""

from __future__ import annotations

import socket
import subprocess
import urllib.error
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .integrations.base import CapabilityBlocked, ExecutionContext


class FailureKind(StrEnum):
    TIMEOUT = "timeout"
    APPLICATION_CLOSED = "application_closed"
    WINDOW_MISSING = "window_missing"
    ELEMENT_MISSING = "element_missing"
    VERIFICATION_FAILED = "verification_failed"
    NETWORK = "network_unavailable"
    POLICY = "policy_denied"
    MISSING_DEPENDENCY = "missing_dependency"
    BLOCKED = "blocked"
    INVALID_INPUT = "invalid_input"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


RETRYABLE = {FailureKind.TIMEOUT, FailureKind.APPLICATION_CLOSED, FailureKind.WINDOW_MISSING, FailureKind.ELEMENT_MISSING,
             FailureKind.VERIFICATION_FAILED, FailureKind.NETWORK, FailureKind.UNKNOWN}
BLOCKING = {FailureKind.POLICY, FailureKind.MISSING_DEPENDENCY, FailureKind.BLOCKED}


def classify(error: BaseException | None = None, message: str = "") -> FailureKind:
    from .desktop.uia import ElementNotFound

    if isinstance(error, InterruptedError):
        return FailureKind.STOPPED
    if isinstance(error, CapabilityBlocked):
        return FailureKind.BLOCKED
    if isinstance(error, PermissionError):
        return FailureKind.POLICY
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired, socket.timeout)):
        return FailureKind.TIMEOUT
    if isinstance(error, ElementNotFound):
        return FailureKind.WINDOW_MISSING if "window" in str(error).lower() else FailureKind.ELEMENT_MISSING
    if isinstance(error, (urllib.error.URLError, ConnectionError)):
        return FailureKind.NETWORK
    if isinstance(error, (FileNotFoundError, ValueError, KeyError)) and error is not None:
        text = str(error).lower()
        if "not installed" in text or "set lab_agent" in text:
            return FailureKind.MISSING_DEPENDENCY
        return FailureKind.INVALID_INPUT
    text = (message or str(error or "")).lower()
    if "exited during start-up" in text or "not running" in text or "is not open" in text:
        return FailureKind.APPLICATION_CLOSED
    if "timed out" in text or "timeout" in text:
        return FailureKind.TIMEOUT
    if "verification" in text or "checks passed" in text:
        return FailureKind.VERIFICATION_FAILED
    return FailureKind.UNKNOWN


@dataclass
class RecoveryDecision:
    action: str  # retry | blocked | failed | ask_human
    reason: str
    parameters: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)


class RecoveryEngine:
    def __init__(self, registry: Any, max_attempts: int = 2, advisor: Any = None) -> None:
        self.registry = registry
        self.max_attempts = max(1, max_attempts)
        self.advisor = advisor
        self._advised: set[int] = set()

    def decide(self, task: Any, kind: FailureKind, attempt: int, error: str, context: ExecutionContext,
               observation: dict[str, Any] | None = None) -> RecoveryDecision:
        if kind == FailureKind.STOPPED:
            return RecoveryDecision("failed", "stopped by user")
        if kind in BLOCKING:
            return RecoveryDecision("blocked", error)
        if kind == FailureKind.INVALID_INPUT:
            advice = self._advice(task, error, observation)
            if advice is not None:
                return advice
            return RecoveryDecision("failed", error)
        if attempt >= self.max_attempts:
            return RecoveryDecision("failed", f"{error} (after {attempt} attempt(s))")
        notes: list[str] = []
        adapter = self.registry.adapter_for(task.action)
        hook = getattr(adapter, "recover", None)
        if callable(hook):
            try:
                note = hook(task.action, task.parameters, context, kind.value)
                if note:
                    notes.append(str(note))
            except Exception as exc:  # noqa: BLE001 - a failed recovery hook just means a plain retry
                notes.append(f"recovery hook failed: {exc}")
        if kind == FailureKind.VERIFICATION_FAILED:
            advice = self._advice(task, error, observation)
            if advice is not None:
                advice.notes = notes + advice.notes
                return advice
        return RecoveryDecision("retry", f"retrying after {kind.value}", notes=notes)

    def _advice(self, task: Any, error: str, observation: dict[str, Any] | None) -> RecoveryDecision | None:
        if self.advisor is None or task.id in self._advised:
            return None
        self._advised.add(task.id)
        from .ai import advise_recovery

        try:
            answer = advise_recovery(self.advisor, self.registry, task, error, observation or {})
        except Exception as exc:  # noqa: BLE001 - advice is optional
            return RecoveryDecision("retry", "AI advice unavailable", notes=[str(exc)])
        decision = answer.get("decision")
        if decision == "replace_parameters" and answer.get("action") == task.action:
            return RecoveryDecision("retry", f"AI: {answer.get('reason')}", parameters=answer.get("parameters") or {},
                                    notes=[f"AI proposed parameters {answer.get('parameters')}"])
        if decision == "retry":
            return RecoveryDecision("retry", f"AI: {answer.get('reason')}")
        if decision == "ask_human":
            return RecoveryDecision("ask_human", f"AI: {answer.get('reason')}")
        if decision == "stop":
            return RecoveryDecision("failed", f"AI: {answer.get('reason')}")
        return None
