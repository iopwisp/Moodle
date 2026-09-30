"""Credential lookup and redaction.

Credentials come only from environment variables, the OS credential store
(``keyring``, optional) or explicit runtime values. Every value obtained through
:func:`get_secret` is remembered so that :func:`redact` can remove it from logs,
SQLite events, reports and AI prompts.
"""

from __future__ import annotations

import os
import re
import threading
from typing import Any

_KNOWN: set[str] = set()
_LOCK = threading.Lock()

SENSITIVE_KEYS = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|credential|session)",
    re.IGNORECASE,
)
_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}"),
    re.compile(r"(?i)(password|passwd|pwd|token|api[_-]?key|secret)\s*[=:]\s*([^\s&\"']+)"),
)
MASK = "***REDACTED***"


def remember_secret(value: str | None) -> None:
    """Register a runtime secret so it is masked everywhere."""
    if value and len(value) >= 4:
        with _LOCK:
            _KNOWN.add(value)


def get_secret(name: str, *, service: str = "doneasik-lab-agent") -> str | None:
    """Return a secret from the environment or the OS keyring, never from config files."""
    value = os.environ.get(name)
    if not value:
        try:
            import keyring  # type: ignore[import-not-found]

            value = keyring.get_password(service, name)
        except Exception:  # noqa: BLE001 - keyring is optional and backend specific
            value = None
    remember_secret(value)
    return value or None


def redact_text(text: str) -> str:
    with _LOCK:
        known = sorted(_KNOWN, key=len, reverse=True)
    for secret in known:
        text = text.replace(secret, MASK)
    text = _PATTERNS[0].sub(MASK, text)
    text = _PATTERNS[1].sub("Bearer " + MASK, text)
    return _PATTERNS[2].sub(lambda m: f"{m.group(1)}={MASK}", text)


def redact(value: Any) -> Any:
    """Recursively redact strings and values stored under sensitive keys."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            key: (MASK if isinstance(key, str) and SENSITIVE_KEYS.search(key) and item else redact(item))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value
