"""AI provider abstraction with structured output, timeouts, retries and validation.

Providers implement :class:`LLMProvider.complete_json`, returning a dict that
matches a JSON schema.  Planning, recovery advice and the desktop computer-use
decider all go through this interface, so another provider can be added by
implementing one method and registering it in :data:`PROVIDERS`.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any, Protocol

from .credentials import get_secret, redact_text


class ProviderError(RuntimeError):
    """The provider could not return a valid structured answer."""


class LLMProvider(Protocol):
    name: str
    model: str

    def complete_json(self, system: str, user: str, schema: dict[str, Any], *, name: str = "answer") -> dict[str, Any]: ...


def _post(url: str, body: dict[str, Any], headers: dict[str, str], timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def _with_retries(call: Callable[[], dict[str, Any]], retries: int, provider: str) -> dict[str, Any]:
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return call()
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code not in {408, 409, 429, 500, 502, 503, 504}:
                raise ProviderError(f"{provider} request failed: HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
        if attempt < retries:
            time.sleep(min(2 ** attempt, 20))
    raise ProviderError(f"{provider} unavailable after {retries + 1} attempt(s): {redact_text(str(last))}")


def _validate(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    """Minimal JSON-schema validation (types, required, enum, additionalProperties)."""
    kind = schema.get("type")
    if "anyOf" in schema:
        errors = []
        for option in schema["anyOf"]:
            try:
                _validate(value, option, path)
                return
            except ProviderError as exc:
                errors.append(str(exc))
        raise ProviderError(f"{path}: no alternative matched ({'; '.join(errors)})")
    checks: dict[str, type | tuple[type, ...]] = {"object": dict, "array": list, "string": str, "boolean": bool, "integer": int,
                                                  "number": (int, float), "null": type(None)}
    if (kind in checks and not isinstance(value, checks[kind])) or (kind == "integer" and isinstance(value, bool)):
        raise ProviderError(f"{path}: expected {kind}, got {type(value).__name__}")
    if "enum" in schema and value not in schema["enum"]:
        raise ProviderError(f"{path}: {value!r} is not one of the allowed values")
    if kind == "object":
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                raise ProviderError(f"{path}: missing required field {key!r}")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                raise ProviderError(f"{path}: unexpected fields {sorted(extra)}")
        for key, item in value.items():
            if key in properties:
                _validate(item, properties[key], f"{path}.{key}")
    if kind == "array":
        for index, item in enumerate(value):
            _validate(item, schema.get("items", {}), f"{path}[{index}]")


class OpenAIProvider:
    name = "openai"

    def __init__(self, model: str, *, timeout: float = 90, retries: int = 2, base_url: str | None = None) -> None:
        self.model = model
        self.timeout = timeout
        self.retries = retries
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        key = get_secret("OPENAI_API_KEY")
        if not key:
            raise ProviderError("OPENAI_API_KEY is required for the OpenAI provider.")
        self._key = key

    def complete_json(self, system: str, user: str, schema: dict[str, Any], *, name: str = "answer") -> dict[str, Any]:
        body = {
            "model": self.model,
            "input": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "text": {"format": {"type": "json_schema", "name": name, "strict": True, "schema": schema}},
        }
        answer = _with_retries(lambda: _post(f"{self.base_url}/responses", body, {"Authorization": f"Bearer {self._key}"},
                                             self.timeout), self.retries, self.name)
        text = answer.get("output_text")
        if not text:
            for output in answer.get("output", []):
                for content in output.get("content", []):
                    if content.get("type") == "output_text":
                        text = content.get("text")
                        break
        if not text:
            raise ProviderError("OpenAI returned no text output.")
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ProviderError(f"OpenAI returned invalid JSON: {exc}") from exc
        _validate(value, schema)
        return value


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str, *, timeout: float = 180, retries: int = 1, base_url: str | None = None) -> None:
        self.model = model
        self.timeout = timeout
        self.retries = retries
        self.base_url = (base_url or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")

    def complete_json(self, system: str, user: str, schema: dict[str, Any], *, name: str = "answer") -> dict[str, Any]:
        body = {"model": self.model, "stream": False, "format": schema, "options": {"temperature": 0},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        answer = _with_retries(lambda: _post(f"{self.base_url}/api/chat", body, {}, self.timeout), self.retries, self.name)
        try:
            value = json.loads(answer["message"]["content"])
        except (KeyError, json.JSONDecodeError) as exc:
            raise ProviderError(f"Ollama returned invalid JSON: {exc}") from exc
        _validate(value, schema)
        return value


class ScriptedProvider:
    """Deterministic provider for tests and offline demos: replays prepared answers."""

    name = "scripted"

    def __init__(self, answers: list[dict[str, Any]] | Callable[[str, str, dict[str, Any]], dict[str, Any]], model: str = "scripted") -> None:
        self.model = model
        self._answers = answers
        self.calls: list[dict[str, Any]] = []

    def complete_json(self, system: str, user: str, schema: dict[str, Any], *, name: str = "answer") -> dict[str, Any]:
        self.calls.append({"system": system, "user": user, "name": name})
        if callable(self._answers):
            value = self._answers(system, user, schema)
        else:
            if not self._answers:
                raise ProviderError("scripted provider has no more answers")
            value = self._answers.pop(0)
        _validate(value, schema)
        return value


DEFAULT_MODELS = {"openai": "gpt-6-astra", "ollama": "qwen2.5:14b"}
PROVIDERS: dict[str, Callable[..., LLMProvider]] = {"openai": OpenAIProvider, "ollama": OllamaProvider}


def resolve_provider_name(requested: str | None) -> str:
    name = (requested or "auto").lower()
    if name != "auto":
        return name
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("OLLAMA_HOST"):
        return "ollama"
    return "deterministic"


def make_provider(name: str, model: str | None = None, config: Any = None) -> LLMProvider | None:
    resolved = resolve_provider_name(name)
    if resolved in {"deterministic", "none"}:
        return None
    if resolved not in PROVIDERS:
        raise ValueError(f"Unknown AI provider {name!r}; available: auto, deterministic, {', '.join(PROVIDERS)}")
    ai = getattr(config, "ai", None)
    return PROVIDERS[resolved](
        model or getattr(ai, "model", None) or DEFAULT_MODELS[resolved],
        timeout=float(getattr(ai, "timeout_seconds", 90)), retries=int(getattr(ai, "max_retries", 2)),
        base_url=getattr(ai, "base_url", None),
    )


def provider_from_config(config: Any, purpose: str = "planning") -> LLMProvider | None:
    """Provider for secondary uses (recovery advice, computer use); ``None`` when not configured."""
    ai = getattr(config, "ai", None)
    if purpose == "recovery" and ai is not None and not ai.recovery_advice:
        return None
    try:
        return make_provider(getattr(ai, "provider", "auto"), getattr(ai, "model", None), config)
    except (ProviderError, ValueError):
        return None
