"""Verification engine: deterministic post-condition checks (a small DSL).

A check is a mapping with a ``type`` plus type-specific fields, e.g.::

    {"type": "file_exists", "path": "results/foremost/audit.txt"}
    {"type": "text_contains", "path": "results/ping.txt", "value": "Received = 4"}
    {"type": "hash_match", "path": "input/evidence.dd", "sha256_file": "input/evidence.dd.sha256"}
    {"type": "sqlite_query", "path": "...autopsy.db", "query": "SELECT count(*) FROM tsk_files", "min": 1}

Checks never trust the adapter's claim; they look at files, processes,
windows, HTTP endpoints or recorded command results.  Integrations may
register additional check types with :func:`register_check`.
"""

from __future__ import annotations

import csv
import json
import re
import socket
import sqlite3
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .workspace import file_hash


@dataclass
class CheckContext:
    workspace: Path
    details: dict[str, Any] = field(default_factory=dict)
    evidence_paths: list[Path] = field(default_factory=list)
    url_allowed: Callable[[str], bool] | None = None
    ui_driver: Any = None

    def path(self, value: str | Path) -> Path:
        raw = Path(str(value))
        root = self.workspace.resolve()
        resolved = (raw if raw.is_absolute() else root / raw).resolve()
        if not resolved.is_relative_to(root):
            raise PermissionError(f"Verification path escapes the workspace: {value}")
        return resolved


@dataclass
class CheckResult:
    type: str
    passed: bool
    detail: str
    spec: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "passed": self.passed, "detail": self.detail, "spec": self.spec}


@dataclass
class VerificationReport:
    results: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(result.passed for result in self.results)

    @property
    def failures(self) -> list[CheckResult]:
        return [result for result in self.results if not result.passed]

    def summary(self) -> str:
        if not self.results:
            return "no checks"
        passed = sum(result.passed for result in self.results)
        text = f"{passed}/{len(self.results)} checks passed"
        if self.failures:
            text += ": " + "; ".join(f"{f.type}: {f.detail}" for f in self.failures[:5])
        return text


CheckFn = Callable[[dict[str, Any], CheckContext], tuple[bool, str]]
_CHECKS: dict[str, CheckFn] = {}


def register_check(name: str) -> Callable[[CheckFn], CheckFn]:
    def decorator(function: CheckFn) -> CheckFn:
        _CHECKS[name] = function
        return function

    return decorator


def check_types() -> list[str]:
    return sorted(_CHECKS)


def run_checks(checks: list[dict[str, Any]], context: CheckContext) -> VerificationReport:
    report = VerificationReport()
    for spec in checks:
        kind = str(spec.get("type", ""))
        function = _CHECKS.get(kind)
        if function is None:
            report.results.append(CheckResult(kind or "?", False, f"unknown check type {kind!r}", spec))
            continue
        try:
            passed, detail = function(spec, context)
        except Exception as exc:  # noqa: BLE001 - a crashing check is a failed check
            passed, detail = False, f"{type(exc).__name__}: {exc}"
        report.results.append(CheckResult(kind, bool(passed), detail, spec))
    return report


# --------------------------------------------------------------------------- helpers
def _read_text(path: Path, limit: int = 20_000_000) -> str:
    if path.stat().st_size > limit:
        raise ValueError(f"{path.name} is too large to inspect as text")
    return path.read_text(encoding="utf-8", errors="replace")


def _json_lookup(document: Any, dotted: str) -> Any:
    cursor = document
    for part in [item for item in dotted.split(".") if item]:
        if isinstance(cursor, list):
            cursor = cursor[int(part)]
        elif isinstance(cursor, dict):
            cursor = cursor[part]
        else:
            raise KeyError(dotted)
    return cursor


def _compare(actual: Any, spec: dict[str, Any]) -> tuple[bool, str]:
    if "equals" in spec:
        return actual == spec["equals"], f"value={actual!r}, expected {spec['equals']!r}"
    passed = True
    if "min" in spec:
        passed &= float(actual) >= float(spec["min"])
    if "max" in spec:
        passed &= float(actual) <= float(spec["max"])
    return passed, f"value={actual!r}"


# --------------------------------------------------------------------------- file checks
@register_check("file_exists")
def _file_exists(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    path = ctx.path(spec["path"])
    min_size = int(spec.get("min_size", 1))
    if not path.is_file():
        return False, f"{spec['path']} does not exist"
    size = path.stat().st_size
    return size >= min_size, f"{spec['path']} exists ({size} bytes)"


@register_check("dir_not_empty")
def _dir_not_empty(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    path = ctx.path(spec["path"])
    files = [item for item in path.rglob(spec.get("pattern", "*")) if item.is_file()] if path.is_dir() else []
    minimum = int(spec.get("min", 1))
    return len(files) >= minimum, f"{len(files)} file(s) in {spec['path']}"


@register_check("text_contains")
def _text_contains(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    text = _read_text(ctx.path(spec["path"]))
    if spec.get("regex"):
        found = re.search(str(spec["regex"]), text, re.MULTILINE) is not None
        return found, f"regex {spec['regex']!r} {'found' if found else 'not found'}"
    value = str(spec["value"])
    haystack, needle = (text.casefold(), value.casefold()) if spec.get("ignore_case") else (text, value)
    return needle in haystack, f"{value!r} {'found' if needle in haystack else 'not found'}"


@register_check("text_not_contains")
def _text_not_contains(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    passed, detail = _text_contains(spec, ctx)
    return not passed, detail


@register_check("json_value")
def _json_value(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    document = json.loads(_read_text(ctx.path(spec["path"])))
    return _compare(_json_lookup(document, str(spec["key"])), spec)


@register_check("csv_rows")
def _csv_rows(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    with ctx.path(spec["path"]).open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    columns = spec.get("columns", [])
    if rows and columns:
        missing = [column for column in columns if column not in rows[0]]
        if missing:
            return False, f"missing columns {missing}"
    return _compare(len(rows), {"min": spec.get("min", 1), **({"max": spec["max"]} if "max" in spec else {})})


@register_check("hash_match")
def _hash_match(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    algorithm = str(spec.get("algorithm", "sha256")).lower()
    actual = file_hash(ctx.path(spec["path"]), algorithm)
    expected = str(spec.get("expected", "")).strip().lower()
    if not expected and spec.get("sha256_file"):
        content = _read_text(ctx.path(spec["sha256_file"]))
        match = re.search(r"\b[0-9a-fA-F]{64}\b", content)
        expected = match.group(0).lower() if match else ""
    if not expected and spec.get("same_as"):
        expected = file_hash(ctx.path(spec["same_as"]), algorithm)
    if not expected:
        return False, "no expected hash supplied"
    return actual == expected, f"{algorithm}={actual}, expected {expected}"


@register_check("image_valid")
def _image_valid(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    from PIL import Image

    path = ctx.path(spec["path"])
    with Image.open(path) as image:
        image.verify()
    with Image.open(path) as image:
        width, height = image.size
    minimum = int(spec.get("min_width", 32))
    return width >= minimum and height >= minimum, f"{width}x{height} image"


@register_check("screenshot_exists")
def _screenshot_exists(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    if spec.get("path"):
        return _image_valid({"path": spec["path"]}, ctx)
    images = [p for p in ctx.evidence_paths if p.suffix.lower() in {".png", ".jpg", ".jpeg"} and p.is_file()]
    for image in images:
        ok, detail = _image_valid({"path": str(image)}, ctx)
        if ok:
            return True, f"{image.name}: {detail}"
    return False, "no valid screenshot evidence for this step"


@register_check("pdf_valid")
def _pdf_valid(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    from pypdf import PdfReader

    reader = PdfReader(str(ctx.path(spec["path"])))
    pages = len(reader.pages)
    if pages < int(spec.get("min_pages", 1)):
        return False, f"{pages} page(s)"
    if spec.get("text_contains"):
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        if str(spec["text_contains"]) not in text:
            return False, f"{pages} page(s) but text {spec['text_contains']!r} missing"
    return True, f"{pages} page(s)"


@register_check("zip_valid")
def _zip_valid(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    with zipfile.ZipFile(ctx.path(spec["path"])) as archive:
        broken = archive.testzip()
        names = archive.namelist()
    if broken:
        return False, f"CRC error in {broken}"
    if spec.get("contains") and spec["contains"] not in names:
        return False, f"member {spec['contains']!r} missing; members={names}"
    return True, f"valid archive with {len(names)} member(s): {names[:10]}"


@register_check("docx_valid")
def _docx_valid(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    with zipfile.ZipFile(ctx.path(spec["path"])) as archive:
        ok = "word/document.xml" in archive.namelist()
    return ok, "word/document.xml present" if ok else "not a DOCX package"


@register_check("sqlite_query")
def _sqlite_query(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    query = str(spec["query"]).strip()
    if not re.match(r"(?is)^\s*select\b", query) or ";" in query.rstrip(";"):
        return False, "only single SELECT statements are allowed"
    path = ctx.path(spec["path"])
    with sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True) as connection:
        row = connection.execute(query).fetchone()
    value = row[0] if row else None
    return _compare(value if value is not None else 0, {k: v for k, v in spec.items() if k in {"min", "max", "equals"}} or {"min": 1})


# --------------------------------------------------------------------------- recorded results
@register_check("details_value")
def _details_value(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    return _compare(_json_lookup(ctx.details, str(spec["key"])), spec)


@register_check("command_exit_code")
def _command_exit_code(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    key = str(spec.get("key", "exit_code"))
    actual = _json_lookup(ctx.details, key)
    expected = int(spec.get("equals", 0))
    return actual == expected, f"exit code {actual}, expected {expected}"


# --------------------------------------------------------------------------- live system checks
@register_check("port_open")
def _port_open(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    host = str(spec.get("host", "127.0.0.1"))
    if host not in {"127.0.0.1", "localhost", "::1"}:
        return False, "port checks are limited to the local machine"
    port = int(spec["port"])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(float(spec.get("timeout", 2)))
        open_ = sock.connect_ex((host, port)) == 0
    return open_, f"{host}:{port} {'accepting connections' if open_ else 'closed'}"


@register_check("http_status")
def _http_status(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    url = str(spec["url"])
    if ctx.url_allowed is None or not ctx.url_allowed(url):
        return False, f"{url} is outside the authorized target scope"
    expected = int(spec.get("status", 200))
    request = urllib.request.Request(url, method=str(spec.get("method", "GET")))
    try:
        with urllib.request.urlopen(request, timeout=float(spec.get("timeout", 15))) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    return status == expected, f"HTTP {status}, expected {expected}"


@register_check("process_running")
def _process_running(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    from .tools.process import process_running

    name = str(spec["name"])
    running = process_running(name)
    return running, f"process {name} {'running' if running else 'not running'}"


def _driver(ctx: CheckContext) -> Any:
    if ctx.ui_driver is not None:
        return ctx.ui_driver
    from .desktop.uia import PywinautoDriver

    return PywinautoDriver()


@register_check("window_exists")
def _window_exists(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    selector = {k: v for k, v in spec.items() if k in {"title", "title_re", "class_name", "process"}}
    window = _driver(ctx).find_window(selector, timeout=float(spec.get("timeout", 5)))
    return window is not None, f"window {selector} {'found' if window is not None else 'not found'}"


@register_check("ui_text_contains")
def _ui_text_contains(spec: dict[str, Any], ctx: CheckContext) -> tuple[bool, str]:
    driver = _driver(ctx)
    window = driver.find_window(spec["window"], timeout=float(spec.get("timeout", 5)))
    if window is None:
        return False, f"window {spec['window']} not found"
    control = driver.find_control(window, spec["control"], timeout=float(spec.get("timeout", 5))) if spec.get("control") else window
    if control is None:
        return False, f"control {spec.get('control')} not found"
    text = driver.read_text(control)
    return str(spec["value"]) in text, f"{spec['value']!r} {'visible' if str(spec['value']) in text else 'not visible'}"
