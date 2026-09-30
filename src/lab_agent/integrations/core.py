"""Core capabilities that do not belong to a third-party application."""

from __future__ import annotations

import csv
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..tools.screenshot import take_screenshot
from ..workspace import calculate_hashes
from .base import (
    BaseIntegration,
    Capability,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_str,
)

ScreenshotFn = Callable[..., Path]
_HEX64 = re.compile(r"\b[0-9a-fA-F]{64}\b")


class CoreAdapter(BaseIntegration):
    name = "core"
    CAPABILITIES = (
        Capability(
            name="core.hash_inputs", tool="core",
            description="Calculate MD5, SHA-1 and SHA-256 for every supplied input file and write input_hashes.csv/json",
            evidence_types=("hash",),
            verification="every input file hashed; result files exist",
            keywords=("sha256", "sha-256", "hash", "хеш", "хэш", "контрольн", "checksum", "md5"),
        ),
        Capability(
            name="core.hash_file", tool="core",
            description="Calculate MD5, SHA-1 and SHA-256 of one workspace file",
            parameters=(Param("path", "path", True, "workspace-relative file"),),
            evidence_types=("hash",), verification="hash file written",
        ),
        Capability(
            name="core.verify_hash", tool="core",
            description="Compare a file's hash with an expected value or a .sha256 file",
            parameters=(Param("path", "path", True), Param("expected", "str", False, "hex digest"),
                        Param("expected_file", "path", False, "file containing the digest, e.g. evidence.dd.sha256"),
                        Param("algorithm", "str", False, "sha256|sha1|md5", choices=("sha256", "sha1", "md5"))),
            evidence_types=("hash",), verification="computed digest equals the expected digest",
        ),
        Capability(
            name="core.screenshot", tool="core",
            description="Capture the target application window (or the desktop) as screenshot evidence",
            parameters=(Param("name", "str", False, "file name .png"), Param("description", "str"),
                        Param("window_title_re", "str", False, "regex of the window to focus and capture")),
            evidence_types=("screenshot",), verification="valid PNG image registered",
            keywords=("screenshot", "screen shot", "скриншот", "снимок экрана"),
        ),
        Capability(
            name="core.manual_review", tool="core",
            description="Stop and ask the student to perform/confirm something that cannot be automated safely",
            parameters=(Param("reason", "str"),),
            verification="never auto-completes; requires user confirmation",
        ),
    )

    def __init__(self, screenshot_fn: ScreenshotFn = take_screenshot) -> None:
        self._screenshot_fn = screenshot_fn

    def hash_inputs(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        files = sorted(p for p in (context.workspace / "input").rglob("*") if p.is_file())
        if not files:
            return IntegrationResult.failed("No input files found in workspace/input.")
        rows = []
        for path in files:
            digests = calculate_hashes(path)
            rows.append({"file": path.relative_to(context.workspace).as_posix(), "size": path.stat().st_size, **digests})
        output = context.save_result("input_hashes.json", {row["file"]: row for row in rows})
        table = context.folder("results") / "input_hashes.csv"
        with table.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["file", "size", "md5", "sha1", "sha256"])
            writer.writeheader()
            writer.writerows(rows)
        checks: list[dict[str, Any]] = [{"type": "file_exists", "path": "results/input_hashes.json"},
                  {"type": "csv_rows", "path": "results/input_hashes.csv", "min": len(rows), "columns": ["file", "sha256"]}]
        checks += [{"type": "hash_match", "path": row["file"], "expected": row["sha256"]} for row in rows[:20]]
        return IntegrationResult(
            verified=True,
            details={"hashes": {row["file"]: row for row in rows}, "output": str(output), "count": len(rows)},
            evidence=[evidence(output, "MD5/SHA-1/SHA-256 of all input files", "hash"),
                      evidence(table, "Input hash table (CSV)", "csv")],
            checks=checks,
        )

    def hash_file(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        target = context.resolve(param_str(parameters, "path"), base="input")
        digests = calculate_hashes(target)
        relative = target.relative_to(context.workspace.resolve()).as_posix()
        output = context.save_result(f"{target.name}.hashes.json", {"file": relative, "size": target.stat().st_size, **digests})
        return IntegrationResult(
            verified=True, details={"file": relative, **digests},
            evidence=[evidence(output, f"Hashes of {relative}", "hash")],
            checks=[{"type": "hash_match", "path": relative, "expected": digests["sha256"]}],
        )

    def verify_hash(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        target = context.resolve(param_str(parameters, "path"), base="input")
        algorithm = param_str(parameters, "algorithm", "sha256").lower() or "sha256"
        expected = param_str(parameters, "expected").lower()
        source = "parameter"
        if not expected:
            expected_file = param_str(parameters, "expected_file") or f"{target.name}.{algorithm}"
            reference = context.resolve(expected_file, base="input") if expected_file else None
            match = _HEX64.search(reference.read_text(encoding="utf-8", errors="replace")) if reference else None
            if match is None or reference is None:
                return IntegrationResult.failed(f"No expected {algorithm} digest found in {expected_file}.")
            expected, source = match.group(0).lower(), reference.relative_to(context.workspace.resolve()).as_posix()
        actual = calculate_hashes(target)[algorithm]
        matches = actual == expected
        relative = target.relative_to(context.workspace.resolve()).as_posix()
        output = context.save_result(f"{target.name}.{algorithm}_verification.txt",
                                     f"file: {relative}\nalgorithm: {algorithm}\nexpected ({source}): {expected}\n"
                                     f"actual: {actual}\nresult: {'MATCH' if matches else 'MISMATCH'}\n")
        return IntegrationResult(
            verified=matches,
            details={"file": relative, "expected": expected, "actual": actual, "match": matches,
                     **({} if matches else {"reason": f"{algorithm} mismatch for {relative}"})},
            evidence=[evidence(output, f"{algorithm.upper()} verification of {relative}", "hash")],
            checks=[{"type": "hash_match", "path": relative, "expected": expected, "algorithm": algorithm}],
        )

    def screenshot(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        name = param_str(parameters, "name") or f"step_{(context.step_id or 0):02d}_{context.stamp()}.png"
        window = param_str(parameters, "window_title_re") or None
        try:
            picture = self._screenshot_fn(context.workspace, name=name, window_title_re=window)
        except TypeError:
            picture = self._screenshot_fn(context.workspace, name=name)
        return IntegrationResult(
            verified=True,
            details={"screenshot": str(picture), "window": window},
            evidence=[evidence(picture, param_str(parameters, "description") or "Captured screen evidence", "screenshot")],
            checks=[{"type": "image_valid", "path": str(picture)}],
        )

    def manual_review(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        return IntegrationResult.blocked_result(param_str(parameters, "reason") or "Manual verification required")


def create_adapters(services: Any) -> list[CoreAdapter]:
    return [CoreAdapter(screenshot_fn=services.screenshot_fn)]
