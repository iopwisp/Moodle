"""Creation of per-assignment workspace folders and immutable input copies.

Layout::

    workspace/<Assignment>/
      input/        byte-identical copies of the originals (never modified)
      working/      tool working directories (cases, extracted archives, ...)
      results/      files produced by capabilities
      screenshots/  captured windows / desktop
      evidence/     evidence registry
      logs/         execution.jsonl, commands.jsonl, ...
      metadata/     analysis, plan, input_manifest.json, evidence_manifest.json
      state/        state.json checkpoint + agent.db (SQLite)
      reports/      DOCX + PDF
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from .models import AssignmentAnalysis, ExecutionPlan, RunState, safe_assignment_name

WORKSPACE_DIRS = ("input", "working", "screenshots", "evidence", "results", "logs", "reports", "state", "metadata")


def sha256_file(path: Path) -> str:
    return file_hash(path, "sha256")


def file_hash(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def calculate_hashes(path: Path) -> dict[str, str]:
    digests = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def _mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat()


def build_input_manifest(sources: list[Path], workspace: Path, copy_inputs: bool = True) -> list[dict[str, object]]:
    """Copy originals into ``input/`` and record chain-of-custody metadata for each."""
    manifest: list[dict[str, object]] = []
    for source in sources:
        hashes = calculate_hashes(source)
        target = workspace / "input" / source.name
        if copy_inputs and source.resolve() != target.resolve():
            if target.exists() and sha256_file(target) != hashes["sha256"]:
                target = workspace / "input" / f"{source.stem}_{hashes['sha256'][:8]}{source.suffix}"
            if not target.exists():
                shutil.copy2(source, target)
            copied = sha256_file(target)
            if copied != hashes["sha256"]:
                raise OSError(f"Workspace copy of {source} does not match the original hash.")
        manifest.append({
            "source": str(source),
            "workspace_copy": str(target),
            "workspace_relative": target.relative_to(workspace).as_posix() if target.is_relative_to(workspace) else None,
            "size": source.stat().st_size,
            "mtime": _mtime(source),
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "sha256": hashes["sha256"],
            "acquired_at": datetime.now(UTC).isoformat(),
        })
    return manifest


def create_workspace(analysis: AssignmentAnalysis, plan: ExecutionPlan, root: Path, copy_inputs: bool = True) -> Path:
    """Create an assignment workspace; source files are copied, never edited."""
    name = safe_assignment_name(Path(analysis.assignment))
    workspace = root.expanduser().resolve() / name
    if (workspace / "state" / "state.json").exists():
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        workspace = workspace.with_name(f"{name}_{stamp}")
    workspace.mkdir(parents=True, exist_ok=True)
    for folder in WORKSPACE_DIRS:
        (workspace / folder).mkdir(exist_ok=True)
    manifest = build_input_manifest([Path(p) for p in analysis.source_files], workspace, copy_inputs)
    manifest.extend(extract_archive_members(analysis, workspace))
    write_json(workspace / "metadata" / "input_manifest.json", manifest)
    (workspace / "metadata" / "assignment_analysis.json").write_text(analysis.model_dump_json(indent=2), encoding="utf-8")
    (workspace / "metadata" / "execution_plan.json").write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    state = RunState(
        assignment=analysis.assignment,
        source_path=str(Path(analysis.source_files[0]).parent),
        workspace_path=str(workspace),
        plan=plan,
        status="PLANNED",
    )
    save_state(workspace, state)
    from .database import RunDatabase

    RunDatabase(workspace).sync_state(state)
    return workspace


def extract_archive_members(analysis: AssignmentAnalysis, workspace: Path) -> list[dict[str, object]]:
    """Extract classified ZIP members to their planned ``working/extracted/...`` paths (traversal-safe)."""
    import zipfile

    entries: list[dict[str, object]] = []
    root = workspace.resolve()
    for item in analysis.files:
        if not item.archive or not item.workspace_path or "::" not in item.path:
            continue
        member = item.path.split("::", 1)[1]
        target = (workspace / item.workspace_path).resolve()
        if not target.is_relative_to(root / "working" / "extracted"):
            raise ValueError(f"Archive member escapes the workspace: {member}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(item.archive) as archive, archive.open(member) as source, target.open("wb") as sink:
            shutil.copyfileobj(source, sink, 1024 * 1024)
        hashes = calculate_hashes(target)
        if item.sha256 and hashes["sha256"] != item.sha256:
            raise OSError(f"Extracted member {member} does not match the analysed bytes")
        entries.append({
            "source": item.path, "workspace_copy": str(target), "workspace_relative": item.workspace_path,
            "derived_from": item.archive, "size": target.stat().st_size, "md5": hashes["md5"], "sha1": hashes["sha1"],
            "sha256": hashes["sha256"], "acquired_at": datetime.now(UTC).isoformat(),
        })
    return entries


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    temporary.replace(path)


def input_manifest(workspace: Path) -> list[dict[str, object]]:
    path = workspace / "metadata" / "input_manifest.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []


def verify_inputs_unchanged(workspace: Path) -> list[dict[str, object]]:
    """Re-hash originals and workspace copies against the acquisition manifest."""
    results: list[dict[str, object]] = []
    for entry in input_manifest(workspace):
        expected = str(entry["sha256"])
        source = Path(str(entry["source"]).split("::", 1)[0]) if not entry.get("derived_from") else Path("")
        copy = Path(str(entry["workspace_copy"]))
        results.append({
            "source": str(source),
            "expected_sha256": expected,
            "source_unchanged": sha256_file(source) == expected if str(source) not in {"", "."} and source.is_file() else None,
            "copy_unchanged": sha256_file(copy) == expected if copy.is_file() else False,
        })
    return results


def save_state(workspace: Path, state: RunState) -> None:
    state.updated_at = datetime.now(UTC)
    target = workspace / "state" / "state.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(state.model_dump_json(indent=2), encoding="utf-8")
    temporary.replace(target)


def load_state(workspace: Path) -> RunState:
    path = workspace / "state" / "state.json"
    return RunState.model_validate_json(path.read_text(encoding="utf-8"))
