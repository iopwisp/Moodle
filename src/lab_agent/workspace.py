"""Creation of per-assignment workspace folders and immutable input copies."""

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


def create_workspace(analysis: AssignmentAnalysis, plan: ExecutionPlan, root: Path, copy_inputs: bool = True) -> Path:
    """Create an assignment workspace; source files are copied, never edited."""
    name = safe_assignment_name(Path(analysis.assignment))
    workspace = root.expanduser().resolve() / name
    if (workspace / "state" / "state.json").exists():
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        workspace = workspace.with_name(f"{name}_{stamp}")
    workspace.mkdir(parents=True, exist_ok=True)
    for name in WORKSPACE_DIRS:
        (workspace / name).mkdir(exist_ok=True)
    manifest: list[dict[str, str]] = []
    for source_text in analysis.source_files:
        source = Path(source_text)
        digest = sha256_file(source)
        target = workspace / "input" / source.name
        if copy_inputs and source.resolve() != target.resolve():
            if target.exists() and sha256_file(target) != digest:
                target = workspace / "input" / f"{source.stem}_{digest[:8]}{source.suffix}"
            if not target.exists():
                shutil.copy2(source, target)
        manifest.append({"source": str(source), "workspace_copy": str(target), "sha256": digest})
    (workspace / "metadata" / "input_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (workspace / "metadata" / "assignment_analysis.json").write_text(analysis.model_dump_json(indent=2), encoding="utf-8")
    (workspace / "metadata" / "execution_plan.json").write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    state = RunState(assignment=analysis.assignment, source_path=str(Path(analysis.source_files[0]).parent),
                     workspace_path=str(workspace), plan=plan)
    save_state(workspace, state)
    from .database import RunDatabase
    RunDatabase(workspace).sync_state(state)
    return workspace


def save_state(workspace: Path, state: RunState) -> None:
    state.updated_at = datetime.now(UTC)
    target = workspace / "state" / "state.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(state.model_dump_json(indent=2), encoding="utf-8")
    temporary.replace(target)


def load_state(workspace: Path) -> RunState:
    path = workspace / "state" / "state.json"
    return RunState.model_validate_json(path.read_text(encoding="utf-8"))
