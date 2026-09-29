"""Evidence registry with relative paths, integrity hashes, and file validation."""

from __future__ import annotations

import json
from pathlib import Path

from .models import EvidenceItem
from .workspace import sha256_file


def registry_path(workspace: Path) -> Path:
    return workspace / "evidence" / "registry.json"


def list_evidence(workspace: Path) -> list[EvidenceItem]:
    path = registry_path(workspace)
    if not path.exists():
        return []
    return [EvidenceItem.model_validate(item) for item in json.loads(path.read_text(encoding="utf-8"))]


def register_evidence(workspace: Path, path: Path, description: str, evidence_type: str = "file",
                      step_id: int | None = None, verified: bool = True) -> EvidenceItem:
    resolved = path.resolve()
    base = workspace.resolve()
    if not resolved.is_relative_to(base):
        raise ValueError("Evidence must be stored inside the assignment workspace.")
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    entries = list_evidence(workspace)
    item = EvidenceItem(id=f"EV-{len(entries) + 1:04d}", type=evidence_type,
                        step_id=step_id, path=resolved.relative_to(base).as_posix(),
                        description=description, verified=verified, sha256=sha256_file(resolved))
    entries.append(item)
    registry_path(workspace).write_text(json.dumps([e.model_dump(mode="json") for e in entries], indent=2), encoding="utf-8")
    return item


def validate_evidence(workspace: Path) -> list[dict[str, object]]:
    results = []
    for item in list_evidence(workspace):
        path = (workspace / item.path).resolve()
        exists = path.is_relative_to(workspace.resolve()) and path.is_file()
        current = sha256_file(path) if exists else None
        results.append({"id": item.id, "path": item.path, "exists": exists,
                        "hash_matches": current == item.sha256 if current else False,
                        "verified": item.verified and exists and current == item.sha256})
    return results
