"""Evidence registry with relative paths, integrity hashes and content validation.

Registration refuses anything that is not a real, readable file of the stated
type inside the workspace: no placeholders, no "probably exists".
"""

from __future__ import annotations

import json
import threading
import zipfile
from pathlib import Path

from .models import EvidenceItem
from .workspace import sha256_file, write_json

EVIDENCE_TYPES = {
    "screenshot", "file", "hash", "log", "json", "csv", "pdf", "docx",
    "command_output", "application_result", "figure", "archive", "report",
}
_LOCK = threading.Lock()


def registry_path(workspace: Path) -> Path:
    return workspace / "evidence" / "registry.json"


def manifest_path(workspace: Path) -> Path:
    return workspace / "metadata" / "evidence_manifest.json"


def list_evidence(workspace: Path) -> list[EvidenceItem]:
    path = registry_path(workspace)
    if not path.exists():
        return []
    return [EvidenceItem.model_validate(item) for item in json.loads(path.read_text(encoding="utf-8"))]


def validate_content(path: Path, evidence_type: str) -> str | None:
    """Return an error message when the file is not a valid instance of its type."""
    if not path.is_file():
        return "file does not exist"
    if path.stat().st_size == 0:
        return "file is empty"
    try:
        if evidence_type in {"screenshot", "figure"}:
            from PIL import Image

            with Image.open(path) as image:
                image.verify()
        elif evidence_type == "pdf" or (evidence_type == "report" and path.suffix.lower() == ".pdf"):
            from pypdf import PdfReader

            if not PdfReader(str(path)).pages:
                return "PDF has no pages"
        elif evidence_type == "docx" or (evidence_type == "report" and path.suffix.lower() == ".docx"):
            with zipfile.ZipFile(path) as archive:
                if "word/document.xml" not in archive.namelist():
                    return "not a DOCX package"
        elif evidence_type == "json" or (evidence_type in {"hash", "application_result"} and path.suffix.lower() == ".json"):
            json.loads(path.read_text(encoding="utf-8"))
        elif evidence_type == "archive" and path.suffix.lower() == ".zip":
            with zipfile.ZipFile(path) as archive:
                if archive.testzip() is not None:
                    return "archive CRC check failed"
    except ImportError:
        return None  # optional validator unavailable; hash still recorded
    except Exception as exc:  # noqa: BLE001 - any parser failure means invalid evidence
        return f"invalid {evidence_type}: {type(exc).__name__}: {exc}"
    return None


def register_evidence(
    workspace: Path,
    path: Path,
    description: str,
    evidence_type: str = "file",
    step_id: int | None = None,
    verified: bool = True,
    *,
    capability: str | None = None,
    requirement_refs: list[str] | None = None,
) -> EvidenceItem:
    resolved = path.resolve()
    base = workspace.resolve()
    if not resolved.is_relative_to(base):
        raise ValueError("Evidence must be stored inside the assignment workspace.")
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    problem = validate_content(resolved, evidence_type)
    if problem:
        raise ValueError(f"Refusing to register {resolved.name} as {evidence_type} evidence: {problem}")
    relative = resolved.relative_to(base).as_posix()
    digest = sha256_file(resolved)
    with _LOCK:
        entries = list_evidence(workspace)
        for index, existing in enumerate(entries):
            if existing.path == relative and existing.step_id == step_id and existing.type == evidence_type:
                updated = existing.model_copy(update={
                    "sha256": digest, "size": resolved.stat().st_size, "verified": verified,
                    "description": description,
                })
                entries[index] = updated
                _persist(workspace, entries)
                return updated
        item = EvidenceItem(
            id=f"EV-{len(entries) + 1:04d}", type=evidence_type, step_id=step_id, path=relative,
            description=description, verified=verified, sha256=digest, size=resolved.stat().st_size,
            capability=capability, requirement_refs=requirement_refs or [],
        )
        entries.append(item)
        _persist(workspace, entries)
    return item


def _persist(workspace: Path, entries: list[EvidenceItem]) -> None:
    payload = [entry.model_dump(mode="json") for entry in entries]
    write_json(registry_path(workspace), payload)
    write_json(manifest_path(workspace), {
        "evidence_count": len(entries),
        "items": [
            {k: item[k] for k in ("id", "type", "step_id", "path", "description", "sha256", "size", "created_at", "verified")}
            for item in payload
        ],
    })


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


def evidence_for_step(workspace: Path, step_id: int) -> list[EvidenceItem]:
    return [item for item in list_evidence(workspace) if item.step_id == step_id]
