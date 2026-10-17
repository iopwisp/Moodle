"""Match screenshot requirements to registered images, not just an image count."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .analyzer import NUMBERED_RE
from .models import EvidenceItem
from .workspace import load_state, write_json

CHECKLIST = Path("metadata/screenshot_checklist.json")


class ScreenshotRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    requirement: str = Field(min_length=1)
    minimum: int = Field(default=1, ge=1, le=100)
    evidence_ids: list[str] = Field(default_factory=list)


class ScreenshotChecklist(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, ge=1, le=1)
    requirements: list[ScreenshotRequirement] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_ids(self) -> ScreenshotChecklist:
        if len({r.id for r in self.requirements}) != len(self.requirements):
            raise ValueError("Screenshot requirement ids must be unique")
        return self


def _key(text: str) -> str:
    return " ".join(NUMBERED_RE.sub("", text).split()).casefold()


def _original_requirements(workspace: Path) -> list[str]:
    path = workspace / "metadata/assignment_analysis.json"
    analysis = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    return list(dict.fromkeys(analysis.get("screenshot_requirements", [])))


def prepare_screenshot_checklist(workspace: Path) -> None:
    path = workspace / CHECKLIST
    if not path.exists():
        spec = ScreenshotChecklist(requirements=[ScreenshotRequirement(id=f"S{i}", requirement=text)
                                   for i, text in enumerate(_original_requirements(workspace), 1)])
        write_json(path, spec.model_dump(mode="json"))


def review_screenshots(workspace: Path, valid_evidence: list[EvidenceItem]) -> dict[str, Any]:
    try:
        path = workspace / CHECKLIST
        spec = ScreenshotChecklist.model_validate_json(path.read_text(encoding="utf-8")) if path.exists() else ScreenshotChecklist()
        originals = _original_requirements(workspace)
    except (ValueError, OSError) as exc:
        return {"ready": False, "requirements": [], "error": str(exc)[:300]}
    demands = list(spec.requirements)
    known = {_key(r.requirement) for r in demands}
    # Deleting a checklist entry cannot erase a requirement extracted from the assignment.
    for index, text in enumerate(originals, 1):
        if _key(text) not in known:
            demands.append(ScreenshotRequirement(id=f"assignment:{index}", requirement=text))
    state = load_state(workspace)
    images = [e for e in valid_evidence if e.type == "screenshot"]
    result = []
    for demand in demands:
        matches = []
        for image in images:
            task = state.step(image.step_id) if image.step_id is not None else None
            refs = [*image.requirement_refs, *(task.requirement_refs if task else [])]
            linked = image.id in demand.evidence_ids or any(
                _key(ref) == _key(demand.requirement) or
                (len(ref) == 300 and _key(demand.requirement).startswith(_key(ref))) for ref in refs)
            if linked:
                matches.append(image)
        # Re-registering/copying the same PNG is not another observation.
        unique = {image.sha256 or image.path for image in matches}
        result.append({"id": demand.id, "requirement": demand.requirement[:300],
                       "minimum": demand.minimum, "matched": len(unique),
                       "evidence_ids": [image.id for image in matches],
                       "ready": len(unique) >= demand.minimum})
    return {"ready": all(r["ready"] for r in result), "requirements": result,
            "scope": "Integrity and requirement links only; inspect image content and report placement separately"}
