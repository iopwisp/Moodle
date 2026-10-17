"""Synthetic image fixtures test validation only; they are not application evidence."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fakes import fake_screenshot
from PIL import Image

from lab_agent.context import workspace_context
from lab_agent.delivery import review_workspace
from lab_agent.evidence import register_evidence
from lab_agent.orchestration import orchestrate_assignment
from lab_agent.screenshot_review import CHECKLIST


@pytest.fixture
def lab(tmp_path, config, registry):
    source = tmp_path / "assignment.txt"
    source.write_text("1. Calculate SHA256 hash of input files.\n", encoding="utf-8")
    result = orchestrate_assignment([source], tmp_path / "runs", execute=True, config=config,
                                    registry=registry, environment={"applications": {}}, generate_report=False)
    ws = Path(result["workspace"])
    assert review_workspace(ws)["ready"]
    return ws


def _demand(ws, requirements):
    path = ws / "metadata/assignment_analysis.json"
    analysis = json.loads(path.read_text(encoding="utf-8"))
    analysis["screenshot_requirements"] = requirements
    path.write_text(json.dumps(analysis), encoding="utf-8")


def _image(ws, name, refs=(), *, different=False):
    path = fake_screenshot(ws, name=name)
    if different:
        with Image.open(path) as picture:
            picture.putpixel((0, 0), (255, 0, 0))
            picture.save(path)
    return register_evidence(ws, path, "Synthetic validation fixture", "screenshot", 1,
                              requirement_refs=list(refs))


def test_missing_screenshots_block_ready_even_when_steps_completed(lab):
    _demand(lab, ["Screenshot of the initial result", "Screenshot after the change"])
    (lab / CHECKLIST).unlink()
    review = review_workspace(lab)
    assert not review["ready"]
    assert len(review["screenshot_coverage"]["requirements"]) == 2
    assert workspace_context(lab)["screenshots"]["uncovered"] == ["assignment:1", "assignment:2"]


def test_unrelated_image_is_not_requirement_coverage(lab):
    _demand(lab, ["Screenshot of the final result"])
    _image(lab, "unrelated.png")
    assert review_workspace(lab)["screenshot_count"] == 1
    assert not review_workspace(lab)["ready"]


def test_each_required_state_needs_a_link_and_valid_image(lab):
    before, after = "Screenshot before change", "Screenshot after change"
    _demand(lab, ["1. " + before, "2. " + after])
    _image(lab, "before.png", [before])
    assert not review_workspace(lab)["ready"]
    last = _image(lab, "after.png", [after], different=True)
    assert review_workspace(lab)["ready"]
    (lab / last.path).write_bytes(b"damaged fixture")
    assert not review_workspace(lab)["ready"]
    assert workspace_context(lab, verify=True)["screenshots"]["ready"] is False


def test_duplicate_pngs_cannot_satisfy_minimum(lab):
    first = _image(lab, "first.png")
    copy = lab / "screenshots/copy.png"
    shutil.copy2(lab / first.path, copy)
    second = register_evidence(lab, copy, "Duplicate fixture", "screenshot", 1)
    spec = {"version": 1, "requirements": [{"id": "result", "requirement": "Two distinct observations",
             "minimum": 2, "evidence_ids": [first.id, second.id]}]}
    (lab / CHECKLIST).write_text(json.dumps(spec), encoding="utf-8")
    result = review_workspace(lab)
    assert not result["ready"]
    assert result["screenshot_coverage"]["requirements"][0]["matched"] == 1
    third = _image(lab, "third.png", different=True)
    spec["requirements"][0]["evidence_ids"].append(third.id)
    (lab / CHECKLIST).write_text(json.dumps(spec), encoding="utf-8")
    assert review_workspace(lab)["ready"]


def test_invalid_checklist_fails_closed(lab):
    (lab / CHECKLIST).write_text('{"requirements":[{"id":"S1","requirement":"Result","minimum":0}]}',
                                encoding="utf-8")
    assert not review_workspace(lab)["ready"]
    assert "error" in workspace_context(lab)["screenshots"]


def test_custom_checklist_cannot_remove_original_requirements(lab):
    _demand(lab, ["Required original screenshot"])
    image = _image(lab, "extra.png")
    (lab / CHECKLIST).write_text(json.dumps({"requirements": [{"id": "extra",
        "requirement": "An additional practical result", "evidence_ids": [image.id]}]}), encoding="utf-8")
    review = review_workspace(lab)
    assert not review["ready"]
    assert len(review["screenshot_coverage"]["requirements"]) == 2
