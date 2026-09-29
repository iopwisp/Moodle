import zipfile
from pathlib import Path

import pytest

from lab_agent.analyzer import analyze, build_plan
from lab_agent.evidence import register_evidence, validate_evidence
from lab_agent.filesystem import copy_file, extract_zip, file_metadata, search_files
from lab_agent.workspace import create_workspace, load_state, save_state


def setup_workspace(tmp_path: Path) -> Path:
    assignment = tmp_path / "assignment.txt"
    assignment.write_text("Analyze the provided evidence and capture screenshot.\n", encoding="utf-8")
    result = analyze([assignment])
    return create_workspace(result, build_plan(result), tmp_path / "workspaces")


def test_workspace_copies_input_and_checkpoint_roundtrip(tmp_path: Path) -> None:
    workspace = setup_workspace(tmp_path)
    assert (workspace / "input" / "assignment.txt").read_text(encoding="utf-8").startswith("Analyze")
    state = load_state(workspace)
    state.status = "IN_PROGRESS"
    save_state(workspace, state)
    assert load_state(workspace).status == "IN_PROGRESS"


def test_evidence_hash_validation_detects_tampering(tmp_path: Path) -> None:
    workspace = setup_workspace(tmp_path)
    evidence_file = workspace / "results" / "result.txt"
    evidence_file.write_text("actual output", encoding="utf-8")
    register_evidence(workspace, evidence_file, "Recorded result")
    assert validate_evidence(workspace)[0]["verified"]
    evidence_file.write_text("changed output", encoding="utf-8")
    assert not validate_evidence(workspace)[0]["verified"]


def test_file_copy_confines_paths_and_checks_hash(tmp_path: Path) -> None:
    workspace = setup_workspace(tmp_path)
    result = copy_file(workspace, "input/assignment.txt", "working/copy.txt")
    assert result["status"] == "MATCH"
    with pytest.raises(ValueError):
        copy_file(workspace, "input/assignment.txt", "../outside.txt")
    assert search_files(workspace, "screenshot", "input") == ["input/assignment.txt"]
    assert file_metadata(workspace, "input/assignment.txt")["sha256"] == result["source_sha256"]


def test_zip_slip_is_rejected(tmp_path: Path) -> None:
    workspace = setup_workspace(tmp_path)
    archive = workspace / "input" / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zip_file:
        zip_file.writestr("../../outside.txt", "bad")
    with pytest.raises(ValueError):
        extract_zip(workspace, "input/unsafe.zip", "working/unpacked")
