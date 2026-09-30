from pathlib import Path

from fakes import fake_screenshot

from lab_agent.database import RunDatabase
from lab_agent.evidence import list_evidence
from lab_agent.runner import run_assignment


def test_assignment_runs_to_reports_with_screenshots(tmp_path: Path, monkeypatch) -> None:
    """Legacy entry point: default registry, default environment discovery, patched screenshot backend."""
    assignment = tmp_path / "assignment.txt"
    assignment.write_text("1. Рассчитать SHA256 хеш\n2. Сделать скриншот результата\n", encoding="utf-8")
    monkeypatch.setattr("lab_agent.runner.take_screenshot", fake_screenshot)
    workspace, state, planner = run_assignment([assignment], tmp_path / "workspaces", provider="deterministic")

    assert planner == "deterministic"
    assert state.status == "COMPLETED"
    assert (workspace / "reports" / "assignment_Report.docx").is_file()
    assert (workspace / "reports" / "assignment_Report.pdf").is_file()
    screenshots = [item for item in list_evidence(workspace) if item.type == "screenshot"]
    assert [item.step_id for item in screenshots] == [2]  # only the step that asked for a screenshot
    assert (workspace / "metadata" / "environment.json").is_file()
    events = RunDatabase(workspace).events(state.run_id or state.assignment)
    assert any(item["event_type"] == "report.completed" for item in events)


def test_screenshot_mode_all_captures_before_and_after(tmp_path: Path, config, registry) -> None:
    config.screenshots.mode = "all"
    assignment = tmp_path / "assignment.txt"
    assignment.write_text("1. Calculate SHA256 hash\n", encoding="utf-8")
    workspace, _, _ = run_assignment([assignment], tmp_path / "ws", "deterministic", config=config, registry=registry,
                                         screenshot_fn=fake_screenshot, environment={"applications": {}})
    names = sorted(Path(item.path).name for item in list_evidence(workspace) if item.type == "screenshot")
    assert names == ["step_01_after.png", "step_01_before.png"]
