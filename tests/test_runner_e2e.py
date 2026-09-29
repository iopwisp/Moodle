from pathlib import Path

from PIL import Image

from lab_agent.database import RunDatabase
from lab_agent.runner import run_assignment


def test_assignment_runs_to_reports_with_screenshots(tmp_path: Path, monkeypatch) -> None:
    assignment = tmp_path / "assignment.txt"
    assignment.write_text("1. Рассчитать SHA256 хеш\n2. Сделать скриншот результата\n", encoding="utf-8")

    def fake_screenshot(workspace: Path, *, name: str | None = None) -> Path:
        output = workspace / "screenshots" / (name or "screen.png")
        output.parent.mkdir(parents=True, exist_ok=True)
        Image.new("RGB", (64, 48), color=(30, 78, 120)).save(output)
        return output

    monkeypatch.setattr("lab_agent.runner.take_screenshot", fake_screenshot)
    workspace, state, planner = run_assignment([assignment], tmp_path / "workspaces", provider="deterministic")

    assert planner == "deterministic"
    assert state.status == "COMPLETED"
    assert (workspace / "reports" / "assignment_Report.docx").is_file()
    assert (workspace / "reports" / "assignment_Report.pdf").is_file()
    assert len(list((workspace / "screenshots").glob("*.png"))) >= 2
    events = RunDatabase(workspace).events(state.run_id or state.assignment)
    assert any(item["event_type"] == "report.completed" for item in events)
