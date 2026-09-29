from pathlib import Path

from lab_agent.automation import autopsy_e2e_operation


def test_autopsy_e2e_uses_workspace_image_and_verifies_success(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "input").mkdir(parents=True)
    (workspace / "working").mkdir()
    (workspace / "logs").mkdir()
    (workspace / "screenshots").mkdir()
    (workspace / "results").mkdir()
    image = workspace / "input" / "evidence.dd"
    image.write_bytes(b"fake-image")

    executable = tmp_path / "autopsy64.exe"
    executable.write_bytes(b"fake-executable")
    monkeypatch.setenv("LAB_AGENT_AUTOPSY_PATH", str(executable))
    monkeypatch.setattr("lab_agent.automation.launch_application", lambda *args, **kwargs: type("P", (), {"pid": 1234})())

    class Completed:
        returncode = 0
        stdout = "ingest complete"
        stderr = ""

    monkeypatch.setattr("lab_agent.automation.subprocess.run", lambda *args, **kwargs: Completed())
    monkeypatch.setattr(
        "lab_agent.automation._discover_case",
        lambda cases_dir, case_name: cases_dir / f"{case_name}_2026",
    )
    monkeypatch.setattr(
        "lab_agent.automation.take_screenshot",
        lambda workspace, *, name=None: (
            workspace / "screenshots" / (name or "screen.png")
        ),
    )
    result = autopsy_e2e_operation(workspace, "Assignment_3")

    assert result["verified"] is True
    assert result["data_source"].endswith("evidence.dd")
    assert result["case_dir"].endswith("_2026")
    assert Path(result["command_log"]).is_file()
