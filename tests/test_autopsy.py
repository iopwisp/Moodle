from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fakes import FakeDriver, FakeWindow, fake_screenshot

from lab_agent.integrations.base import ExecutionContext
from lab_agent.tools.process import CommandResult
from lab_agent.verification import CheckContext, run_checks

IMAGE_BYTES = b"\x00" * 512 + b"secret budget data" + b"\x00" * 494


class FakeAutopsy:
    """Imitates the side effects of ``autopsy64.exe`` command-line mode."""

    def __init__(self, *, ingest_status: int = 2, exit_code: int = 0) -> None:
        self.ingest_status = ingest_status
        self.exit_code = exit_code
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **kwargs: object) -> CommandResult:
        self.commands.append(command)
        options = {part.split("=", 1)[0]: part.split("=", 1)[1] for part in command if part.startswith("--") and "=" in part}
        flags = set(command)
        if self.exit_code:
            return CommandResult(command, self.exit_code, "", "ingest failed", 0.1)
        if "--createCase" in flags:
            case_dir = Path(options["--caseBaseDir"]) / f"{options['--caseName']}_20260930_101010"
            case_dir.mkdir(parents=True)
            (case_dir / f"{options['--caseName']}.aut").write_text("<AutopsyCase/>")
            self._schema(case_dir / "autopsy.db")
        else:
            case_dir = Path(options["--caseDir"])
        db = case_dir / "autopsy.db"
        with sqlite3.connect(db) as connection:
            if "--addDataSource" in flags:
                source = options["--dataSourcePath"]
                connection.execute("INSERT INTO data_source_info VALUES (1, 'dev-1', 'UTC')")
                connection.execute("INSERT INTO tsk_image_names VALUES (1, ?, 0)", (source,))
                connection.execute("INSERT INTO tsk_files VALUES (2, 'secret_budget.xlsx', '/', 18, NULL, 1, 1, 1, 0)")
                connection.execute("INSERT INTO tsk_file_layout VALUES (2, 512, 18, 0)")
                connection.execute("INSERT INTO tsk_files VALUES (3, 'Unalloc_1', '/$Unalloc/', 494, NULL, 1, 1, 1, 4)")
            if "--runIngest" in flags:
                connection.execute("INSERT INTO ingest_jobs VALUES (1, 1, 'host', 0, 1, ?, '')", (self.ingest_status,))
                connection.execute("INSERT INTO blackboard_artifacts VALUES (1, 2, 9)")
        if "--generateReports" in flags:
            reports = case_dir / "Reports" / "HTML Report"
            reports.mkdir(parents=True, exist_ok=True)
            (reports / "report.html").write_text("<html>Autopsy report</html>")
        return CommandResult(command, 0, "Ingest completed", "", 1.0)

    @staticmethod
    def _schema(path: Path) -> None:
        with sqlite3.connect(path) as connection:
            connection.executescript("""
            CREATE TABLE data_source_info (obj_id INTEGER, device_id TEXT, time_zone TEXT);
            CREATE TABLE tsk_image_names (obj_id INTEGER, name TEXT, sequence INTEGER);
            CREATE TABLE tsk_files (obj_id INTEGER, name TEXT, parent_path TEXT, size INTEGER, md5 TEXT,
                                    dir_flags INTEGER, meta_flags INTEGER, data_source_obj_id INTEGER, type INTEGER);
            CREATE TABLE tsk_file_layout (obj_id INTEGER, byte_start INTEGER, byte_len INTEGER, sequence INTEGER);
            CREATE TABLE ingest_job_status_types (type_id INTEGER, type_name TEXT);
            INSERT INTO ingest_job_status_types VALUES (0,'Started'),(1,'Cancelled'),(2,'Completed');
            CREATE TABLE ingest_jobs (ingest_job_id INTEGER, obj_id INTEGER, host_name TEXT, start_date_time INTEGER,
                                      end_date_time INTEGER, status_id INTEGER, settings_dir TEXT);
            CREATE TABLE blackboard_artifact_types (artifact_type_id INTEGER, display_name TEXT);
            INSERT INTO blackboard_artifact_types VALUES (9, 'Keyword Hits');
            CREATE TABLE blackboard_artifacts (artifact_id INTEGER, obj_id INTEGER, artifact_type_id INTEGER);
            CREATE TABLE blackboard_attributes (artifact_id INTEGER, value_text TEXT);
            """)


@pytest.fixture
def autopsy_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ExecutionContext:
    (tmp_path / "input").mkdir()
    (tmp_path / "input" / "evidence.dd").write_bytes(IMAGE_BYTES)
    executable = tmp_path / "autopsy64.exe"
    executable.write_bytes(b"MZ")
    monkeypatch.setenv("LAB_AGENT_AUTOPSY_PATH", str(executable))
    return ExecutionContext(tmp_path, "Assignment_3", step_id=5, screenshot_fn=fake_screenshot)


def _verify(result, context: ExecutionContext) -> bool:
    report = run_checks(result.checks, CheckContext(context.workspace, details=result.details))
    return result.verified and report.passed


def test_ingest_is_verified_from_the_case_database(autopsy_context: ExecutionContext, registry, monkeypatch) -> None:
    fake = FakeAutopsy()
    monkeypatch.setattr("lab_agent.integrations.autopsy.run_command", fake)
    result = registry.execute("autopsy.ingest", {}, autopsy_context)
    assert _verify(result, autopsy_context), result.details
    assert result.details["ingest_completed"] and result.details["files"] == 2
    command = fake.commands[0]
    assert "--createCase" in command and "--runIngest" in command and "--nosplash" in command
    assert any(part.startswith("--dataSourcePath=") and part.endswith("evidence.dd") for part in command)

    inspect = registry.execute("autopsy.inspect_results", {}, autopsy_context)
    assert _verify(inspect, autopsy_context)
    search = registry.execute("autopsy.search_artifacts", {"query": "budget"}, autopsy_context)
    assert search.details["matches"] == 1
    exported = registry.execute("autopsy.export_artifact", {"name": "secret_budget.xlsx"}, autopsy_context)
    assert _verify(exported, autopsy_context)
    assert (autopsy_context.workspace / "results" / "autopsy_export_secret_budget.xlsx").read_bytes() == b"secret budget data"
    report = registry.execute("autopsy.generate_report", {}, autopsy_context)
    assert report.verified and (autopsy_context.workspace / "results" / "autopsy_report.html").is_file()


def test_ingest_prepares_case_base_dir_and_leaves_reports_to_their_own_step(
        autopsy_context: ExecutionContext, registry, monkeypatch) -> None:
    fake = FakeAutopsy()
    monkeypatch.setattr("lab_agent.integrations.autopsy.run_command", fake)
    assert registry.execute("autopsy.ingest", {}, autopsy_context).verified
    command = fake.commands[0]
    assert "--generateReports" not in command
    base = next(part.split("=", 1)[1] for part in command if part.startswith("--caseBaseDir="))
    assert Path(base).is_dir()


def test_report_without_command_line_profile_is_blocked(autopsy_context: ExecutionContext, registry, monkeypatch) -> None:
    from lab_agent.integrations.base import CapabilityBlocked

    fake = FakeAutopsy()
    monkeypatch.setattr("lab_agent.integrations.autopsy.run_command", fake)
    assert registry.execute("autopsy.ingest", {}, autopsy_context).verified

    def no_profile(command: list[str], **kwargs: object) -> CommandResult:
        return CommandResult(command, 1, "", "Error loading reporting configuration CommandLineIngest", 0.1)

    monkeypatch.setattr("lab_agent.integrations.autopsy.run_command", no_profile)
    try:
        result = registry.execute("autopsy.generate_report", {}, autopsy_context)
    except CapabilityBlocked as blocked:  # depending on how the registry surfaces it
        assert "Generate Report" in str(blocked)
    else:
        assert result.blocked and not result.verified
        assert "Generate Report" in result.reason


def test_unfinished_ingest_is_not_verified(autopsy_context: ExecutionContext, registry, monkeypatch) -> None:
    monkeypatch.setattr("lab_agent.integrations.autopsy.run_command", FakeAutopsy(ingest_status=0))
    result = registry.execute("autopsy.ingest", {}, autopsy_context)
    assert not _verify(result, autopsy_context)
    assert "not all completed" in result.details["reason"]


def test_failed_exit_code_fails(autopsy_context: ExecutionContext, registry, monkeypatch) -> None:
    monkeypatch.setattr("lab_agent.integrations.autopsy.run_command", FakeAutopsy(exit_code=1))
    assert not registry.execute("autopsy.ingest", {}, autopsy_context).verified


def test_step_by_step_capabilities(autopsy_context: ExecutionContext, registry, monkeypatch) -> None:
    monkeypatch.setattr("lab_agent.integrations.autopsy.run_command", FakeAutopsy())
    assert _verify(registry.execute("autopsy.create_case", {"case_name": "lab3"}, autopsy_context), autopsy_context)
    assert _verify(registry.execute("autopsy.add_data_source", {"data_source": "input/evidence.dd"}, autopsy_context), autopsy_context)
    assert registry.execute("autopsy.configure_ingest", {"profile": "Carving"}, autopsy_context).verified
    started = registry.execute("autopsy.start_ingest", {}, autopsy_context)
    assert _verify(started, autopsy_context)
    assert _verify(registry.execute("autopsy.wait_for_completion", {}, autopsy_context), autopsy_context)


def test_missing_autopsy_is_blocked(tmp_path: Path, registry, monkeypatch) -> None:
    monkeypatch.delenv("LAB_AGENT_AUTOPSY_PATH", raising=False)
    monkeypatch.setattr("lab_agent.environment.discover_app",
                        lambda spec, config=None, entries=None: type("I", (), {"available": False, "path": None})())
    (tmp_path / "input").mkdir()
    (tmp_path / "input" / "evidence.dd").write_bytes(IMAGE_BYTES)
    from lab_agent.integrations.base import CapabilityBlocked

    with pytest.raises(CapabilityBlocked):
        registry.execute("autopsy.ingest", {}, ExecutionContext(tmp_path, "A3"))


def test_gui_evidence_uses_window(autopsy_context: ExecutionContext, registry, monkeypatch) -> None:
    monkeypatch.setattr("lab_agent.integrations.autopsy.run_command", FakeAutopsy())
    registry.execute("autopsy.ingest", {}, autopsy_context)
    driver = FakeDriver()
    driver.add_window(FakeWindow("Autopsy 4.21.0 - Assignment_3_agent"))
    monkeypatch.setattr("lab_agent.applications.default_driver", lambda: driver)
    launched = []
    monkeypatch.setattr("lab_agent.applications.launch_application",
                        lambda exe, args, cwd=None: launched.append(args) or type("P", (), {"pid": 1, "poll": lambda self: None})())
    result = registry.execute("autopsy.open_case_gui", {}, autopsy_context)
    assert result.verified and result.evidence[0]["type"] == "screenshot"
    assert launched and launched[0][0].endswith(".aut")
