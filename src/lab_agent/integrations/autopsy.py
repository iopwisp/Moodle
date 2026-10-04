"""Autopsy integration - the reference desktop forensic workflow.

Forensic work is driven through Autopsy's supported command-line mode
(``--createCase``, ``--addDataSource``, ``--runIngest``, ``--generateReports``),
which is deterministic and scriptable.  Results are verified by reading the
case database (``autopsy.db``, SQLite): data sources, finished ingest jobs,
files and blackboard artifacts.  The GUI is opened afterwards on the case's
``.aut`` file for window-targeted screenshots.  Any failure is reported; no
step is marked verified from the exit code alone.

Autopsy has no ``--caseDir`` option ("Unrecognized option", verified on 4.23.1):
an existing case is addressed by ``--caseBaseDir=<parent> --caseName=<name>``,
and Autopsy finds the timestamped case folder itself.
"""

from __future__ import annotations

import csv
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from ..tools.process import run_command
from .autopsy_story import AutopsyNarration
from .base import (
    AppSpec,
    BaseIntegration,
    Capability,
    CapabilityBlocked,
    ExecutionContext,
    IntegrationResult,
    Param,
    evidence,
    param_int,
    param_str,
)

FORENSIC_EXTENSIONS = {".dd", ".raw", ".img", ".001", ".e01", ".vmdk", ".vhd", ".vhdx", ".bin"}
AUTOPSY_SPEC = AppSpec(
    "autopsy", "Autopsy", env_var="LAB_AGENT_AUTOPSY_PATH", executables=("autopsy64.exe", "autopsy.exe", "autopsy"),
    install_globs=("Autopsy*/bin/autopsy64.exe", "Autopsy*/bin/autopsy.exe"), registry_name_re=r"^Autopsy",
    capabilities=("autopsy.*",),
)
INGEST_COMPLETED = {"completed", "2"}


def case_args(case_dir: Path) -> list[str]:
    """Command-line options that make Autopsy open the existing case in ``case_dir``."""
    aut = next(iter(sorted(case_dir.glob("*.aut"))), None)
    if aut is None:
        raise FileNotFoundError(f"No Autopsy case file (*.aut) in {case_dir}")
    return [f"--caseBaseDir={case_dir.parent}", f"--caseName={aut.stem}"]


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "_", text)[:60].strip("_") or "case"


def case_database(case_dir: Path) -> Path:
    database = case_dir / "autopsy.db"
    if not database.is_file():
        raise FileNotFoundError(f"Autopsy case database not found in {case_dir}")
    return database


def case_summary(case_dir: Path) -> dict[str, Any]:
    """Read verifiable facts from an Autopsy case database (read-only)."""
    database = case_database(case_dir)
    with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        summary: dict[str, Any] = {"case_dir": str(case_dir), "database": str(database)}
        summary["data_sources"] = [dict(row) for row in connection.execute(
            "SELECT obj_id, device_id, time_zone FROM data_source_info")] if "data_source_info" in tables else []
        if "tsk_image_names" in tables:
            summary["image_paths"] = [row[0] for row in connection.execute("SELECT name FROM tsk_image_names")]
        summary["files"] = connection.execute("SELECT count(*) FROM tsk_files").fetchone()[0] if "tsk_files" in tables else 0
        if "tsk_files" in tables:
            summary["unallocated_or_carved"] = connection.execute(
                "SELECT count(*) FROM tsk_files WHERE name LIKE 'Unalloc%' OR parent_path LIKE '%$CarvedFiles%'").fetchone()[0]
        jobs: list[dict[str, Any]] = []
        if "ingest_jobs" in tables:
            if "ingest_job_status_types" in tables:
                rows = connection.execute(
                    "SELECT j.ingest_job_id, j.status_id, s.type_name AS status, j.start_date_time, j.end_date_time "
                    "FROM ingest_jobs j LEFT JOIN ingest_job_status_types s ON s.type_id = j.status_id")
            else:
                rows = connection.execute("SELECT ingest_job_id, status_id, status_id AS status, start_date_time, end_date_time FROM ingest_jobs")
            jobs = [dict(row) for row in rows]
        summary["ingest_jobs"] = jobs
        artifacts: dict[str, int] = {}
        if {"blackboard_artifacts", "blackboard_artifact_types"} <= tables:
            for row in connection.execute(
                "SELECT t.display_name AS name, count(*) AS n FROM blackboard_artifacts a "
                "JOIN blackboard_artifact_types t ON t.artifact_type_id = a.artifact_type_id GROUP BY t.display_name"):
                artifacts[row["name"]] = row["n"]
        summary["artifacts"] = artifacts
    summary["ingest_completed"] = bool(jobs) and all(str(job.get("status", "")).casefold() in INGEST_COMPLETED for job in jobs)
    return summary


def pending_data_sources(case_dir: Path) -> list[int]:
    """Object ids of data sources that have no completed ingest job yet."""
    with sqlite3.connect(f"file:{case_database(case_dir).as_posix()}?mode=ro", uri=True) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "data_source_info" not in tables:
            return []
        ids = [int(row[0]) for row in connection.execute("SELECT obj_id FROM data_source_info ORDER BY obj_id")]
        done = {int(row[0]) for row in connection.execute("SELECT obj_id FROM ingest_jobs WHERE status_id = 2")} \
            if "ingest_jobs" in tables else set()
    return [object_id for object_id in ids if object_id not in done]


class AutopsyAdapter(AutopsyNarration, BaseIntegration):
    name = "autopsy"
    APPLICATIONS = (AUTOPSY_SPEC,)
    CAPABILITIES = (
        Capability("autopsy.create_case", "autopsy", "Create a new Autopsy case with the command-line interface",
                   (Param("case_name", "str"),), ("log",), "case folder with .aut file and autopsy.db exists",
                   requires=("app:autopsy",), keywords=("case", "кейс", "дело")),
        Capability("autopsy.add_data_source", "autopsy", "Add a disk image as data source to the case",
                   (Param("data_source", "path"), Param("case_dir", "path")), ("log",),
                   "the image path is recorded as a data source in autopsy.db", requires=("app:autopsy",),
                   keywords=("data source", "образ", "image")),
        Capability("autopsy.configure_ingest", "autopsy", "Select the ingest profile passed to Autopsy (--ingestProfile)",
                   (Param("profile", "str", False, "Autopsy ingest profile name; default settings when empty"),), (),
                   "ingest profile recorded for the following start_ingest", requires=("app:autopsy",)),
        Capability("autopsy.start_ingest", "autopsy", "Run ingest modules on the case data sources and wait for them",
                   (Param("case_dir", "path"), Param("profile", "str")), ("log",),
                   "every ingest job in autopsy.db has status Completed", requires=("app:autopsy",), keywords=("ingest",)),
        Capability("autopsy.wait_for_completion", "autopsy", "Verify from the case database that ingest finished",
                   (Param("case_dir", "path"),), ("json",), "ingest jobs completed"),
        Capability("autopsy.ingest", "autopsy",
                   "One command: create case, add the image and run ingest",
                   (Param("data_source", "path"), Param("case_name", "str"), Param("profile", "str")), ("log",),
                   "case DB lists the data source and completed ingest jobs", requires=("app:autopsy",),
                   keywords=("autopsy", "ingest")),
        Capability("autopsy.inspect_results", "autopsy", "Summarise files and artifacts found by ingest (CSV/JSON)",
                   (Param("case_dir", "path"),), ("csv", "json"), "summary lists files > 0 and artifact counts"),
        Capability("autopsy.search_artifacts", "autopsy", "Search file names or artifact text in the case database",
                   (Param("query", "str", True), Param("case_dir", "path"), Param("limit", "int")), ("csv",),
                   "matching rows written (may be zero rows, reported as such)"),
        Capability("autopsy.export_artifact", "autopsy", "Extract a file's bytes from the image using its layout in autopsy.db",
                   (Param("name", "str", True, "file name as shown in Autopsy"), Param("case_dir", "path")), ("file",),
                   "exported bytes length equals the recorded file size"),
        Capability("autopsy.generate_report", "autopsy", "Generate Autopsy reports (--generateReports)",
                   (Param("case_dir", "path"),), ("report",), "Reports folder contains generated files", requires=("app:autopsy",)),
        Capability("autopsy.open_case_gui", "autopsy", "Open the case in the Autopsy GUI and capture its window",
                   (Param("case_dir", "path"),), ("screenshot",), "Autopsy window visible with the case", requires=("app:autopsy",)),
        Capability("autopsy.capture_evidence", "autopsy", "Screenshot of the Autopsy window", (Param("name", "str"),),
                   ("screenshot",), "valid window screenshot", requires=("app:autopsy",)),
        Capability("autopsy.e2e", "autopsy",
                   "Create case, add image, ingest, verify the case DB, generate report, open GUI and capture evidence",
                   (Param("data_source", "path"), Param("case_name", "str"), Param("profile", "str")),
                   ("screenshot", "log", "csv"), "case DB verified, report generated, window screenshot captured",
                   requires=("app:autopsy",), keywords=("autopsy",)),
    )

    def __init__(self) -> None:
        self._state_file = "autopsy_state.json"

    # ------------------------------------------------------------------ state
    def _state(self, context: ExecutionContext) -> dict[str, Any]:
        path = context.workspace / "working" / self._state_file
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}

    def _save_state(self, context: ExecutionContext, **values: Any) -> None:
        state = {**self._state(context), **values}
        (context.folder("working") / self._state_file).write_text(json.dumps(state, indent=2), encoding="utf-8")

    def _executable(self, context: ExecutionContext) -> str:
        from ..applications import ManagedApplication

        return ManagedApplication("autopsy", context, spec=AUTOPSY_SPEC).executable()

    def _cases_dir(self, context: ExecutionContext) -> Path:
        # Autopsy refuses to start when --caseBaseDir does not already exist.
        path = context.folder("working") / "autopsy_cases"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _case_dir(self, parameters: dict[str, Any], context: ExecutionContext) -> Path:
        value = param_str(parameters, "case_dir") or self._state(context).get("case_dir", "")
        if not value:
            raise CapabilityBlocked("No Autopsy case exists yet; run autopsy.create_case or autopsy.ingest first.")
        return context.resolve(value)

    def _data_source(self, parameters: dict[str, Any], context: ExecutionContext) -> Path:
        value = param_str(parameters, "data_source")
        if value:
            candidate = context.resolve(value, base="input")
        else:
            roots = [context.workspace / "working" / "evidence_copy", context.workspace / "input", context.workspace / "working" / "extracted"]
            found = [p for root in roots if root.is_dir() for p in sorted(root.rglob("*"))
                     if p.is_file() and p.suffix.lower() in FORENSIC_EXTENSIONS]
            if not found:
                raise FileNotFoundError("No forensic image (.dd/.e01/.raw/.img/...) in the workspace.")
            candidate = found[0]
        if candidate.suffix.lower() not in FORENSIC_EXTENSIONS:
            raise ValueError(f"Unsupported forensic image extension: {candidate.suffix}")
        return candidate

    def _run(self, context: ExecutionContext, args: list[str], label: str) -> tuple[dict[str, Any], Path]:
        import os

        executable = self._executable(context)
        timeout = float(os.environ.get("LAB_AGENT_AUTOPSY_TIMEOUT", "21600"))
        result = run_command([executable, "--nosplash", *args], cwd=context.workspace, timeout=timeout,
                             log_file=context.folder("logs") / "commands.jsonl")
        log = context.folder("logs") / f"autopsy_{label}.json"
        log.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return result.to_dict(), log

    def _discover_case(self, base: Path, case_name: str) -> Path:
        candidates = sorted((p for p in base.iterdir() if p.is_dir() and p.name.lower().startswith(case_name.lower())),
                            key=lambda p: p.stat().st_mtime) if base.is_dir() else []
        for candidate in reversed(candidates):
            if list(candidate.glob("*.aut")):
                return candidate
        raise RuntimeError(f"Autopsy did not create a case folder for {case_name} under {base}")

    def _case_checks(self, case_dir: Path, context: ExecutionContext, *, ingest: bool = False, source: bool = False) -> list[dict[str, Any]]:
        relative = case_dir.resolve().relative_to(context.workspace.resolve()).as_posix()
        checks: list[dict[str, Any]] = [{"type": "file_exists", "path": f"{relative}/autopsy.db"}]
        if source:
            checks.append({"type": "sqlite_query", "path": f"{relative}/autopsy.db", "query": "SELECT count(*) FROM data_source_info", "min": 1})
        if ingest:
            checks.append({"type": "sqlite_query", "path": f"{relative}/autopsy.db", "query": "SELECT count(*) FROM ingest_jobs", "min": 1})
            checks.append({"type": "sqlite_query", "path": f"{relative}/autopsy.db",
                           "query": "SELECT count(*) FROM ingest_jobs WHERE status_id <> 2", "equals": 0})
        return checks

    # ------------------------------------------------------------------ capabilities
    def create_case(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        case_name = _safe_name(param_str(parameters, "case_name") or f"{context.assignment}_agent")
        base = self._cases_dir(context)
        details, log = self._run(context, ["--createCase", f"--caseName={case_name}", f"--caseBaseDir={base}"], "create_case")
        if details["exit_code"] != 0:
            return IntegrationResult.failed(f"Autopsy --createCase exited with {details['exit_code']}", **details)
        case_dir = self._discover_case(base, case_name)
        self._save_state(context, case_dir=str(case_dir), case_name=case_name)
        return IntegrationResult(True, {"case_dir": str(case_dir), **details}, [evidence(log, "Autopsy create case log", "log")],
                                 checks=self._case_checks(case_dir, context))

    def add_data_source(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        case_dir = self._case_dir(parameters, context)
        source = self._data_source(parameters, context)
        details, log = self._run(context, [*case_args(case_dir), "--addDataSource", f"--dataSourcePath={source}"], "add_data_source")
        if details["exit_code"] != 0:
            return IntegrationResult.failed(f"Autopsy --addDataSource exited with {details['exit_code']}", **details)
        self._save_state(context, data_source=str(source))
        return IntegrationResult(True, {"case_dir": str(case_dir), "data_source": str(source), **details},
                                 [evidence(log, "Autopsy add data source log", "log")],
                                 checks=self._case_checks(case_dir, context, source=True))

    def configure_ingest(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        profile = param_str(parameters, "profile")
        self._save_state(context, ingest_profile=profile)
        record = context.save_result("autopsy_ingest_configuration.json",
                                     {"ingest_profile": profile or "(Autopsy default ingest settings)"})
        return IntegrationResult(True, {"ingest_profile": profile or None}, [evidence(record, "Selected ingest configuration", "json")],
                                 checks=[{"type": "file_exists", "path": "results/autopsy_ingest_configuration.json"}])

    def start_ingest(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        case_dir = self._case_dir(parameters, context)
        profile = param_str(parameters, "profile") or self._state(context).get("ingest_profile", "")
        # On an existing case Autopsy ingests one data source per call and needs its object id
        # ("'dataSourceId' argument is empty" otherwise, verified on 4.23.1).
        pending = pending_data_sources(case_dir)
        if not pending:
            if not case_summary(case_dir)["data_sources"]:
                return IntegrationResult.failed("The case has no data source to ingest; run autopsy.add_data_source first")
            return self._verified_summary(case_dir, context, {"already_ingested": True}, [])
        details: dict[str, Any] = {}
        logs = []
        for object_id in pending:
            args = [*case_args(case_dir), "--runIngest", f"--dataSourceObjectId={object_id}"]
            args += [f"--ingestProfile={profile}"] if profile else []
            details, log = self._run(context, args, f"ingest_{object_id}")
            logs.append(evidence(log, f"Autopsy ingest log (data source {object_id})", "log"))
            if details["exit_code"] != 0:
                return IntegrationResult.failed(f"Autopsy --runIngest exited with {details['exit_code']} "
                                                f"for data source {object_id}", **details)
        return self._verified_summary(case_dir, context, {**details, "ingested_data_sources": pending}, logs)

    def wait_for_completion(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        case_dir = self._case_dir(parameters, context)
        return self._verified_summary(case_dir, context, {}, [])

    def _verified_summary(self, case_dir: Path, context: ExecutionContext, details: dict[str, Any],
                          items: list[dict[str, Any]]) -> IntegrationResult:
        summary = case_summary(case_dir)
        output = context.save_result("autopsy_case_summary.json", summary)
        verified = summary["ingest_completed"] and bool(summary["data_sources"])
        reason = {} if verified else {"reason": "Ingest jobs are not all completed or no data source is recorded in autopsy.db"}
        return IntegrationResult(verified, {**details, **summary, **reason},
                                 items + [evidence(output, "Autopsy case database summary", "json")],
                                 checks=self._case_checks(case_dir, context, ingest=True, source=True))

    def ingest(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        source = self._data_source(parameters, context)
        case_name = _safe_name(param_str(parameters, "case_name") or f"{context.assignment}_agent")
        profile = param_str(parameters, "profile")
        base = self._cases_dir(context)
        # --generateReports is deliberately not bundled here: it needs a command-line report profile
        # that only exists once it is created in the GUI, and its failure would discard a whole
        # successful ingest.  Reports are a separate capability (autopsy.generate_report).
        args = ["--createCase", f"--caseName={case_name}", f"--caseBaseDir={base}", "--addDataSource",
                f"--dataSourcePath={source}", "--runIngest"] + ([f"--ingestProfile={profile}"] if profile else [])
        details, log = self._run(context, args, "ingest")
        if details["exit_code"] != 0:
            return IntegrationResult.failed(f"Autopsy command-line ingest exited with {details['exit_code']}", **details)
        case_dir = self._discover_case(base, case_name)
        self._save_state(context, case_dir=str(case_dir), case_name=case_name, data_source=str(source))
        result = self._verified_summary(case_dir, context, {**details, "case_dir": str(case_dir), "data_source": str(source)},
                                        [evidence(log, "Autopsy command-line ingest log", "log")])
        result.report_sections.append({"title": "Autopsy case parameters", "table": [
            {"field": "Case name", "value": case_name}, {"field": "Case folder", "value": str(case_dir)},
            {"field": "Image", "value": str(source)}, {"field": "Ingest profile", "value": profile or "default"},
            {"field": "Files indexed", "value": result.details.get("files")},
            {"field": "Artifacts", "value": json.dumps(result.details.get("artifacts", {}), ensure_ascii=False)}]})
        return result

    def inspect_results(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        case_dir = self._case_dir(parameters, context)
        summary = case_summary(case_dir)
        database = case_database(case_dir)
        output = context.folder("results") / "autopsy_files.csv"
        with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as connection:
            rows = connection.execute(
                "SELECT obj_id, name, parent_path, size, md5, dir_flags, meta_flags FROM tsk_files "
                "WHERE type NOT IN (1) OR type IS NULL ORDER BY parent_path, name LIMIT 5000").fetchall()
        with output.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["obj_id", "name", "parent_path", "size", "md5", "dir_flags", "meta_flags"])
            writer.writerows(rows)
        summary_file = context.save_result("autopsy_results_summary.json", summary)
        verified = summary["files"] > 0
        return IntegrationResult(
            verified, {**summary, **({} if verified else {"reason": "The case database lists no files"})},
            [evidence(output, "Files indexed by Autopsy", "csv"), evidence(summary_file, "Autopsy artifact summary", "json")],
            checks=[{"type": "csv_rows", "path": "results/autopsy_files.csv", "min": 1}],
            report_sections=[{"title": "Autopsy results", "table": [{"artifact": k, "count": v} for k, v in summary["artifacts"].items()]
                              or [{"artifact": "(none)", "count": 0}]}],
        )

    def search_artifacts(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        case_dir = self._case_dir(parameters, context)
        query = param_str(parameters, "query")
        limit = param_int(parameters, "limit", 500)
        like = f"%{query}%"
        with sqlite3.connect(f"file:{case_database(case_dir).as_posix()}?mode=ro", uri=True) as connection:
            files = connection.execute("SELECT 'file' AS kind, obj_id, name, parent_path, size FROM tsk_files WHERE name LIKE ? LIMIT ?",
                                       (like, limit)).fetchall()
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            attributes = connection.execute(
                "SELECT 'artifact' AS kind, artifact_id, value_text, '', '' FROM blackboard_attributes WHERE value_text LIKE ? LIMIT ?",
                (like, limit)).fetchall() if "blackboard_attributes" in tables else []
        output = context.folder("results") / f"autopsy_search_{_safe_name(query)}.csv"
        with output.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["kind", "id", "value", "parent_path", "size"])
            writer.writerows(files + attributes)
        return IntegrationResult(True, {"query": query, "matches": len(files) + len(attributes)},
                                 [evidence(output, f"Autopsy search results for {query!r}", "csv")],
                                 checks=[{"type": "file_exists", "path": output.relative_to(context.workspace).as_posix()}])

    def export_artifact(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        case_dir = self._case_dir(parameters, context)
        name = param_str(parameters, "name")
        with sqlite3.connect(f"file:{case_database(case_dir).as_posix()}?mode=ro", uri=True) as connection:
            row = connection.execute("SELECT obj_id, size, data_source_obj_id FROM tsk_files WHERE name = ? AND size > 0 LIMIT 1",
                                     (name,)).fetchone()
            if row is None:
                return IntegrationResult.failed(f"No file named {name!r} with content in the case database")
            layout = connection.execute("SELECT byte_start, byte_len FROM tsk_file_layout WHERE obj_id = ? ORDER BY sequence",
                                        (row[0],)).fetchall()
            images = connection.execute("SELECT name FROM tsk_image_names WHERE obj_id = ? ORDER BY sequence", (row[2],)).fetchall()
        if not layout or not images:
            return IntegrationResult.failed(f"{name!r} has no byte layout (resident or compressed file); export it from the GUI")
        image_path = Path(images[0][0])
        data = bytearray()
        with image_path.open("rb") as stream:
            for start, length in layout:
                stream.seek(int(start))
                data.extend(stream.read(int(length)))
        data = data[: int(row[1])]
        output = context.save_result(f"autopsy_export_{Path(name).name}", bytes(data))
        return IntegrationResult(len(data) == int(row[1]), {"name": name, "size": len(data), "obj_id": row[0]},
                                 [evidence(output, f"File {name} exported from the image via Autopsy layout", "file")],
                                 checks=[{"type": "file_exists", "path": f"results/{output.name}", "min_size": int(row[1])}])

    def generate_report(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        case_dir = self._case_dir(parameters, context)
        details, log = self._run(context, [*case_args(case_dir), "--generateReports"], "report")
        reports = [p for p in (case_dir / "Reports").rglob("*") if p.is_file()] if (case_dir / "Reports").is_dir() else []
        if details["exit_code"] != 0 and not reports:
            output = f"{details.get('stdout', '')}\n{details.get('stderr', '')}"
            if "reporting configuration" in output.casefold() or not output.strip():
                raise CapabilityBlocked(
                    "Autopsy has no command-line report profile, so --generateReports cannot run "
                    "(it looks for the profile named 'CommandLineIngest'). Create one once in the Autopsy GUI "
                    "(Tools -> Generate Report, save the configuration), or use autopsy.inspect_results, which "
                    "exports the same findings as CSV/JSON from the case database.")
            return IntegrationResult.failed("Autopsy did not generate report files", **details)
        if not reports:
            return IntegrationResult.failed("Autopsy did not generate report files", **details)
        html = next((p for p in reports if p.suffix.lower() in {".html", ".htm"}), reports[0])
        copy = context.save_result("autopsy_report" + html.suffix.lower(), html.read_bytes())
        return IntegrationResult(True, {**details, "reports": [str(p) for p in reports[:20]]},
                                 [evidence(log, "Autopsy report generation log", "log"), evidence(copy, "Autopsy generated report", "file")],
                                 checks=[{"type": "file_exists", "path": f"results/{copy.name}"}])

    def open_case_gui(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        from ..applications import ManagedApplication

        case_dir = self._case_dir(parameters, context)
        aut = next(iter(sorted(case_dir.glob("*.aut"))), None)
        if aut is None:
            return IntegrationResult.failed(f"No Autopsy case file (*.aut) in {case_dir}")
        app = ManagedApplication("autopsy", context, spec=AUTOPSY_SPEC)
        app.launch([str(aut)], reuse=False)
        picture = app.screenshot(f"autopsy_case_{context.stamp()}.png")
        return IntegrationResult(True, {"case_dir": str(case_dir)},
                                 [evidence(picture, "Autopsy GUI with the analysed case", "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(picture)},
                                         {"type": "window_exists", "title_re": app.window_selector.get("title_re", "Autopsy")}])

    def capture_evidence(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        from ..applications import ManagedApplication

        app = ManagedApplication("autopsy", context, spec=AUTOPSY_SPEC)
        if app.running_window() is None:
            return IntegrationResult.failed("The Autopsy window is not open; nothing to capture.")
        picture = app.screenshot(param_str(parameters, "name") or f"autopsy_{context.stamp()}.png")
        return IntegrationResult(True, {}, [evidence(picture, "Autopsy window", "screenshot")],
                                 checks=[{"type": "image_valid", "path": str(picture)}])

    def e2e(self, parameters: dict[str, Any], context: ExecutionContext) -> IntegrationResult:
        result = self.ingest(parameters, context)
        if not result.verified:
            return result
        inspect = self.inspect_results({}, context)
        combined = IntegrationResult(inspect.verified, {**result.details, **inspect.details},
                                     result.evidence + inspect.evidence, checks=result.checks + inspect.checks,
                                     report_sections=result.report_sections + inspect.report_sections)
        report = self.generate_report({}, context)
        combined.evidence += report.evidence if report.verified else []
        gui = self.open_case_gui({}, context)
        combined.evidence += gui.evidence
        combined.checks += gui.checks
        return combined


def create_adapters(services: Any) -> list[AutopsyAdapter]:
    return [AutopsyAdapter()]
