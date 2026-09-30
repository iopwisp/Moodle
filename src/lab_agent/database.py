"""SQLite event store for an assignment workspace.

The JSON checkpoint remains portable, while SQLite gives the dashboard a durable
and queryable history of runs, tasks, events, evidence, verifications and errors.
Schemas created by older versions are migrated in place (columns are only added).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .credentials import redact
from .models import RunState

EVENT_TYPES = (
    "agent.started", "agent.paused", "agent.stopped", "agent.completed", "agent.failed",
    "task.started", "task.completed", "task.failed", "task.blocked", "task.skipped", "task.reconciled",
    "capability.started", "capability.completed", "capability.failed",
    "verification.started", "verification.passed", "verification.failed",
    "evidence.created", "evidence.verified", "screenshot.created",
    "recovery.started", "recovery.completed", "confirmation.requested", "confirmation.decided",
    "policy.denied", "report.completed", "application.launched",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assignments (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, workspace TEXT NOT NULL,
    status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, assignment TEXT NOT NULL, status TEXT NOT NULL,
    planner TEXT, started_at TEXT NOT NULL, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS tasks (
    assignment_id TEXT NOT NULL, step_id INTEGER NOT NULL, title TEXT NOT NULL,
    action TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL,
    PRIMARY KEY (assignment_id, step_id)
);
CREATE TABLE IF NOT EXISTS evidence (
    assignment_id TEXT NOT NULL, evidence_id TEXT NOT NULL, path TEXT NOT NULL,
    kind TEXT NOT NULL, verified INTEGER NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY (assignment_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, assignment_id TEXT NOT NULL,
    event_type TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, assignment_id TEXT NOT NULL, step_id INTEGER NOT NULL,
    check_type TEXT NOT NULL, passed INTEGER NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT, assignment_id TEXT NOT NULL, step_id INTEGER,
    kind TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capabilities (
    assignment_id TEXT NOT NULL, name TEXT NOT NULL, tool TEXT NOT NULL,
    description TEXT NOT NULL, PRIMARY KEY (assignment_id, name)
);
CREATE INDEX IF NOT EXISTS events_by_assignment ON events(assignment_id, id);
"""

_MIGRATIONS: dict[str, dict[str, str]] = {
    "tasks": {"tool": "TEXT", "attempts": "INTEGER DEFAULT 0", "status_reason": "TEXT DEFAULT ''"},
    "evidence": {"step_id": "INTEGER", "sha256": "TEXT", "description": "TEXT DEFAULT ''"},
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


class RunDatabase:
    def __init__(self, workspace: Path) -> None:
        self.path = workspace / "state" / "agent.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
            for table, columns in _MIGRATIONS.items():
                existing = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
                for column, definition in columns.items():
                    if column not in existing:
                        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # ------------------------------------------------------------------ writes
    def sync_state(self, state: RunState) -> None:
        assignment_id = state.run_id or state.assignment
        now = _now()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO assignments(id,name,workspace,status,created_at,updated_at) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at",
                (assignment_id, state.assignment, state.workspace_path, state.status, now, now),
            )
            for task in state.plan.steps:
                connection.execute(
                    "INSERT INTO tasks(assignment_id,step_id,title,action,status,updated_at,tool,attempts,status_reason) "
                    "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(assignment_id,step_id) DO UPDATE SET title=excluded.title, "
                    "action=excluded.action, status=excluded.status, updated_at=excluded.updated_at, tool=excluded.tool, "
                    "attempts=excluded.attempts, status_reason=excluded.status_reason",
                    (assignment_id, task.id, task.title, task.action, task.status.value, now, task.tool,
                     len(task.attempts), task.status_reason),
                )

    def start_run(self, run_id: str, assignment: str, planner: str | None) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO runs(run_id,assignment,status,planner,started_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(run_id) DO UPDATE SET status=excluded.status",
                (run_id, assignment, "IN_PROGRESS", planner, _now()),
            )

    def finish_run(self, run_id: str, status: str) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE runs SET status=?, finished_at=? WHERE run_id=?", (status, _now(), run_id))

    def event(self, assignment_id: str, event_type: str, payload: dict[str, Any] | None = None) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO events(assignment_id,event_type,payload,created_at) VALUES(?,?,?,?)",
                (assignment_id, event_type, json.dumps(redact(payload or {}), ensure_ascii=False, default=str), _now()),
            )
            return int(cursor.lastrowid or 0)

    def sync_evidence(
        self, assignment_id: str, item_id: str, path: str, kind: str, verified: bool,
        *, step_id: int | None = None, sha256: str | None = None, description: str = "",
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO evidence(assignment_id,evidence_id,path,kind,verified,created_at,step_id,sha256,description) "
                "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(assignment_id,evidence_id) DO UPDATE SET "
                "verified=excluded.verified, sha256=excluded.sha256",
                (assignment_id, item_id, path, kind, int(verified), _now(), step_id, sha256, description),
            )

    def record_verification(self, assignment_id: str, step_id: int, results: list[dict[str, Any]]) -> None:
        with self._connect() as connection:
            connection.executemany(
                "INSERT INTO verifications(assignment_id,step_id,check_type,passed,detail,created_at) VALUES(?,?,?,?,?,?)",
                [(assignment_id, step_id, r["type"], int(r["passed"]), str(r["detail"])[:2000], _now()) for r in results],
            )

    def record_error(self, assignment_id: str, step_id: int | None, kind: str, message: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO errors(assignment_id,step_id,kind,message,created_at) VALUES(?,?,?,?,?)",
                (assignment_id, step_id, kind, str(redact(message))[:4000], _now()),
            )

    def record_capabilities(self, assignment_id: str, capabilities: list[dict[str, Any]]) -> None:
        with self._connect() as connection:
            connection.executemany(
                "INSERT OR REPLACE INTO capabilities(assignment_id,name,tool,description) VALUES(?,?,?,?)",
                [(assignment_id, c["name"], c["tool"], c["description"]) for c in capabilities],
            )

    # ------------------------------------------------------------------ reads
    def events(self, assignment_id: str, limit: int = 200, since_id: int = 0) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if since_id:
                rows = connection.execute(
                    "SELECT id, event_type, payload, created_at FROM events WHERE assignment_id=? AND id>? ORDER BY id ASC LIMIT ?",
                    (assignment_id, since_id, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT id, event_type, payload, created_at FROM events WHERE assignment_id=? ORDER BY id DESC LIMIT ?",
                    (assignment_id, limit),
                ).fetchall()
        return [
            {"id": row["id"], "event_type": row["event_type"], "payload": json.loads(row["payload"]),
             "created_at": row["created_at"]}
            for row in rows
        ]

    def verifications(self, assignment_id: str, step_id: int | None = None) -> list[dict[str, Any]]:
        query = "SELECT step_id, check_type, passed, detail, created_at FROM verifications WHERE assignment_id=?"
        args: tuple[Any, ...] = (assignment_id,)
        if step_id is not None:
            query += " AND step_id=?"
            args += (step_id,)
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(query + " ORDER BY id", args)]

    def errors(self, assignment_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT step_id, kind, message, created_at FROM errors WHERE assignment_id=? ORDER BY id", (assignment_id,)
            )]

    def runs(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM runs ORDER BY started_at DESC")]
