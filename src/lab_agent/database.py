"""SQLite event store for an assignment workspace.

The JSON checkpoint remains portable, while SQLite gives the dashboard a durable
and queryable history of each attempt, screenshot, and task transition.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import RunState


def _now() -> str:
    return datetime.now(UTC).isoformat()


class RunDatabase:
    def __init__(self, workspace: Path) -> None:
        self.path = workspace / "state" / "agent.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS assignments (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, workspace TEXT NOT NULL,
                    status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
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
                """
            )

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
                    "INSERT INTO tasks(assignment_id,step_id,title,action,status,updated_at) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(assignment_id,step_id) DO UPDATE SET title=excluded.title, action=excluded.action, status=excluded.status, updated_at=excluded.updated_at",
                    (assignment_id, task.id, task.title, task.action, task.status.value, now),
                )

    def event(self, assignment_id: str, event_type: str, payload: dict[str, Any] | None = None) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO events(assignment_id,event_type,payload,created_at) VALUES(?,?,?,?)",
                (assignment_id, event_type, json.dumps(payload or {}, ensure_ascii=False), _now()),
            )

    def sync_evidence(self, assignment_id: str, item_id: str, path: str, kind: str, verified: bool) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO evidence(assignment_id,evidence_id,path,kind,verified,created_at) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(assignment_id,evidence_id) DO UPDATE SET verified=excluded.verified",
                (assignment_id, item_id, path, kind, int(verified), _now()),
            )

    def events(self, assignment_id: str, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_type, payload, created_at FROM events WHERE assignment_id=? ORDER BY id DESC LIMIT ?",
                (assignment_id, limit),
            ).fetchall()
        return [{"event_type": row["event_type"], "payload": json.loads(row["payload"]), "created_at": row["created_at"]} for row in rows]
