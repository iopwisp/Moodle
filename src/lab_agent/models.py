"""Typed data structures shared by the CLI and workflow modules."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


class TaskStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


class PlannedTask(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    title: str
    description: str
    tool: str = "manual"
    action: str = "manual_review"
    parameters: dict[str, str] = Field(default_factory=dict)
    required: bool = True
    evidence_required: bool = False
    evidence_type_required: str | None = None
    inputs: list[str] = Field(default_factory=list)
    expected_result: str = ""
    verification: str = ""
    evidence_path: str | None = None
    status: TaskStatus = TaskStatus.PENDING


class AssignmentAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignment: str
    source_files: list[str]
    objective: str
    tools: list[str]
    requirements: list[str]
    screenshot_requirements: list[str]
    expected_outputs: list[str]
    limitations: list[str]
    extracted_text_files: dict[str, str]
    created_at: datetime = Field(default_factory=utc_now)


class ExecutionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignment: str
    objective: str
    steps: list[PlannedTask]
    source_files: list[str]
    created_at: datetime = Field(default_factory=utc_now)


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    type: str
    step_id: int | None = None
    path: str
    description: str
    verified: bool = False
    sha256: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class ExecutionRecord(BaseModel):
    timestamp: datetime = Field(default_factory=utc_now)
    command: str
    working_directory: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_seconds: float = 0


class RunState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignment: str
    source_path: str
    workspace_path: str
    status: str = "ANALYZED"
    current_step: int | None = None
    plan: ExecutionPlan
    completed_steps: list[int] = Field(default_factory=list)
    errors: list[dict[str, Any]] = Field(default_factory=list)
    run_id: str | None = None
    updated_at: datetime = Field(default_factory=utc_now)


def safe_assignment_name(path: Path) -> str:
    """Return a filesystem-safe workspace name derived from an input path."""
    candidate = "".join(c if c.isalnum() or c in "-_" else "_" for c in path.stem).strip("_-")
    return candidate[:80] or "assignment"
