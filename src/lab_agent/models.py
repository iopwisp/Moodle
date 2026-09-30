"""Typed data structures shared by the CLI and workflow modules.

New fields always have defaults so checkpoints written by earlier versions
(``state/state.json``) keep loading.
"""

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


class RunStatus(StrEnum):
    ANALYZED = "ANALYZED"
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    PAUSED = "PAUSED"
    STOPPED = "STOPPED"
    WAITING_CONFIRMATION = "WAITING_CONFIRMATION"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class VerificationCheck(BaseModel):
    """One machine-checkable post-condition (see :mod:`lab_agent.verification`)."""

    model_config = ConfigDict(extra="allow")

    type: str


class Attempt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    number: int
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    outcome: str = "RUNNING"
    error: str | None = None
    failure_kind: str | None = None
    recovery: str | None = None


class PlannedTask(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    title: str
    description: str
    tool: str = "manual"
    action: str = "core.manual_review"
    parameters: dict[str, Any] = Field(default_factory=dict)
    required: bool = True
    evidence_required: bool = False
    evidence_type_required: str | None = None
    inputs: list[str] = Field(default_factory=list)
    expected_result: str = ""
    verification: str = ""
    evidence_path: str | None = None
    status: TaskStatus = TaskStatus.PENDING
    # --- added in 0.3 ---------------------------------------------------------
    depends_on: list[int] = Field(default_factory=list)  # must be COMPLETED first
    run_after: list[int] = Field(default_factory=list)  # must merely have finished (any terminal state)
    verification_checks: list[dict[str, Any]] = Field(default_factory=list)
    requirement_refs: list[str] = Field(default_factory=list)
    screenshot_required: bool = False
    attempts: list[Attempt] = Field(default_factory=list)
    result_summary: str = ""
    status_reason: str = ""
    verification_results: list[dict[str, Any]] = Field(default_factory=list)
    report_sections: list[dict[str, Any]] = Field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def capability(self) -> str:
        return self.action


class InputFile(BaseModel):
    """Classified input file (assignment text, evidence image, reference, ...)."""

    model_config = ConfigDict(extra="forbid")

    path: str
    role: str
    size: int = 0
    note: str = ""
    archive: str | None = None
    workspace_path: str = ""
    sha256: str = ""


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
    # --- added in 0.3 ---------------------------------------------------------
    title: str = ""
    files: list[InputFile] = Field(default_factory=list)
    sections: list[dict[str, Any]] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)
    deliverables: list[str] = Field(default_factory=list)
    verification_criteria: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hashes: dict[str, str] = Field(default_factory=dict)
    questions: list[str] = Field(default_factory=list)


class ExecutionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignment: str
    objective: str
    steps: list[PlannedTask]
    source_files: list[str]
    created_at: datetime = Field(default_factory=utc_now)
    planner: str = ""
    warnings: list[str] = Field(default_factory=list)

    def step(self, step_id: int) -> PlannedTask | None:
        return next((task for task in self.steps if task.id == step_id), None)


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
    size: int | None = None
    capability: str | None = None
    requirement_refs: list[str] = Field(default_factory=list)


class ExecutionRecord(BaseModel):
    timestamp: datetime = Field(default_factory=utc_now)
    command: str
    working_directory: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_seconds: float = 0


class ConfirmationRequest(BaseModel):
    """Human-in-the-loop request raised by policy or an adapter."""

    model_config = ConfigDict(extra="forbid")

    id: str
    step_id: int
    reason: str
    created_at: datetime = Field(default_factory=utc_now)
    status: str = "PENDING"  # PENDING | APPROVED | REJECTED
    decided_at: datetime | None = None
    note: str = ""


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
    # --- added in 0.3 ---------------------------------------------------------
    control: str | None = None  # PAUSE_REQUESTED | STOP_REQUESTED
    confirmations: list[ConfirmationRequest] = Field(default_factory=list)
    recoveries: list[dict[str, Any]] = Field(default_factory=list)
    current_application: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    status_reason: str = ""

    def step(self, step_id: int) -> PlannedTask | None:
        return self.plan.step(step_id)


def safe_assignment_name(path: Path) -> str:
    """Return a filesystem-safe workspace name derived from an input path."""
    candidate = "".join(c if c.isalnum() or c in "-_" else "_" for c in path.stem).strip("_-")
    return candidate[:80] or "assignment"
