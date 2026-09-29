"""Shared contracts for pluggable Lab Agent integrations."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class Capability:
    """A single operation an integration can execute."""

    name: str
    tool: str
    description: str
    parameters: tuple[str, ...] = ()
    evidence_types: tuple[str, ...] = ()

    def as_prompt_line(self) -> str:
        params = ", ".join(self.parameters) if self.parameters else "none"
        evidence = ", ".join(self.evidence_types) if self.evidence_types else "optional"
        return (
            f"- {self.name}: {self.description}. "
            f"parameters=[{params}]; evidence={evidence}"
        )


@dataclass
class ExecutionContext:
    """Runtime context shared by all integrations."""

    workspace: Path
    assignment: str
    allowed_targets: set[str] = field(default_factory=set)


@dataclass
class IntegrationResult:
    """Normalized result returned by every integration capability."""

    verified: bool
    details: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, str]] = field(default_factory=list)
    blocked: bool = False


class IntegrationAdapter(Protocol):
    """Protocol implemented by built-in and third-party integrations."""

    name: str

    def capabilities(self) -> list[Capability]:
        ...

    def execute(
        self,
        capability: str,
        parameters: dict[str, Any],
        context: ExecutionContext,
    ) -> IntegrationResult:
        ...
