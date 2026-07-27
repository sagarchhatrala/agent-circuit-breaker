"""Pipeline result DTOs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Tuple


ALLOW = "allow"
DENY = "deny"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class GuardResult:
    """Result returned by one guard."""

    verdict: str
    guard_id: str
    reason: str = ""
    severity: str = "LOW"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def allow(cls, guard_id: str, reason: str = "", metadata: Mapping[str, Any] | None = None) -> "GuardResult":
        return cls(ALLOW, guard_id, reason, "LOW", metadata or {})

    @classmethod
    def deny(
        cls,
        guard_id: str,
        reason: str,
        severity: str = "HIGH",
        metadata: Mapping[str, Any] | None = None,
    ) -> "GuardResult":
        return cls(DENY, guard_id, reason, severity, metadata or {})

    @classmethod
    def unknown(cls, guard_id: str, reason: str = "", metadata: Mapping[str, Any] | None = None) -> "GuardResult":
        return cls(UNKNOWN, guard_id, reason, "LOW", metadata or {})


@dataclass(frozen=True)
class PipelineResult:
    """Aggregate result from the concurrent guard pipeline."""

    verdict: str
    request_id: str
    guard_results: Tuple[GuardResult, ...]
    denied_by: str | None = None
    reason: str = ""

    @property
    def allowed(self) -> bool:
        """Return true when the pipeline allows execution."""
        return self.verdict == ALLOW
