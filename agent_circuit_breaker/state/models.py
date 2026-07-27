"""State DTOs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Tuple


@dataclass(frozen=True)
class CircuitState:
    """Persistent state for one circuit."""

    circuit_id: str
    status: str = "closed"
    failure_count: int = 0
    version: int = 0
    last_sequence_hash: str | None = None
    repeated_sequence_count: int = 0
    opened_reason: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    tool_call_timestamps: Tuple[float, ...] = ()
    progress_timestamps: Tuple[float, ...] = ()
