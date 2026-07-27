"""Guard protocol contract."""

from __future__ import annotations

from typing import Protocol

from agent_circuit_breaker.core.context import AgentContext
from agent_circuit_breaker.core.results import GuardResult


class GuardProtocol(Protocol):
    """Async guard contract used by the pipeline engine."""

    guard_id: str

    async def evaluate(self, context: AgentContext) -> GuardResult:
        """Evaluate one context and return a deterministic guard result."""
        ...
