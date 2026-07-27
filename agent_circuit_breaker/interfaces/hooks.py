"""Hook protocol contract."""

from __future__ import annotations

from typing import Protocol

from agent_circuit_breaker.core.context import AgentContext
from agent_circuit_breaker.core.results import PipelineResult


class HookProtocol(Protocol):
    """Optional lifecycle hook contract."""

    async def pre_execution(self, context: AgentContext) -> None:
        """Called before guards run."""
        ...

    async def post_execution(self, context: AgentContext, result: PipelineResult) -> None:
        """Called after guard aggregation."""
        ...

    async def on_circuit_open(self, context: AgentContext, result: PipelineResult) -> None:
        """Called when a context is denied."""
        ...
