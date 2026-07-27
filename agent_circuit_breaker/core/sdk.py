"""High-level SDK for the async pipeline."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, Iterable, Mapping

from agent_circuit_breaker.core.context import AgentContext
from agent_circuit_breaker.core.pipeline import PipelineEngine
from agent_circuit_breaker.core.results import PipelineResult
from agent_circuit_breaker.guards import (
    ContextWindowBreaker,
    FilesystemGuard,
    HaltingHeuristicGuard,
    LegacyActionGuard,
    NetworkEgressGuard,
    PackageInstallGuard,
    SequenceBreakerGuard,
    ShellGuard,
)
from agent_circuit_breaker.interfaces.guards import GuardProtocol
from agent_circuit_breaker.observability.events import EventBus
from agent_circuit_breaker.state.manager import StateManager


class AgentCircuitBreaker:
    """SDK facade for pipeline-based agent safety checks."""

    def __init__(
        self,
        guards: Iterable[GuardProtocol] | None = None,
        *,
        state_manager: StateManager | None = None,
        event_bus: EventBus | None = None,
        max_context_tokens: int | None = None,
        max_sequence_repeats: int = 3,
        max_tool_calls: int = 50,
        tool_call_window_seconds: float = 300.0,
    ) -> None:
        self.state_manager = state_manager or StateManager()
        if guards is None:
            guard_list: list[GuardProtocol] = [
                LegacyActionGuard(),
                ShellGuard(),
                FilesystemGuard(),
                NetworkEgressGuard(),
                PackageInstallGuard(),
                SequenceBreakerGuard(self.state_manager, max_repeats=max_sequence_repeats),
                HaltingHeuristicGuard(
                    self.state_manager,
                    max_tool_calls=max_tool_calls,
                    window_seconds=tool_call_window_seconds,
                ),
            ]
            if max_context_tokens is not None:
                guard_list.append(ContextWindowBreaker(max_tokens=max_context_tokens))
            guards = guard_list
        self.engine = PipelineEngine(guards, event_bus=event_bus)

    async def evaluate_tool_call(
        self,
        *,
        tool_name: str,
        tool_args: Mapping[str, Any],
        agent_id: str = "default-agent",
        request_id: str | None = None,
        span_links: tuple[str, ...] = (),
        circuit_id: str | None = None,
    ) -> PipelineResult:
        """Evaluate one attempted tool call asynchronously."""
        context = AgentContext(
            request_id=request_id or uuid.uuid4().hex,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=dict(tool_args),
            span_links=span_links,
            circuit_id=circuit_id,
        )
        return await self.engine.evaluate(context)

    def evaluate_tool_call_sync(
        self,
        *,
        tool_name: str,
        tool_args: Mapping[str, Any],
        agent_id: str = "default-agent",
        request_id: str | None = None,
        span_links: tuple[str, ...] = (),
        circuit_id: str | None = None,
    ) -> PipelineResult:
        """Synchronous wrapper for outer SDK callers."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(
                self.evaluate_tool_call(
                    tool_name=tool_name,
                    tool_args=tool_args,
                    agent_id=agent_id,
                    request_id=request_id,
                    span_links=span_links,
                    circuit_id=circuit_id,
                )
            )
        raise RuntimeError("evaluate_tool_call_sync cannot be called from a running event loop")
