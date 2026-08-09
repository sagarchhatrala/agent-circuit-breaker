"""Stateful loop-breaking guards."""

from __future__ import annotations

import time
from typing import Any, Mapping

from agent_circuit_breaker.core.context import AgentContext
from agent_circuit_breaker.core.results import GuardResult
from agent_circuit_breaker.state.manager import StateManager


class SequenceBreakerGuard:
    """Trip when the same tool/argument sequence repeats too often."""

    guard_id = "sequence_breaker_guard"

    def __init__(self, state_manager: StateManager, *, max_repeats: int = 3) -> None:
        self.state_manager = state_manager
        self.max_repeats = max_repeats

    async def evaluate(self, context: AgentContext) -> GuardResult:
        sequence = _sequence_from_context(context)
        state = await self.state_manager.record_sequence(context.state_key(), sequence)
        if state.repeated_sequence_count >= self.max_repeats:
            await self.state_manager.open_circuit(context.state_key(), "repeated exact tool sequence")
            return GuardResult.deny(
                self.guard_id,
                "repeated exact tool sequence",
                "HIGH",
                {"repeated_sequence_count": state.repeated_sequence_count},
            )
        return GuardResult.allow(self.guard_id, "sequence repetition below threshold")


class ContextWindowBreaker:
    """Trip before an LLM payload exceeds a configured token budget."""

    guard_id = "context_window_breaker"

    def __init__(self, *, max_tokens: int) -> None:
        self.max_tokens = max_tokens

    async def evaluate(self, context: AgentContext) -> GuardResult:
        payload = context.tool_args.get("payload") or context.tool_args.get("prompt") or context.tool_args.get("messages")
        if payload is None:
            return GuardResult.not_applicable(self.guard_id, "no LLM payload")
        tokens = _fast_token_count(payload)
        if tokens > self.max_tokens:
            return GuardResult.deny(
                self.guard_id,
                "context window token budget exceeded",
                "HIGH",
                {"tokens": tokens, "max_tokens": self.max_tokens},
            )
        return GuardResult.allow(self.guard_id, "context window within budget", {"tokens": tokens})


class HaltingHeuristicGuard:
    """Trip when tool-call volume exceeds a threshold without progress."""

    guard_id = "halting_heuristic_guard"

    def __init__(
        self,
        state_manager: StateManager,
        *,
        max_tool_calls: int = 50,
        window_seconds: float = 300.0,
    ) -> None:
        self.state_manager = state_manager
        self.max_tool_calls = max_tool_calls
        self.window_seconds = window_seconds

    async def evaluate(self, context: AgentContext) -> GuardResult:
        if bool(context.tool_args.get("progress")):
            await self.state_manager.record_progress(context.state_key())
            return GuardResult.allow(self.guard_id, "progress signal recorded")

        state = await self.state_manager.record_tool_call(context.state_key(), self.window_seconds)
        now = time.time()
        recent_progress = [ts for ts in state.progress_timestamps if now - ts <= self.window_seconds]
        if len(state.tool_call_timestamps) > self.max_tool_calls and not recent_progress:
            await self.state_manager.open_circuit(context.state_key(), "tool-call volume exceeded without progress")
            return GuardResult.deny(
                self.guard_id,
                "tool-call volume exceeded without progress",
                "HIGH",
                {"tool_calls": len(state.tool_call_timestamps), "window_seconds": self.window_seconds},
            )
        return GuardResult.allow(self.guard_id, "tool-call volume below threshold")


def _sequence_from_context(context: AgentContext) -> list[Mapping[str, Any]]:
    raw_sequence = context.tool_args.get("sequence")
    if isinstance(raw_sequence, list):
        return [item if isinstance(item, Mapping) else {"value": item} for item in raw_sequence]
    return [{"tool_name": context.tool_name, "tool_args": dict(context.tool_args)}]


def _fast_token_count(payload: Any) -> int:
    if isinstance(payload, list):
        return sum(_fast_token_count(item) for item in payload)
    if isinstance(payload, Mapping):
        return sum(_fast_token_count(value) for value in payload.values())
    text = str(payload)
    return len(text.split())
