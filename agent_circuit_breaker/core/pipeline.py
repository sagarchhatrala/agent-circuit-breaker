"""Concurrent fail-closed guard pipeline."""

from __future__ import annotations

import asyncio
from typing import Iterable, List, Tuple

from agent_circuit_breaker.core.context import AgentContext, context_scope
from agent_circuit_breaker.core.results import ALLOW, DENY, UNKNOWN, GuardResult, PipelineResult
from agent_circuit_breaker.interfaces.guards import GuardProtocol
from agent_circuit_breaker.interfaces.hooks import HookProtocol
from agent_circuit_breaker.observability.events import EventBus, PipelineEvent


class PipelineEngine:
    """Run guards concurrently and fail closed on errors."""

    def __init__(
        self,
        guards: Iterable[GuardProtocol] = (),
        *,
        hooks: Iterable[HookProtocol] = (),
        event_bus: EventBus | None = None,
    ) -> None:
        self.guards: Tuple[GuardProtocol, ...] = tuple(guards)
        self.hooks: Tuple[HookProtocol, ...] = tuple(hooks)
        self.event_bus = event_bus or EventBus()

    async def evaluate(self, context: AgentContext) -> PipelineResult:
        """Evaluate one context through all registered guards."""
        with context_scope(context):
            await self._run_pre_hooks(context)
            self._emit("PipelineStarted", context)

            result = await self._evaluate_guards(context)

            if not result.allowed:
                await self._run_open_hooks(context, result)
            await self._run_post_hooks(context, result)
            self._emit(
                "PipelineCompleted",
                context,
                {"verdict": result.verdict, "denied_by": result.denied_by},
            )
            return result

    async def _evaluate_guards(self, context: AgentContext) -> PipelineResult:
        if not self.guards:
            return PipelineResult(UNKNOWN, context.request_id, ())

        queue: asyncio.Queue[tuple[GuardProtocol, GuardResult]] = asyncio.Queue()
        tasks: List[asyncio.Task[None]] = []
        results: List[GuardResult] = []

        async def run_and_report(guard: GuardProtocol) -> None:
            result = await self._run_guard(guard, context)
            await queue.put((guard, result))

        async with asyncio.TaskGroup() as task_group:
            for guard in self.guards:
                tasks.append(task_group.create_task(run_and_report(guard)))

            remaining = len(tasks)
            while remaining:
                _guard, result = await queue.get()
                remaining -= 1
                results.append(result)
                if result.verdict == DENY:
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    self._emit(
                        "GuardDenied",
                        context,
                        {"guard_id": result.guard_id, "reason": result.reason},
                    )
                    return PipelineResult(DENY, context.request_id, tuple(results), result.guard_id, result.reason)

        verdict = ALLOW if any(result.verdict == ALLOW for result in results) else UNKNOWN
        return PipelineResult(verdict, context.request_id, tuple(results))

    @staticmethod
    async def _run_guard(guard: GuardProtocol, context: AgentContext) -> GuardResult:
        try:
            return await guard.evaluate(context)
        except Exception as exc:
            return GuardResult.deny(
                getattr(guard, "guard_id", guard.__class__.__name__),
                f"guard raised {exc.__class__.__name__}",
                severity="CRITICAL",
            )

    async def _run_pre_hooks(self, context: AgentContext) -> None:
        for hook in self.hooks:
            await hook.pre_execution(context)

    async def _run_post_hooks(self, context: AgentContext, result: PipelineResult) -> None:
        for hook in self.hooks:
            await hook.post_execution(context, result)

    async def _run_open_hooks(self, context: AgentContext, result: PipelineResult) -> None:
        for hook in self.hooks:
            await hook.on_circuit_open(context, result)

    def _emit(self, event_type: str, context: AgentContext, metadata: dict | None = None) -> None:
        self.event_bus.emit(
            PipelineEvent(
                event_type=event_type,
                request_id=context.request_id,
                agent_id=context.agent_id,
                tool_name=context.tool_name,
                metadata=metadata or {},
            )
        )
