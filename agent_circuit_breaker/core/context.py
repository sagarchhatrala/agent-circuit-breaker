"""Immutable context propagated through guard evaluation."""

from __future__ import annotations

import contextlib
import contextvars
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Optional, Tuple


@dataclass(frozen=True)
class AgentContext:
    """One attempted tool call or agent action."""

    request_id: str
    agent_id: str
    tool_name: str
    tool_args: Mapping[str, Any] = field(default_factory=dict)
    span_links: Tuple[str, ...] = ()
    circuit_id: Optional[str] = None

    def action_text(self) -> str:
        """Return all inspectable string argument values.

        Tool schemas are caller-defined, so safety checks must not depend on a
        small set of conventional argument names such as ``command`` or
        ``url``. Prefer common action keys first for backwards-compatible
        display behavior, then include every other nested string value.
        """
        values: list[str] = []
        for key in ("command", "cmd", "input", "query", "script", "path", "url", "payload"):
            value = self.tool_args.get(key)
            if isinstance(value, str):
                values.append(value)
        for value in self.string_values():
            if value not in values:
                values.append(value)
        return "\n".join(values)

    def string_values(self) -> Tuple[str, ...]:
        """Return all nested string values from tool arguments."""
        return tuple(_string_values(self.tool_args))

    def state_key(self) -> str:
        """Return the state circuit key for this context."""
        return self.circuit_id or f"{self.agent_id}:{self.tool_name}"


_CURRENT_CONTEXT: contextvars.ContextVar[Optional[AgentContext]] = contextvars.ContextVar(
    "agent_circuit_breaker_context",
    default=None,
)


def current_context() -> Optional[AgentContext]:
    """Return the current context propagated through the async pipeline."""
    return _CURRENT_CONTEXT.get()


@contextlib.contextmanager
def context_scope(context: AgentContext) -> Iterator[None]:
    """Set current context for the duration of a pipeline evaluation."""
    token = _CURRENT_CONTEXT.set(context)
    try:
        yield
    finally:
        _CURRENT_CONTEXT.reset(token)


def _string_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _string_values(item)
