"""State store protocol contract."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from agent_circuit_breaker.state.models import CircuitState


class StateStoreProtocol(Protocol):
    """Atomic circuit-state persistence contract."""

    async def read_state(self, circuit_id: str) -> CircuitState:
        """Read current circuit state."""
        ...

    async def transition(self, circuit_id: str, updates: Mapping[str, Any]) -> CircuitState:
        """Atomically update circuit state and return the new state."""
        ...
