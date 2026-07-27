"""In-memory state store."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any, Dict, Mapping

from .models import CircuitState


class InMemoryStore:
    """Atomic in-memory state store for local development and tests."""

    def __init__(self) -> None:
        self._states: Dict[str, CircuitState] = {}
        self._lock = asyncio.Lock()

    async def read_state(self, circuit_id: str) -> CircuitState:
        async with self._lock:
            return self._states.get(circuit_id, CircuitState(circuit_id=circuit_id))

    async def transition(self, circuit_id: str, updates: Mapping[str, Any]) -> CircuitState:
        async with self._lock:
            state = self._states.get(circuit_id, CircuitState(circuit_id=circuit_id))
            data = dict(updates)
            data["version"] = state.version + 1
            next_state = replace(state, **data)
            self._states[circuit_id] = next_state
            return next_state
