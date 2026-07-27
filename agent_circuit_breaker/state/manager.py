"""State management helpers for circuit breakers."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Mapping

from .memory import InMemoryStore
from .models import CircuitState


class StateManager:
    """High-level helpers around an atomic state store."""

    def __init__(self, store: Any | None = None) -> None:
        self.store = store or InMemoryStore()

    async def read_state(self, circuit_id: str) -> CircuitState:
        return await self.store.read_state(circuit_id)

    async def transition(self, circuit_id: str, updates: Mapping[str, Any]) -> CircuitState:
        return await self.store.transition(circuit_id, updates)

    async def record_sequence(self, circuit_id: str, sequence: list[Mapping[str, Any]]) -> CircuitState:
        state = await self.read_state(circuit_id)
        sequence_hash = self.sequence_hash(sequence)
        repeated = state.repeated_sequence_count + 1 if state.last_sequence_hash == sequence_hash else 1
        return await self.transition(
            circuit_id,
            {
                "last_sequence_hash": sequence_hash,
                "repeated_sequence_count": repeated,
                "failure_count": state.failure_count + 1,
            },
        )

    async def open_circuit(self, circuit_id: str, reason: str) -> CircuitState:
        state = await self.read_state(circuit_id)
        return await self.transition(
            circuit_id,
            {
                "status": "open",
                "opened_reason": reason,
                "failure_count": state.failure_count + 1,
            },
        )

    async def record_tool_call(self, circuit_id: str, window_seconds: float) -> CircuitState:
        now = time.time()
        state = await self.read_state(circuit_id)
        timestamps = tuple(ts for ts in state.tool_call_timestamps if now - ts <= window_seconds) + (now,)
        return await self.transition(circuit_id, {"tool_call_timestamps": timestamps})

    async def record_progress(self, circuit_id: str) -> CircuitState:
        now = time.time()
        state = await self.read_state(circuit_id)
        return await self.transition(circuit_id, {"progress_timestamps": state.progress_timestamps + (now,)})

    @staticmethod
    def sequence_hash(sequence: list[Mapping[str, Any]]) -> str:
        encoded = json.dumps(sequence, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
