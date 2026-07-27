"""SQLite-backed circuit state store."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from .models import CircuitState


class SQLiteStore:
    """SQLite state store using transactions for atomic transitions."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _initialize(self) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS circuit_state (
                    circuit_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                )
                """
            )
            connection.commit()

    async def read_state(self, circuit_id: str) -> CircuitState:
        return await asyncio.to_thread(self._read_state_sync, circuit_id)

    async def transition(self, circuit_id: str, updates: Mapping[str, Any]) -> CircuitState:
        return await asyncio.to_thread(self._transition_sync, circuit_id, dict(updates))

    def _read_state_sync(self, circuit_id: str) -> CircuitState:
        with self._lock, sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT payload FROM circuit_state WHERE circuit_id = ?",
                (circuit_id,),
            ).fetchone()
            if row is None:
                return CircuitState(circuit_id=circuit_id)
            return self._decode(row[0])

    def _transition_sync(self, circuit_id: str, updates: Mapping[str, Any]) -> CircuitState:
        with self._lock, sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload FROM circuit_state WHERE circuit_id = ?",
                (circuit_id,),
            ).fetchone()
            state = self._decode(row[0]) if row else CircuitState(circuit_id=circuit_id)
            payload = asdict(state)
            payload.update(updates)
            payload["version"] = state.version + 1
            next_state = self._decode(json.dumps(payload, sort_keys=True))
            connection.execute(
                """
                INSERT INTO circuit_state (circuit_id, payload)
                VALUES (?, ?)
                ON CONFLICT(circuit_id) DO UPDATE SET payload = excluded.payload
                """,
                (circuit_id, json.dumps(asdict(next_state), sort_keys=True)),
            )
            connection.commit()
            return next_state

    @staticmethod
    def _decode(payload: str) -> CircuitState:
        data = json.loads(payload)
        data["tool_call_timestamps"] = tuple(data.get("tool_call_timestamps", ()))
        data["progress_timestamps"] = tuple(data.get("progress_timestamps", ()))
        return CircuitState(**data)
