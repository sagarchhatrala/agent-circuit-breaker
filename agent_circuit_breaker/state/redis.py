"""Optional Redis-backed circuit state store."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Mapping

from .models import CircuitState


class RedisStore:
    """Redis state store using a Lua script for atomic transitions.

    The Redis client is optional. Install with ``agent-circuit-breaker[redis]``
    or pass a compatible async client for tests and custom integrations.
    """

    _TRANSITION_SCRIPT = """
local key = KEYS[1]
local circuit_id = ARGV[1]
local updates = cjson.decode(ARGV[2])
local payload = redis.call("GET", key)
local state
if payload then
  state = cjson.decode(payload)
else
  state = {
    circuit_id = circuit_id,
    status = "closed",
    failure_count = 0,
    version = 0,
    repeated_sequence_count = 0,
    metadata = {},
    tool_call_timestamps = {},
    progress_timestamps = {}
  }
end
for name, value in pairs(updates) do
  state[name] = value
end
state["version"] = (state["version"] or 0) + 1
local encoded = cjson.encode(state)
redis.call("SET", key, encoded)
return encoded
"""

    def __init__(self, url: str = "redis://localhost:6379/0", *, client: Any | None = None, key_prefix: str = "acb") -> None:
        self.key_prefix = key_prefix.rstrip(":")
        if client is not None:
            self.client = client
            return
        try:
            import redis.asyncio as redis  # type: ignore
        except ImportError as exc:
            raise ImportError("RedisStore requires the optional 'redis' extra") from exc
        self.client = redis.from_url(url)

    async def read_state(self, circuit_id: str) -> CircuitState:
        payload = await self.client.get(self._key(circuit_id))
        if payload is None:
            return CircuitState(circuit_id=circuit_id)
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        return _decode(payload)

    async def transition(self, circuit_id: str, updates: Mapping[str, Any]) -> CircuitState:
        encoded_updates = json.dumps(_json_ready(dict(updates)), sort_keys=True)
        payload = await self.client.eval(self._TRANSITION_SCRIPT, 1, self._key(circuit_id), circuit_id, encoded_updates)
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        return _decode(payload)

    def _key(self, circuit_id: str) -> str:
        return f"{self.key_prefix}:state:{circuit_id}"


def _decode(payload: str) -> CircuitState:
    data = json.loads(payload)
    data.setdefault("status", "closed")
    data.setdefault("failure_count", 0)
    data.setdefault("version", 0)
    data.setdefault("repeated_sequence_count", 0)
    data.setdefault("metadata", {})
    data["tool_call_timestamps"] = tuple(data.get("tool_call_timestamps", ()))
    data["progress_timestamps"] = tuple(data.get("progress_timestamps", ()))
    return CircuitState(**data)


def _json_ready(value: Any) -> Any:
    if isinstance(value, CircuitState):
        return asdict(value)
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_ready(item) for key, item in value.items()}
    return value
