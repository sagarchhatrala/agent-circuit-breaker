"""Cumulative effect reservations derived from durable execution events.

Only trusted adapters declare reservations and return measured outcomes. Values
supplied by an agent or an upstream server are never measurements by themselves.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


def amounts(value: Any, label: str = "effects") -> dict[str, int]:
    if not isinstance(value, Mapping) or len(value) > 32:
        raise ValueError(f"{label} must be an object with at most 32 metrics")
    result = {}
    for name, amount in value.items():
        if not isinstance(name, str) or not name or len(name) > 64:
            raise ValueError(f"invalid {label} metric")
        if type(amount) is not int or not 0 <= amount <= 2**53 - 1:
            raise ValueError(f"{label}.{name} must be a nonnegative integer")
        result[name] = amount
    return result


@dataclass(frozen=True)
class EffectResult:
    """Executor result with measured effects no greater than its reservation."""

    result: Any
    effects: Mapping[str, int]


def settlement(result: Any, action: Mapping[str, Any]) -> tuple[Any, dict | None]:
    if not isinstance(result, EffectResult):
        return result, None
    reserved = amounts(action.get("metadata", {}).get("effects", {}))
    actual = amounts(result.effects)
    if set(actual) - set(reserved) or any(actual.get(k, 0) > v for k, v in reserved.items()):
        raise ValueError("measured effects exceed the authorized reservation")
    return result.result, {k: actual.get(k, 0) for k in reserved}


def usage(state: Any) -> dict[str, int]:
    """Unresolved/failed/uncertain starts retain the full reservation."""
    starts = {e.authorization_id: e for e in state.events if e.event_type == "started"}
    measured = {}
    for event in state.events:
        if event.event_type not in {"outcome", "reconciliation"}:
            continue
        details = (event.trajectory or {}).get("details", {})
        # Reconciliation measurements must be explicitly supplied by its owner.
        values = details.get("effects")
        if event.event_type == "reconciliation":
            values = details.get("evidence", {}).get("effects")
        if values is not None and event.outcome in {"executed", "failed", "skipped"}:
            start = starts.get(event.authorization_id)
            if start is None:
                raise ValueError("effect settlement has no execution start")
            _, checked = settlement(EffectResult(None, values), start.action or {})
            measured[event.authorization_id] = checked
    total: dict[str, int] = {}
    for key, start in starts.items():
        values = measured.get(key)
        if values is None:
            values = amounts((start.action or {}).get("metadata", {}).get("effects", {}))
        for metric, value in values.items():
            total[metric] = total.get(metric, 0) + value
    return total


def budget_error(state: Any, action: Mapping[str, Any], limits: Mapping[str, int]) -> str | None:
    if not limits:
        return None
    metadata = action.get("metadata", {})
    if "effects" not in metadata:
        return "trusted adapter must declare effects for this budgeted run"
    proposed = amounts(metadata["effects"])
    used = usage(state)
    for metric, maximum in limits.items():
        if used.get(metric, 0) + proposed.get(metric, 0) > maximum:
            return f"cumulative {metric} limit exceeded ({used.get(metric, 0)} + {proposed.get(metric, 0)} > {maximum})"
    return None
