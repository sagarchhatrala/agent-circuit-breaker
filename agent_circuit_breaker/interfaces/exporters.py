"""Exporter protocol contract."""

from __future__ import annotations

from typing import Protocol

from agent_circuit_breaker.observability.events import PipelineEvent


class ExporterProtocol(Protocol):
    """Asynchronous event exporter contract."""

    async def export(self, event: PipelineEvent) -> None:
        """Export a pipeline event without blocking core business logic."""
        ...
