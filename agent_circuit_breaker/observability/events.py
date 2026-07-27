"""Pipeline event bus and dependency-free exporters."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Mapping, Tuple


@dataclass(frozen=True)
class PipelineEvent:
    """One asynchronous pipeline event."""

    event_type: str
    request_id: str
    agent_id: str
    tool_name: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


class EventBus:
    """Fire-and-forget async event bus for exporters."""

    def __init__(self, exporters: Tuple[Any, ...] = ()) -> None:
        self.exporters = exporters

    def emit(self, event: PipelineEvent) -> None:
        for exporter in self.exporters:
            try:
                asyncio.create_task(exporter.export(event))
            except RuntimeError:
                # No running event loop; exporters must never break core logic.
                pass


class LoggingExporter:
    """Small stdlib logging exporter."""

    def __init__(self, logger_name: str = "agent_circuit_breaker.pipeline") -> None:
        self.logger = logging.getLogger(logger_name)

    async def export(self, event: PipelineEvent) -> None:
        self.logger.info(
            "pipeline_event=%s request_id=%s agent_id=%s tool=%s metadata=%s",
            event.event_type,
            event.request_id,
            event.agent_id,
            event.tool_name,
            dict(event.metadata),
        )
