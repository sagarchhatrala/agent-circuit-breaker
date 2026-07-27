"""Optional OpenTelemetry exporter."""

from __future__ import annotations

from typing import Any

from .events import PipelineEvent


class OTelExporter:
    """Emit pipeline events on an OpenTelemetry span."""

    def __init__(self, tracer_name: str = "agent_circuit_breaker.pipeline", *, tracer: Any | None = None) -> None:
        if tracer is not None:
            self.tracer = tracer
            return
        try:
            from opentelemetry import trace  # type: ignore
        except ImportError as exc:
            raise ImportError("OTelExporter requires the optional 'otel' extra") from exc
        self.tracer = trace.get_tracer(tracer_name)

    async def export(self, event: PipelineEvent) -> None:
        attributes = {
            "acb.event_type": event.event_type,
            "acb.request_id": event.request_id,
            "acb.agent_id": event.agent_id,
            "acb.tool_name": event.tool_name,
        }
        for key, value in event.metadata.items():
            attributes[f"acb.metadata.{key}"] = str(value)
        with self.tracer.start_as_current_span("agent_circuit_breaker.pipeline_event") as span:
            span.set_attributes(attributes)
