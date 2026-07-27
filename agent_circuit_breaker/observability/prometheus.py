"""Optional Prometheus exporter."""

from __future__ import annotations

from typing import Any

from .events import PipelineEvent


class PrometheusExporter:
    """Export pipeline event counters through prometheus-client."""

    def __init__(self, *, registry: Any | None = None, namespace: str = "agent_circuit_breaker") -> None:
        try:
            from prometheus_client import Counter  # type: ignore
        except ImportError as exc:
            raise ImportError("PrometheusExporter requires the optional 'prometheus' extra") from exc

        self.events_total = Counter(
            f"{namespace}_pipeline_events_total",
            "Pipeline events emitted by Agent Circuit Breaker.",
            ("event_type", "tool_name"),
            registry=registry,
        )
        self.denials_total = Counter(
            f"{namespace}_pipeline_denials_total",
            "Pipeline denials emitted by Agent Circuit Breaker.",
            ("guard_id", "tool_name"),
            registry=registry,
        )

    async def export(self, event: PipelineEvent) -> None:
        self.events_total.labels(event.event_type, event.tool_name).inc()
        if event.event_type == "GuardDenied":
            self.denials_total.labels(str(event.metadata.get("guard_id", "unknown")), event.tool_name).inc()
