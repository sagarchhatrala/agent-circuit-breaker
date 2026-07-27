"""Small benchmark helper for pipeline integrations."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from .context import AgentContext
from .pipeline import PipelineEngine


@dataclass(frozen=True)
class PipelineBenchmark:
    """Pipeline timing summary in milliseconds."""

    iterations: int
    total_ms: float
    average_ms: float
    min_ms: float
    max_ms: float


async def benchmark_pipeline(
    engine: PipelineEngine,
    context_factory: Callable[[int], AgentContext],
    *,
    iterations: int = 100,
) -> PipelineBenchmark:
    """Measure pipeline evaluation overhead for a caller-provided workload."""
    if iterations < 1:
        raise ValueError("iterations must be at least 1")

    timings: list[float] = []
    for index in range(iterations):
        started = time.perf_counter()
        await engine.evaluate(context_factory(index))
        timings.append((time.perf_counter() - started) * 1000)

    total = sum(timings)
    return PipelineBenchmark(
        iterations=iterations,
        total_ms=total,
        average_ms=total / iterations,
        min_ms=min(timings),
        max_ms=max(timings),
    )
