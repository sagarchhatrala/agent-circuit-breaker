"""Measure a full local workflow path, including durable history growth."""
import asyncio
import json
import platform
import statistics
import tempfile
import time
from pathlib import Path

from agent_circuit_breaker.demo import initialize_fixture
from agent_circuit_breaker.workflow import Workflow


async def main():
    with tempfile.TemporaryDirectory(prefix='acb-latency-') as directory:
        root = Path(directory)
        policy = initialize_fixture(root / 'workspace')
        workflow = Workflow(root / 'workspace', root / 'state', policy)
        await workflow.start()
        samples = []
        for _ in range(80):
            start = time.perf_counter()
            result = await workflow.call('read_file', {'path': 'incident.txt'})
            samples.append((time.perf_counter() - start) * 1000)
            assert result['decision'] == 'ALLOW'
        print(json.dumps({'python': platform.python_version(), 'os': platform.system(),
            'machine': platform.machine(), 'samples': len(samples),
            'operation': 'full read_file path, SQLite + HMAC provenance',
            'p50_ms': statistics.median(samples), 'p95_ms': sorted(samples)[75],
            'first10_ms': statistics.mean(samples[:10]),
            'last10_ms': statistics.mean(samples[-10:]), 'total_ms': sum(samples),
            'db_bytes': (root / 'state/runtime.sqlite3').stat().st_size}, indent=2))


if __name__ == '__main__':
    asyncio.run(main())
