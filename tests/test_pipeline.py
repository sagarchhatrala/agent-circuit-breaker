import asyncio
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

from agent_circuit_breaker import AgentCircuitBreaker, AgentContext, GuardResult, PipelineEngine, benchmark_pipeline
from agent_circuit_breaker.core.context import current_context
from agent_circuit_breaker.guards import (
    ContextWindowBreaker,
    FilesystemGuard,
    NetworkEgressGuard,
    PackageInstallGuard,
    SequenceBreakerGuard,
    ShellGuard,
)
from agent_circuit_breaker.observability import OTelExporter, PrometheusExporter
from agent_circuit_breaker.observability.events import PipelineEvent
from agent_circuit_breaker.state import InMemoryStore, RedisStore, SQLiteStore, StateManager


class AllowGuard:
    guard_id = "allow_guard"

    async def evaluate(self, context):
        return GuardResult.allow(self.guard_id, "ok")


class DenyGuard:
    guard_id = "deny_guard"

    async def evaluate(self, context):
        return GuardResult.deny(self.guard_id, "blocked")


class ErrorGuard:
    guard_id = "error_guard"

    async def evaluate(self, context):
        raise RuntimeError("boom")


class ContextGuard:
    guard_id = "context_guard"

    async def evaluate(self, context):
        active = current_context()
        if active and active.request_id == context.request_id:
            return GuardResult.allow(self.guard_id, "context propagated")
        return GuardResult.deny(self.guard_id, "context missing")


class TestPipelineArchitecture(unittest.TestCase):
    def test_context_and_result_dtos(self):
        context = AgentContext(
            request_id="req-1",
            agent_id="agent",
            tool_name="shell",
            tool_args={"command": "git status"},
        )
        result = GuardResult.deny("guard", "reason")

        self.assertEqual(context.action_text(), "git status")
        self.assertEqual(result.verdict, "deny")

    def test_pipeline_allows_when_guard_allows(self):
        result = asyncio.run(
            PipelineEngine([AllowGuard()]).evaluate(
                AgentContext("req-1", "agent", "shell", {"command": "git status"})
            )
        )

        self.assertTrue(result.allowed)

    def test_pipeline_fails_closed_when_guard_raises(self):
        result = asyncio.run(
            PipelineEngine([ErrorGuard(), AllowGuard()]).evaluate(
                AgentContext("req-1", "agent", "shell", {"command": "git status"})
            )
        )

        self.assertEqual(result.verdict, "deny")
        self.assertEqual(result.denied_by, "error_guard")

    def test_contextvars_propagate_to_guard(self):
        result = asyncio.run(
            PipelineEngine([ContextGuard()]).evaluate(
                AgentContext("req-ctx", "agent", "shell", {"command": "git status"})
            )
        )

        self.assertTrue(result.allowed)

    def test_pipeline_cancels_remaining_guards_on_deny(self):
        started = asyncio.Event()

        class SlowGuard:
            guard_id = "slow_guard"

            def __init__(self):
                self.cancelled = False

            async def evaluate(self, context):
                started.set()
                try:
                    await asyncio.sleep(10)
                except asyncio.CancelledError:
                    self.cancelled = True
                    raise
                return GuardResult.allow(self.guard_id, "late")

        class DelayedDenyGuard:
            guard_id = "delayed_deny_guard"

            async def evaluate(self, context):
                await started.wait()
                return GuardResult.deny(self.guard_id, "blocked")

        slow = SlowGuard()
        result = asyncio.run(
            PipelineEngine([slow, DelayedDenyGuard()]).evaluate(
                AgentContext("req-fast", "agent", "shell", {"command": "rm -rf /tmp/x"})
            )
        )

        self.assertEqual(result.verdict, "deny")
        self.assertTrue(slow.cancelled)

    def test_sdk_sync_blocks_known_destructive_command(self):
        breaker = AgentCircuitBreaker(guards=[ShellGuard()])

        result = breaker.evaluate_tool_call_sync(tool_name="shell", tool_args={"command": "rm -rf /tmp/x"})

        self.assertFalse(result.allowed)
        self.assertEqual(result.denied_by, "shell_guard")

    def test_sdk_async_allows_plain_command(self):
        async def run():
            breaker = AgentCircuitBreaker(guards=[ShellGuard()])
            return await breaker.evaluate_tool_call(tool_name="shell", tool_args={"command": "git status"})

        result = asyncio.run(run())

        self.assertTrue(result.allowed)


class TestStateStores(unittest.TestCase):
    def test_in_memory_store_transitions_atomically(self):
        async def run():
            store = InMemoryStore()
            state = await store.transition("circuit", {"status": "open"})
            return state

        state = asyncio.run(run())

        self.assertEqual(state.status, "open")

    def test_redis_store_uses_atomic_eval_contract(self):
        class FakeRedis:
            def __init__(self):
                self.payloads = {}

            async def get(self, key):
                return self.payloads.get(key)

            async def eval(self, script, key_count, key, circuit_id, updates):
                payload = self.payloads.get(key)
                state = json.loads(payload) if payload else {
                    "circuit_id": circuit_id,
                    "status": "closed",
                    "failure_count": 0,
                    "version": 0,
                    "repeated_sequence_count": 0,
                    "metadata": {},
                    "tool_call_timestamps": [],
                    "progress_timestamps": [],
                }
                state.update(json.loads(updates))
                state["version"] += 1
                encoded = json.dumps(state, sort_keys=True)
                self.payloads[key] = encoded
                return encoded

        async def run():
            store = RedisStore(client=FakeRedis())
            await store.transition("circuit", {"status": "open"})
            return await store.read_state("circuit")

        state = asyncio.run(run())

        self.assertEqual(state.status, "open")
        self.assertEqual(state.version, 1)
        self.assertEqual(state.version, 1)

    def test_sqlite_store_persists_state(self):
        async def run(path):
            store = SQLiteStore(path)
            await store.transition("circuit", {"status": "open"})
            return await SQLiteStore(path).read_state("circuit")

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            state = asyncio.run(run(str(Path(temp_dir) / "state.sqlite3")))

        self.assertEqual(state.status, "open")


class TestPipelineGuards(unittest.TestCase):
    def test_shell_guard_blocks_unapproved_operator(self):
        result = asyncio.run(
            ShellGuard().evaluate(
                AgentContext("req", "agent", "shell", {"command": "echo ok; rm -rf /tmp/x"})
            )
        )

        self.assertEqual(result.verdict, "deny")

    def test_filesystem_guard_blocks_quarantined_extension(self):
        result = asyncio.run(
            FilesystemGuard().evaluate(
                AgentContext("req", "agent", "filesystem", {"path": "scripts/install.sh", "operation": "write"})
            )
        )

        self.assertEqual(result.verdict, "deny")

    def test_filesystem_guard_enforces_directory_permissions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            allowed = str(Path(temp_dir) / "allowed")
            denied = str(Path(temp_dir) / "denied")
            Path(allowed).mkdir()
            Path(denied).mkdir()
            guard = FilesystemGuard({allowed: {"read", "write"}})
            result = asyncio.run(
                guard.evaluate(
                    AgentContext("req", "agent", "filesystem", {"path": str(Path(denied) / "x.py"), "operation": "write"})
                )
            )

        self.assertEqual(result.verdict, "deny")

    def test_network_guard_blocks_metadata_endpoint(self):
        result = asyncio.run(
            NetworkEgressGuard().evaluate(
                AgentContext("req", "agent", "http", {"url": "http://169.254.169.254/latest/meta-data"})
            )
        )

        self.assertEqual(result.verdict, "deny")

    def test_package_guard_requires_index_url(self):
        result = asyncio.run(
            PackageInstallGuard(required_index_url="https://packages.example/simple").evaluate(
                AgentContext("req", "agent", "shell", {"command": "pip install requests"})
            )
        )

        self.assertEqual(result.verdict, "deny")

    def test_package_guard_blocks_unallowlisted_resolved_dependency(self):
        result = asyncio.run(
            PackageInstallGuard(
                allowed_packages={"requests"},
                allowed_transitive_packages={"requests", "urllib3"},
            ).evaluate(
                AgentContext(
                    "req",
                    "agent",
                    "shell",
                    {
                        "command": "pip install requests",
                        "resolved_dependencies": ["requests", "urllib3", "evilpkg"],
                    },
                )
            )
        )

        self.assertEqual(result.verdict, "deny")
        self.assertEqual(result.metadata["packages"], ["evilpkg"])

    def test_package_guard_accepts_lockfile_dependencies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "requirements.lock"
            lockfile.write_text("requests==2.32.0\nurllib3==2.2.0\n", encoding="utf-8")
            result = asyncio.run(
                PackageInstallGuard(
                    allowed_packages={"requests"},
                    allowed_transitive_packages={"requests", "urllib3"},
                    lockfile_path=str(lockfile),
                ).evaluate(
                    AgentContext("req", "agent", "shell", {"command": "pip install requests"})
                )
            )

        self.assertEqual(result.verdict, "allow")

    def test_context_window_breaker_blocks_large_payload(self):
        result = asyncio.run(
            ContextWindowBreaker(max_tokens=3).evaluate(
                AgentContext("req", "agent", "llm", {"payload": "one two three four"})
            )
        )

        self.assertEqual(result.verdict, "deny")

    def test_sequence_breaker_blocks_repeated_sequence(self):
        async def run():
            manager = StateManager()
            guard = SequenceBreakerGuard(manager, max_repeats=2)
            context = AgentContext("req", "agent", "shell", {"command": "git status"}, circuit_id="loop")
            first = await guard.evaluate(context)
            second = await guard.evaluate(context)
            return first, second

        first, second = asyncio.run(run())

        self.assertEqual(first.verdict, "allow")
        self.assertEqual(second.verdict, "deny")


class TestPipelineEnterpriseIntegrations(unittest.TestCase):
    def test_pipeline_benchmark_reports_timings(self):
        async def run():
            return await benchmark_pipeline(
                PipelineEngine([AllowGuard()]),
                lambda index: AgentContext(f"req-{index}", "agent", "shell", {"command": "git status"}),
                iterations=3,
            )

        benchmark = asyncio.run(run())

        self.assertEqual(benchmark.iterations, 3)
        self.assertGreaterEqual(benchmark.average_ms, 0)

    def test_otel_exporter_accepts_injected_tracer(self):
        class FakeSpan:
            def __init__(self):
                self.attributes = {}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return None

            def set_attributes(self, attributes):
                self.attributes.update(attributes)

        class FakeTracer:
            def __init__(self):
                self.span = FakeSpan()

            def start_as_current_span(self, name):
                self.name = name
                return self.span

        tracer = FakeTracer()
        exporter = OTelExporter(tracer=tracer)

        asyncio.run(exporter.export(PipelineEvent("PipelineStarted", "req", "agent", "shell")))

        self.assertEqual(tracer.name, "agent_circuit_breaker.pipeline_event")
        self.assertEqual(tracer.span.attributes["acb.request_id"], "req")

    def test_prometheus_exporter_uses_optional_counter(self):
        class FakeMetric:
            def __init__(self):
                self.count = 0

            def labels(self, *args):
                self.labels_seen = args
                return self

            def inc(self):
                self.count += 1

        metrics = []

        def fake_counter(*args, **kwargs):
            metric = FakeMetric()
            metrics.append(metric)
            return metric

        previous = sys.modules.get("prometheus_client")
        sys.modules["prometheus_client"] = types.SimpleNamespace(Counter=fake_counter)
        try:
            exporter = PrometheusExporter()
            asyncio.run(exporter.export(PipelineEvent("GuardDenied", "req", "agent", "shell", {"guard_id": "guard"})))
        finally:
            if previous is None:
                sys.modules.pop("prometheus_client", None)
            else:
                sys.modules["prometheus_client"] = previous

        self.assertEqual(metrics[0].count, 1)
        self.assertEqual(metrics[1].count, 1)


if __name__ == "__main__":
    unittest.main()
