# Pipeline Architecture

`v1.4.9` added a dependency-free async pipeline for integrations that want to evaluate full tool-call contexts instead of only command strings. `v1.5.0` adds optional enterprise integrations around that core while keeping the default install dependency-free.

The existing CLI, `evaluate_action(...)`, and `evaluate_trajectory(...)` APIs remain supported. The pipeline is additive.

## Directory Layout

```text
agent_circuit_breaker/
  core/              # AgentContext, GuardResult, PipelineEngine, SDK facade
  interfaces/        # Guard, state store, hook, and exporter Protocol contracts
  state/             # InMemoryStore, SQLiteStore, optional RedisStore, StateManager
  guards/            # Shell, filesystem, network, package, and loop guards
  observability/     # event bus, logging exporter, optional OTel/Prometheus exporters
```

## Context And Results

`AgentContext` is immutable and carries:

- `request_id`
- `agent_id`
- `tool_name`
- `tool_args`
- `span_links`
- optional `circuit_id`

Tool schemas are caller-defined, so the pipeline does not depend on fixed argument names. `AgentContext.string_values()` recursively exposes every nested string-valued argument, and `action_text()` combines those strings for guards that evaluate action text.

`GuardResult` returns `allow`, `deny`, or `unknown`. A guard should return `unknown` when the context is outside its domain. The pipeline denies immediately when any guard denies, allows when at least one guard allows and no guard denies, and returns `unknown` when no guard applies.

If a guard raises an exception, the pipeline converts it to `deny`.

## SDK Example

```python
from agent_circuit_breaker import AgentCircuitBreaker

breaker = AgentCircuitBreaker(max_context_tokens=120000)

result = breaker.evaluate_tool_call_sync(
    tool_name="shell",
    tool_args={"command": "rm -rf /"},
    agent_id="local-agent",
)

assert not result.allowed
```

Async callers should use:

```python
result = await breaker.evaluate_tool_call(
    tool_name="shell",
    tool_args={"command": "git status"},
)
```

## Included Guards

- `LegacyActionGuard`: calls the existing deterministic evaluator.
- `ShellGuard`: tokenizes shell commands, blocks unapproved shell operators, denied binaries, `rm -rf`, and forced git pushes.
- `FilesystemGuard`: canonicalizes paths with `os.path.realpath`, enforces directory permissions, and quarantines executable script extensions by default.
- `NetworkEgressGuard`: blocks RFC 1918/private, loopback, link-local, reserved, multicast, unspecified, and metadata IP targets.
- `PackageInstallGuard`: enforces package index and allowlist policies for `pip install` and `npm install`.
- `SequenceBreakerGuard`: hashes exact tool-name/tool-argument sequences and denies repeated loops.
- `ContextWindowBreaker`: performs a fast dependency-free token estimate before LLM payload submission.
- `HaltingHeuristicGuard`: denies excessive tool-call volume without a progress signal.

`PackageInstallGuard` evaluates the command that the agent is about to run. Full transitive dependency enforcement requires a lockfile, package-manager dry run, or integration-supplied dependency list because core intentionally does not contact package registries. In `v1.5.0`, callers can provide `resolved_dependencies`, `dependencies`, or a lockfile path so the guard can enforce transitive allowlists deterministically.

`NetworkEgressGuard` does not perform live DNS resolution. It blocks literal private/internal IP targets and configured metadata hosts without creating outbound DNS side effects during evaluation.

## State Stores

`InMemoryStore` is intended for tests and single-process local use.

`SQLiteStore` persists state locally and uses SQLite transactions for atomic transitions.

`RedisStore` is available through the optional `redis` extra and uses a Lua script for atomic transitions:

```bash
python -m pip install "agent-circuit-breaker[redis]"
```

```python
from agent_circuit_breaker.state import RedisStore, StateManager

state_manager = StateManager(RedisStore("redis://localhost:6379/0"))
```

## File Writes

The library does not claim OS-level interception of arbitrary file writes. File-write validation applies when an integration routes a proposed write through the SDK/pipeline, for example with:

```python
await breaker.evaluate_tool_call(
    tool_name="filesystem",
    tool_args={"path": "scripts/install.sh", "operation": "write"},
)
```

Blocking writes before they reach the filesystem requires an editor integration, MCP proxy, filesystem proxy, or OS sandbox.

## Observability

The pipeline emits dependency-free events:

- `PipelineStarted`
- `GuardDenied`
- `PipelineCompleted`

`LoggingExporter` is included in the default install. `OTelExporter` and `PrometheusExporter` are optional extras:

```bash
python -m pip install "agent-circuit-breaker[otel]"
python -m pip install "agent-circuit-breaker[prometheus]"
```

```python
from agent_circuit_breaker.observability import EventBus, PrometheusExporter

event_bus = EventBus((PrometheusExporter(),))
```

## Benchmarking

`benchmark_pipeline(...)` measures caller-owned workloads without hard-coding a universal latency claim:

```python
from agent_circuit_breaker import AgentContext, PipelineEngine, benchmark_pipeline

summary = await benchmark_pipeline(
    PipelineEngine([]),
    lambda index: AgentContext(f"req-{index}", "agent", "shell", {"command": "git status"}),
)
```
