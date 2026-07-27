# Pipeline Architecture

`v1.4.9` adds a dependency-free async pipeline for integrations that want to evaluate full tool-call contexts instead of only command strings.

The existing CLI, `evaluate_action(...)`, and `evaluate_trajectory(...)` APIs remain supported. The pipeline is additive.

## Directory Layout

```text
agent_circuit_breaker/
  core/              # AgentContext, GuardResult, PipelineEngine, SDK facade
  interfaces/        # Guard, state store, hook, and exporter Protocol contracts
  state/             # InMemoryStore, SQLiteStore, StateManager
  guards/            # Shell, filesystem, network, package, and loop guards
  observability/     # dependency-free event bus and logging exporter
```

## Context And Results

`AgentContext` is immutable and carries:

- `request_id`
- `agent_id`
- `tool_name`
- `tool_args`
- `span_links`
- optional `circuit_id`

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

`PackageInstallGuard` evaluates the command that the agent is about to run. Full transitive dependency enforcement requires a lockfile, package-manager dry run, or integration-supplied dependency list because core intentionally does not contact package registries.

## State Stores

`InMemoryStore` is intended for tests and single-process local use.

`SQLiteStore` persists state locally and uses SQLite transactions for atomic transitions. Redis is intentionally not included in core because this package keeps runtime dependencies at zero.

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

`LoggingExporter` is included. OTel and Prometheus exporters are intentionally not included in this patch to preserve zero runtime dependencies.
