# Security Model

Agent Circuit Breaker is a deterministic pre-execution safety checkpoint for agent-proposed actions.

It is not a sandbox. It does not execute, isolate, monitor, roll back, or prevent operating-system actions by itself. Callers must place it before execution and must honor its decisions.

## Trust Boundary

The trusted boundary is the local Agent Circuit Breaker process and the rule set loaded from disk.

Untrusted inputs include:

- LLM or agent-generated actions.
- User-provided command text.
- SQL text proposed by an agent.
- External JSON rule files until they pass validation.

The caller is responsible for:

- sending every proposed action to Agent Circuit Breaker before execution.
- treating `BLOCK` and `ERROR` as stop conditions.
- deciding whether `UNKNOWN` should stop or require human review.
- preventing bypass paths that execute actions without evaluation.

## Decision Model

Agent Circuit Breaker returns one of four decisions:

- `ALLOW`: recognized safe operation with no matching block rule.
- `BLOCK`: a built-in or custom rule matched and denied the action.
- `ERROR`: input, parsing, rule loading, or evaluation failed.
- `UNKNOWN`: no rule matched and the action is not recognized as safe.

The recommended integration policy is:

- execute only on `ALLOW`.
- stop on `BLOCK`.
- stop on `ERROR`.
- treat `UNKNOWN` as review-required unless the integration has a separate allowlist.

## Rule Ordering

Built-in rules are evaluated before custom rules.

This means a custom `allow` rule cannot override a built-in `block` rule. Custom rules are append-only policy extensions in the current design.

## Fail-Closed Behavior

The project intentionally treats these conditions as stop conditions:

- malformed command input.
- malformed SQL input.
- non-string action input.
- invalid JSON rule files.
- unsupported rule fields or matcher types.
- rule matcher exceptions.

CLI callers receive a non-zero exit code for `BLOCK`, `ERROR`, and `UNKNOWN`.

## Local-First Operation

The core package has no runtime dependency outside the Python standard library.

Agent Circuit Breaker does not:

- fetch remote rules.
- send telemetry.
- call an LLM.
- execute shell commands.
- connect to databases.

## Explicit Non-Goals

Agent Circuit Breaker is not:

- a sandbox.
- an antivirus tool.
- an endpoint monitor.
- an identity or permissions system.
- a complete shell parser.
- a complete SQL parser.
- a substitute for backups, access control, or least-privilege execution.

Use it as a deterministic gate in a broader defense-in-depth design.
