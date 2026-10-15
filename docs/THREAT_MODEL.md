# Threat Model

This document describes the threats Agent Circuit Breaker is designed to reduce and the threats it does not address.

## In Scope

### Accidental Destructive Filesystem Actions

An agent may propose recursive deletion, dangerous filesystem targets, or bulk delete patterns.

Mitigation:

- filesystem inspector analysis.
- built-in recursive delete and system path rules.
- explicit `BLOCK` decisions before execution.

### Dangerous Command Patterns

An agent may propose risky command operations such as force pushes, recursive world-writable permissions, or remote scripts piped to a shell.

Mitigation:

- command tokenization and segment splitting.
- built-in command risk rules.
- newline and shell-operator command chain inspection.

### Destructive SQL

An agent may propose destructive SQL such as `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`, or unqualified `DELETE` and `UPDATE`.

Mitigation:

- SQL tokenization and statement splitting.
- destructive SQL rule coverage.
- quoted strings and comments handled by the SQL inspector for supported cases.

### Malformed Model Output

An agent may produce malformed command or SQL text.

Mitigation:

- malformed command and SQL analysis returns `ERROR`.
- callers are expected to treat `ERROR` as a stop condition.

### Malformed MCP Tool Calls

An agent or MCP client may produce malformed `tools/call` JSON-RPC envelopes.

Mitigation:

- the MCP proxy rejects malformed `params`, missing tool names, and non-object
  `arguments` before forwarding.
- blocked requests receive a JSON-RPC error response when the request includes
  an `id`.

### Stateful Run Drift Through A Trusted Harness

An agent or subagent may propose actions that exceed the run contract after
earlier steps, such as using an unauthorized actor, replaying a different action
after approval, exceeding a local action limit, or continuing after a blocked
proposal.

Mitigation:

- `RuntimeGate` serializes proposals inside one local process.
- every proposal is evaluated against recorded run history before execution.
- only aggregate `allow` decisions set `authorized: true`.
- allowed proposals receive a single-use `authorization_id`.
- `execute_authorized` rejects forged and replayed authorizations before calling
  the executor and records a `started` event before side effects.
- `RuntimeToolExecutor` binds integration-controlled actor/tool metadata before
  authorization and rejects conflicting caller-supplied metadata before side
  effects.
- optional `actor_tokens` prevent simple caller-supplied actor spoofing when
  tokens are kept outside the model-visible environment.
- `record_outcome` binds execution reporting to an authorized action fingerprint
  in the same run.

### Invalid Custom Policies

Custom JSON rules may be malformed, unsupported, or accidentally duplicated.

Mitigation:

- schema validation before rule construction.
- duplicate rule ID rejection.
- unsupported matcher rejection.
- invalid rule files fail closed.

## Out Of Scope

Agent Circuit Breaker does not defend against:

- callers that ignore the result and execute anyway.
- actions executed through bypass paths that skip evaluation.
- compromised operating-system users.
- malicious local modification of built-in source code.
- complete shell grammar edge cases.
- complete SQL dialect edge cases.
- runtime effects after a command is executed.
- data exfiltration through channels not represented in the action text.
- network policy enforcement.
- containment of an agent that can bypass the trusted integration and call tools
  directly.
- durable recovery of in-memory runtime state after process crash or restart.
- cross-process runtime-state locking with the default in-memory store.
- recovery of a process killed after a tool side effect but before final outcome
  recording when using the in-memory runtime store.
- calls made directly to the underlying executor instead of through
  `RuntimeToolExecutor`.
- safe execution of artifacts after download when the download or execution path
  is not visible in the proposed action text.

## Assumptions

- The integration invokes Agent Circuit Breaker before execution.
- The integration treats `BLOCK` and `ERROR` as stop conditions.
- The integration has an explicit policy for `UNKNOWN`.
- For `RuntimeGate`, the integration also treats `PENDING_APPROVAL` as
  non-executable until a separate fresh approval validation succeeds.
- Actor tokens, when used, are held by trusted integration code and are not
  exposed to the LLM or delegated agent.
- Built-in package files are not maliciously modified.
- Custom rule files are local files that pass validation before use.

## Residual Risk

The inspectors are intentionally conservative and scoped. They catch known dangerous shapes; they do not prove that arbitrary action text is safe.

For production use, combine Agent Circuit Breaker with:

- least-privilege execution.
- environment isolation.
- backups and restore tests.
- code review for high-risk automation.
- explicit allowlists for known-safe workflows.
