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

## Assumptions

- The integration invokes Agent Circuit Breaker before execution.
- The integration treats `BLOCK` and `ERROR` as stop conditions.
- The integration has an explicit policy for `UNKNOWN`.
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
