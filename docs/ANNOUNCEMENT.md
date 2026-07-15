# Agent Circuit Breaker v1.0 Announcement

Agent Circuit Breaker v1.0 is now available.

Agent Circuit Breaker is a deterministic safety gate for AI coding agents. It evaluates proposed actions before execution and returns explicit decisions: `ALLOW`, `BLOCK`, `ERROR`, or `UNKNOWN`.

## What It Protects Against

- Recursive filesystem deletion.
- Dangerous filesystem targets.
- Git force pushes.
- Recursive `chmod 777`.
- Remote scripts piped to shells.
- Destructive SQL statements.
- Invalid custom rule files.
- Malformed command and SQL inputs.

## Install

```bash
pip install agent-circuit-breaker
```

## CLI Example

```bash
circuit-breaker check "rm -rf /"
```

Expected result:

```text
Verdict: BLOCK
```

## Python Example

```python
from agent_circuit_breaker import evaluate_action

result = evaluate_action("rm -rf /")
assert result["verdict"] == "block"
```

## Notes

- The project is local-first and dependency-free at runtime.
- The external JSON rule schema is versioned.
- The public Python API and CLI contracts are stable as of v1.0.
- Agent Circuit Breaker is a deterministic gate, not a sandbox.

Project: https://github.com/sagarchhatrala/agent-circuit-breaker
