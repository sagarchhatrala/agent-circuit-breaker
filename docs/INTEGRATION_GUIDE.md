# Integration Guide

Agent Circuit Breaker should sit between an agent and any execution layer.

Recommended flow:

1. Agent proposes an action.
2. Integration evaluates the action with Agent Circuit Breaker.
3. Integration executes only if the result is `ALLOW`.
4. Integration stops, logs, or asks for review on `BLOCK`, `ERROR`, or `UNKNOWN`.

## CLI Gate

Use the CLI when the integration can shell out before execution:

```bash
circuit-breaker check "rm -rf /"
```

Exit codes:

- `0`: allowed.
- `1`: blocked or error.
- `2`: unknown.

Recommended shell policy:

- continue only on exit code `0`.
- stop on exit code `1`.
- stop or require review on exit code `2`.

## Python API Gate

Use the Python API when the integration runs in Python:

```python
from agent_circuit_breaker import evaluate_action

result = evaluate_action("rm -rf /")
if result["verdict"] != "allow":
    raise RuntimeError(result["verdict"])
```

Custom rules:

```python
from agent_circuit_breaker import evaluate_action

result = evaluate_action(
    "deploy production",
    rule_file_path="docs/examples/rules/custom_deploy_guard.json",
)
```

Invalid custom rule files return an `error` verdict and include `custom_rules` error details.

## Rule Validation

Validate custom rule files before using them:

```bash
circuit-breaker validate-rules docs/examples/rules/custom_deploy_guard.json
```

or:

```python
from agent_circuit_breaker import validate_rule_file

result = validate_rule_file("docs/examples/rules/custom_deploy_guard.json")
```

Only use rule files where `is_valid` is `True`.

## Handling `UNKNOWN`

`UNKNOWN` does not mean safe. It means the current deterministic rules did not classify the action.

Recommended policies:

- stop and ask for human review.
- route to a separate allowlist.
- log and block by default in unattended automation.

## Placement

Place the gate as close as possible to execution:

- before shell command execution.
- before database migration execution.
- before file operation helpers.
- before deployment automation.

Avoid designs where an agent can call an execution path that bypasses the gate.

## Logging

Store enough result data to investigate decisions:

- action text.
- verdict and decision.
- matched rule.
- operation, command, and SQL analysis.
- custom rule validation errors when present.

Do not log secrets or sensitive command arguments unless your environment already permits that data in logs.
