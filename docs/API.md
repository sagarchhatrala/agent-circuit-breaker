# Public Python API

Agent Circuit Breaker exposes a small package-level API for integrations that want deterministic safety checks without invoking the CLI.

The current API is alpha and intentionally small.

## `evaluate_action(action, rule_file_path=None)`

Evaluates an action string against built-in rules and optional external JSON rules.

```python
from agent_circuit_breaker import evaluate_action

result = evaluate_action("rm -rf /")
```

Important result fields:

- `verdict`: `allow`, `block`, `error`, or `unknown`.
- `decision`: `ALLOW`, `BLOCK`, `ERROR`, or `UNKNOWN`.
- `matched_rule`: matching rule ID when a rule matched.
- `rule_details`: matching rule details when available.
- `operation_analysis`: filesystem-oriented analysis.
- `command_analysis`: command-oriented analysis.
- `sql_analysis`: SQL-oriented analysis.
- `error`: error text when evaluation fails.

Custom rule files can be appended after built-in rules:

```python
result = evaluate_action(
    "deploy production",
    rule_file_path="docs/examples/rules/custom_deploy_guard.json",
)
```

Invalid custom rule files fail closed and return an `error` verdict before action evaluation.

## `validate_rule_file(path)`

Validates an external JSON rule file and returns path context, validity, errors, and the parsed definition when valid.

```python
from agent_circuit_breaker import validate_rule_file

result = validate_rule_file("docs/examples/rules/custom_deploy_guard.json")
```

## `rule_schema_metadata()`

Returns deterministic metadata for the supported external rule schema.

```python
from agent_circuit_breaker import rule_schema_metadata

metadata = rule_schema_metadata()
```

## Stability

The v0.6 API is the first public alpha surface. It is intended to become the v1.0 integration surface after adversarial testing, documentation hardening, and release-candidate review.
