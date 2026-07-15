# Public Python API

Agent Circuit Breaker exposes a small package-level API for integrations that want deterministic safety checks without invoking the CLI.

The current API is stable for v1.x compatible releases and intentionally small.

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

The detailed JSON-compatible result contract is documented in [JSON_OUTPUT_CONTRACT.md](JSON_OUTPUT_CONTRACT.md).

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

The public API became stable at v1.0. Compatible v1.x releases may add result fields, built-in rules, docs, and examples without changing the meaning of existing fields or the external rule schema version.
