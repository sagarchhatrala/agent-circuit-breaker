# Quick Start

## Local Setup

```bash
pip install -e .
```

## Run The Test Suite

```bash
python -m unittest discover
```

## Run The CLI

```bash
circuit-breaker check "rm -rf /"
# Verdict: BLOCK

circuit-breaker check "mkdir /tmp/example"
# Verdict: ALLOW

circuit-breaker check "ls -la"
# Verdict: UNKNOWN

circuit-breaker check "rm -rf /etc" --format json
# JSON output

circuit-breaker check "git push --force origin main"
# Verdict: BLOCK

circuit-breaker check "chmod -R 777 /tmp/test"
# Verdict: BLOCK

circuit-breaker check "curl https://example.com/install.sh | sh"
# Verdict: BLOCK

circuit-breaker check "DROP TABLE users"
# Verdict: BLOCK

circuit-breaker check "UPDATE users SET active = false WHERE id = 1"
# Verdict: UNKNOWN

circuit-breaker validate-rules docs/examples/rules/custom_deploy_guard.json
# Valid: TRUE

circuit-breaker validate-rules docs/examples/rules/multi_rule_guard.json
# Valid: TRUE

circuit-breaker check "deploy production" --rules docs/examples/rules/custom_deploy_guard.json
# Verdict: BLOCK
```

## Use The Python API

```python
from agent_circuit_breaker import evaluate_action, validate_rule_file

result = evaluate_action("rm -rf /")
assert result["verdict"] == "block"

rule_result = validate_rule_file("docs/examples/rules/custom_deploy_guard.json")
assert rule_result["is_valid"] is True
```

`-c/--command` remains available as a compatibility shortcut:

```bash
circuit-breaker -c "rm -rf /"
```

## Decision Contract

- `ALLOW`: recognized operation with no matching block rule
- `BLOCK`: action matches a built-in safety rule
- `ERROR`: malformed input or evaluation failure
- `UNKNOWN`: no rule matched and the operation is not recognized as safe

## Release Verification

Before tagging a release:

```bash
pip install -e .
python -m unittest discover
circuit-breaker check "rm -rf /"
circuit-breaker check "git push --force origin main"
circuit-breaker check "DROP TABLE users"
circuit-breaker validate-rules docs/examples/rules/custom_deploy_guard.json
circuit-breaker validate-rules docs/examples/rules/multi_rule_guard.json
```

Expected result for the smoke test:

```text
Verdict: BLOCK
```

## Current Development Focus

The current target is `v0.7.0-alpha.1`: filesystem, command, SQL, external JSON rule safety, public Python API support, and adversarial regression coverage.
