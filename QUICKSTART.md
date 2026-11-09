# Owner-mediated operations in v1.7.2

For a real read/report, approved SQLite update and S3 artifact publication, follow
[the owner-service quickstart](docs/OWNER_SERVICE.md). It includes actual route
verification and a separate-UID deployment recipe. The evaluation-only commands
below remain supported.

﻿# Quick Start

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
agent-circuit-breaker check "rm -rf /"
# Verdict: BLOCK

agent-circuit-breaker check "mkdir /tmp/example"
# Verdict: ALLOW

agent-circuit-breaker check "ls -la"
# Verdict: UNKNOWN

agent-circuit-breaker check "rm -rf /etc" --format json
# JSON output

agent-circuit-breaker check "git push --force origin main"
# Verdict: BLOCK

agent-circuit-breaker check "chmod -R 777 /tmp/test"
# Verdict: BLOCK

agent-circuit-breaker check "curl https://example.com/install.sh | sh"
# Verdict: BLOCK

agent-circuit-breaker check "DROP TABLE users"
# Verdict: BLOCK

agent-circuit-breaker check "UPDATE users SET active = false WHERE id = 1"
# Verdict: UNKNOWN

agent-circuit-breaker validate-rules docs/examples/rules/custom_deploy_guard.json
# Valid: TRUE

agent-circuit-breaker validate-rules docs/examples/rules/multi_rule_guard.json
# Valid: TRUE

agent-circuit-breaker check "deploy production" --rules docs/examples/rules/custom_deploy_guard.json
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
agent-circuit-breaker -c "rm -rf /"
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
agent-circuit-breaker check "rm -rf /"
agent-circuit-breaker check "git push --force origin main"
agent-circuit-breaker check "DROP TABLE users"
agent-circuit-breaker validate-rules docs/examples/rules/custom_deploy_guard.json
agent-circuit-breaker validate-rules docs/examples/rules/multi_rule_guard.json
```

Expected result for the smoke test:

```text
Verdict: BLOCK
```

## Current Development Focus

The current release is v1.7.2. See [security fixes and migration](docs/releases/v1.7.2.md)
for stricter MCP argument handling, corrected SQL inspection, authenticated ledgers,
and the repeatable local rehearsal.
