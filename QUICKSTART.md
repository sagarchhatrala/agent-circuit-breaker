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
```

Expected result for the smoke test:

```text
Verdict: BLOCK
```

## Current Development Focus

The current target is `v0.3.0-alpha.1`: filesystem, command, and SQL safety alpha with enforced rules for scoped destructive patterns.
