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
```

Expected result for the smoke test:

```text
Verdict: BLOCK
```

## Current Development Focus

The current target is `v0.1.0-alpha.1`: filesystem safety alpha with stable CLI behavior and complete project documentation for the implemented scope.
