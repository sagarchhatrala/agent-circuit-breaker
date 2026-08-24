# Getting Started

This guide covers the shortest path from installation to a first protected
action. For broader integration patterns, see `INTEGRATION_GUIDE.md`.

## Install

```bash
python -m pip install agent-circuit-breaker
```

## Check An Action

```bash
agent-circuit-breaker check "rm -rf /etc"
agent-circuit-breaker check "ls /home"
```

`BLOCK`, `ERROR`, `UNKNOWN`, and `PENDING_APPROVAL` must not be treated as
permission to execute. Only `ALLOW` is executable by default.

## Use JSON Output

```bash
agent-circuit-breaker check "git push --force origin main" --format json
```

The JSON contract is documented in `JSON_OUTPUT_CONTRACT.md`.

## Add A Custom Rule

```bash
agent-circuit-breaker validate-rules docs/examples/rules/custom_deploy_guard.json
agent-circuit-breaker check "deploy production" --rules docs/examples/rules/custom_deploy_guard.json
```

Built-in block rules are evaluated before custom allow rules.

## Next Steps

- `SECURITY_MODEL.md` explains what ACB does and does not guarantee.
- `RULE_SCHEMA.md` documents custom rule files.
- `POLICY_ASSURANCE.md` documents policy loading, signatures, and trust.
- `INTEGRATION_GUIDE.md` shows CLI, API, MCP, and pipeline usage.
- `CONTRIBUTING.md` explains the development workflow.
