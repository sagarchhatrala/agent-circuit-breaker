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

## Add A Live Runtime Gate

For an agent harness or subagent runner, do not submit history only after the
fact. Gate each proposed action before the tool executes:

```python
from agent_circuit_breaker import RuntimeGate

gate = RuntimeGate()
run = await gate.create_run({
    "allowed_actors": ["orchestrator"],
    "require_actor": True,
    "max_actions": 20,
})

decision = await gate.propose_action(
    run.run_id,
    {"command": "mkdir /tmp/acb-demo", "actor": "orchestrator"},
)

if decision.authorized:
    # Execute through a single-use authorization.
    await gate.execute_authorized(run.run_id, authorization_id=decision.authorization_id, executor=my_executor)
```

Only a trusted integration should hold actor tokens or decide whether to execute
after `authorized: true`.

The supported first-party wrapper is `RuntimeToolExecutor`:

```python
from agent_circuit_breaker import RuntimeGate, RuntimeToolExecutor

gate = RuntimeGate()
run = await gate.create_run({"allowed_actors": ["orchestrator"], "require_actor": True})

tool = RuntimeToolExecutor(
    gate,
    run_id=run.run_id,
    actor="orchestrator",
    executor=lambda action: {"would_execute": action["command"]},
)

result = await tool.execute("mkdir /tmp/acb-demo")
```

Replace the lambda with a trusted adapter. Do not expose direct access to the
underlying privileged tool if ACB is expected to enforce the boundary.

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
