# Long-Horizon Agent Safety

Agent Circuit Breaker provides deterministic runtime controls for long-running, tool-using AI agents.

This page is intended for developers and security teams looking for practical controls after reading discussions such as OpenAI's "Safety and alignment in an era of long-horizon models." Agent Circuit Breaker focuses on the runtime action layer: commands, MCP tool calls, SQL text, filesystem operations, approvals, and trajectory-level policy.

Traditional command safety checks answer one question:

```text
Is this single action risky?
```

Long-horizon agent safety also needs a second question:

```text
Is this sequence of actions still inside the approved goal, scope, and output boundary?
```

This matters for coding agents, MCP-connected agents, autonomous development workflows, and enterprise agent deployments where a run may span many tool calls, retries, files, repositories, and external services.

## What Trajectory Evaluation Does

`agent-circuit-breaker trajectory` evaluates an ordered action sequence and returns an aggregate run verdict.

It can detect:

- repeated blocked actions in one run.
- too many unknown actions in one run.
- references to forbidden targets such as `main`, `production`, `.env`, or private paths.
- write-like actions outside declared scopes.
- output-channel drift, such as using GitHub when only Slack was allowed.
- unauthorized actors and unauthorized delegation edges in structured action records.
- direct secret-like material in egress actions.
- secret-like reads followed by later egress.
- data export followed by upload, publish, or network send actions.

Example run contract:

```json
{
  "goal": "post benchmark results only to Slack",
  "allowed_outputs": ["slack"],
  "allowed_scopes": ["tests/", "docs/"],
  "forbidden_targets": ["main", "production", ".env"],
  "allowed_actors": ["orchestrator", "bench-worker"],
  "allowed_delegations": [{"from": "orchestrator", "to": "bench-worker"}],
  "max_blocked_attempts": 1,
  "max_unknown_actions": 3,
  "actions": [
    {"command": "python bench.py", "actor": "bench-worker", "delegated_by": "orchestrator"},
    {"command": "gh pr create --title PowerCool", "actor": "subagent.release"}
  ]
}
```

Run it:

```bash
agent-circuit-breaker trajectory ./agent-run.json --format json
```

The result is blocked because the run contract allowed Slack output, while the action attempted a GitHub PR, and because `subagent.release` is not an authorized actor.

Structured action objects are optional. Existing string-only action lists still work. Use structured actions when your harness, orchestrator, MCP bridge, or agent runtime can identify the actor that proposed the action and the parent actor that delegated it.

Actor and delegation fields are not magic identity. They are authenticated only
when a trusted integration supplies them from a trusted runtime context. For
stateful local enforcement, use `RuntimeGate` and configure `actor_tokens` when
the integration can keep actor tokens outside model-visible state.

## Stateful Runtime API

Retrospective trajectory evaluation is useful for tests, demos, and ledger
review, but live enforcement needs one proposed action at a time. `RuntimeGate`
provides that minimal workflow:

```python
from agent_circuit_breaker import RuntimeGate

gate = RuntimeGate()
run = await gate.create_run({
    "goal": "update docs only",
    "allowed_actors": ["orchestrator", "worker.docs"],
    "allowed_delegations": [{"from": "orchestrator", "to": "worker.docs"}],
    "require_actor": True,
    "max_actions": 20,
    "ttl_seconds": 1800,
})

decision = await gate.propose_action(
    run.run_id,
    {
        "command": "mkdir /tmp/acb-demo",
        "actor": "worker.docs",
        "delegated_by": "orchestrator",
    },
)

if decision.authorized:
    # Execute through ACB's one-time authorization wrapper.
    await gate.execute_authorized(
        run.run_id,
        authorization_id=decision.authorization_id,
        executor=lambda action: {"would_execute": action["command"]},
    )
else:
    # Stop this execution path. ACB returns recovery evidence, but does not
    # automatically spawn a replacement agent.
    print(decision.recovery)
```

The default runtime store is in-memory and process-local. It gives deterministic
local ordering and concurrent proposal serialization for one process; it does
not provide durable crash recovery or cross-process locking.

`execute_authorized` is the supported local binding between authorization and
side effects. It consumes the returned `authorization_id` once, records
`started`, calls the trusted executor with the exact authorized action record,
and records the final outcome. It still depends on the integration ensuring that
privileged tools are reachable only through this path.

## MCP Runtime Enforcement

For MCP servers, Agent Circuit Breaker can inspect every string-valued `tools/call` argument. By default this inspection is stateless and per-call.

Enable stateful run checks:

```bash
agent-circuit-breaker-mcp-proxy --trajectory -- python -m your_mcp_server
```

Load a run contract:

```bash
agent-circuit-breaker-mcp-proxy --trajectory-policy ./agent-run-policy.json -- python -m your_mcp_server
```

In stateful mode, a tool call that reads `.env` followed by a later tool call that uploads data can be blocked even if neither individual action triggered a single-action block rule.

## Human Review And Replay

When a trajectory requires approval, approval records include compact review context:

- run ID.
- aggregate verdict.
- summary counts.
- finding IDs and reasons.
- recent action summaries.

For replayable local records:

```bash
agent-circuit-breaker trajectory ./agent-run.json --ledger
agent-circuit-breaker ledger
agent-circuit-breaker ledger <RUN_ID>
agent-circuit-breaker ledger --verify
```

The run ledger is a local hash-chained JSONL file. It is useful for debugging, review, and lightweight governance. It is not a remote telemetry system.

## Approval Boundary

Local approvals are useful for review queues and audit trails. They are not a complete separation-of-duties mechanism if the same agent process can run the approval command.

For a stronger local gate, configure an approval token outside the agent runtime:

```bash
set ACB_APPROVAL_TOKEN=<human-held-token>
agent-circuit-breaker --approval-token <human-held-token> approvals approve <ID>
```

For high-stakes environments, keep the approval decision path outside the agent's shell/tool authority.

## Design Boundaries

Agent Circuit Breaker is deterministic and local-first.

It does not:

- call an LLM to classify actions.
- execute commands.
- sandbox tools.
- authenticate caller-supplied actor names unless a trusted integration uses
  runtime-held actor tokens.
- automatically spawn replacement agents.
- prove that a transfer happened.
- replace least privilege, isolation, backups, or endpoint controls.

Use it as a pre-execution runtime safety gate in a broader defense-in-depth design.

## Related Terms

This project is relevant to:

- long-horizon model safety.
- AI agent safety.
- AI coding agent safety.
- MCP security.
- agentic AI security.
- runtime guardrails.
- deterministic policy enforcement.
- tool-use safety.
- human-in-the-loop approvals.
- local-first AI governance.
