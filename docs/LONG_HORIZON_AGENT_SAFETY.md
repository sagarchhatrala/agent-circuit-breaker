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

`circuit-breaker trajectory` evaluates an ordered action sequence and returns an aggregate run verdict.

It can detect:

- repeated blocked actions in one run.
- too many unknown actions in one run.
- references to forbidden targets such as `main`, `production`, `.env`, or private paths.
- write-like actions outside declared scopes.
- output-channel drift, such as using GitHub when only Slack was allowed.
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
  "max_blocked_attempts": 1,
  "max_unknown_actions": 3,
  "actions": [
    "python bench.py",
    "gh pr create --title PowerCool"
  ]
}
```

Run it:

```bash
circuit-breaker trajectory ./agent-run.json --format json
```

The result is blocked because the run contract allowed Slack output, while the action attempted a GitHub PR.

## MCP Runtime Enforcement

For MCP servers, Agent Circuit Breaker can inspect every string-valued `tools/call` argument. By default this inspection is stateless and per-call.

Enable stateful run checks:

```bash
circuit-breaker-mcp-proxy --trajectory -- python -m your_mcp_server
```

Load a run contract:

```bash
circuit-breaker-mcp-proxy --trajectory-policy ./agent-run-policy.json -- python -m your_mcp_server
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
circuit-breaker trajectory ./agent-run.json --ledger
circuit-breaker ledger
circuit-breaker ledger <RUN_ID>
circuit-breaker ledger --verify
```

The run ledger is a local hash-chained JSONL file. It is useful for debugging, review, and lightweight governance. It is not a remote telemetry system.

## Approval Boundary

Local approvals are useful for review queues and audit trails. They are not a complete separation-of-duties mechanism if the same agent process can run the approval command.

For a stronger local gate, configure an approval token outside the agent runtime:

```bash
set ACB_APPROVAL_TOKEN=<human-held-token>
circuit-breaker --approval-token <human-held-token> approvals approve <ID>
```

For high-stakes environments, keep the approval decision path outside the agent's shell/tool authority.

## Design Boundaries

Agent Circuit Breaker is deterministic and local-first.

It does not:

- call an LLM to classify actions.
- execute commands.
- sandbox tools.
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
