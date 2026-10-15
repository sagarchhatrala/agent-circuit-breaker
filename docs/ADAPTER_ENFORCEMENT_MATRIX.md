# Adapter Enforcement Matrix

Date: 2026-10-15

This matrix classifies ACB entry points for the single-host, trusted
executor-bound deployment model. "Enforced" means the path owns the protected
side effect and checks RuntimeGate state before invoking the executor.

| Entry point | Side effects | Principal/capability | Policy/history | Approval | Suspension/revocation | Durable consumption/start/outcome | Classification |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `RuntimeToolExecutor.execute(...)` without `approval_id` | Yes, through caller executor | Enforced when contract configures tokens/capabilities | RuntimeGate trajectory and persisted run history | Returns `pending_approval` when configured; does not execute | Enforced before start | Yes | Enforced |
| `RuntimeToolExecutor.execute(..., approval_id=...)` | Yes, through caller executor | Enforced | RuntimeGate trajectory and persisted run history | Exact approval consumed once | Enforced before start | Yes | Enforced |
| `RuntimeGate.execute_authorized(...)` | Yes, through caller executor | Bound at proposal; policy fingerprint rechecked at start | RuntimeGate persisted history | Not for approval-required actions | Enforced before start | Yes | Enforced |
| `RuntimeGate.execute_approved(...)` | Yes, through caller executor | Enforced before approval and start | RuntimeGate persisted history | Exact approval consumed once | Enforced before start | Yes | Enforced |
| `RuntimeGate.propose_action(...)` | No | Evaluates authority before issuing authorization | Yes | Can return `pending_approval` | Yes | Proposal only | Advisory authorization step |
| `RuntimeGate.record_outcome(...)` | No | Matches existing authorization | Store integrity checked | N/A | Does not start execution | Outcome only | Evidence API |
| `RuntimeGate.reconcile_execution(...)` | No | Trusted reconciler token when configured | Matches started execution | N/A | Does not start execution | Reconciliation event only | Recovery evidence API |
| MCP stdio proxy | Forwards to upstream MCP server if allowed | None beyond caller/tool metadata | Evaluates command-like arguments and optional trajectory | Advisory only, not RuntimeGate approvals | No RuntimeGate suspension/revocation | No RuntimeGate start/outcome | Advisory proxy |
| `AgentCircuitBreaker` / `PipelineEngine` SDK | No direct execution | None | Guard evaluation only | Advisory result only | Pipeline state only | No RuntimeGate start/outcome | Advisory |
| `evaluate_action`, `evaluate_trajectory`, CLI `check`, `scan`, `trajectory`, `explain` | No direct protected execution | Caller metadata only | Deterministic evaluation | Advisory/local review only | No RuntimeGate suspension/revocation | No RuntimeGate start/outcome | Advisory |
| ApprovalStore in `approvals.py` | No execution | Local file review record | Binds to evaluation result hash | Review queue only | No RuntimeGate revocation | No execution start/outcome | Advisory review evidence |
| Direct caller executor/tool/subprocess invocation | Yes | None from ACB | None unless caller separately evaluates | None | None | None | Untrusted/direct |

## Common Enforced Contract

Every enforced path must:

1. use trusted integration-supplied principal, capability, and token context;
2. canonicalize the action and target;
3. evaluate current policy and persisted run history;
4. require an exact approval for configured approval scopes;
5. validate SQLite schema and runtime-state integrity;
6. check current suspension, revocation, policy fingerprint, and unresolved state;
7. atomically consume authorization or approval before side effects;
8. durably record `started` before invoking the executor;
9. record `outcome` or preserve unresolved execution for reconciliation.

Advisory integrations can be useful for blocking or warning, but they must not
be described as providing RuntimeGate's executor-bound guarantees.
