# Adapter enforcement matrix

Reviewed for v1.7.0, November 8, 2026. Enforcement assumes the owner process,
policy/state and executors cannot be modified or bypassed by the agent.

| Entry point | Who executes? | Authorization / approvals | Durable start / outcome | Scope |
|---|---|---|---|---|
| `Workflow.call` | ACB typed executor | Owner policy; derived resources; exact artifact versions; single-use approval | RuntimeGate + SQLite | Pinned reads, copies, Base64, fixed report generation, bounded Git status, owner-supplied publisher |
| `workflow-mcp` | ACB typed executor | Same dispatcher; client metadata cannot grant authority | Same lifecycle | stdio modern 2026-07-28 and legacy initialization; six fixed tools |
| Responses `Dispatcher` | Application's ACB executor | Same typed contract; duplicate call IDs never reexecute | Same lifecycle | Application-side function calls; hosted tools excluded |
| `RegisteredMCPBridge` | Trusted transport forwards to registered upstream | Explicit owner registrations, reviewed catalog hash, principal, resource, capability | Before forward and after report; uncertain on error/timeout/cancel | Library integration for bounded string arguments and text results; not a generic secure MCP server |
| `RuntimeToolExecutor` / `RuntimeGate.execute_*` | Trusted caller-supplied executor | Configured capabilities, exact approvals, policy checks | Yes | Caller must correctly bind actual execution and mark ambiguous remote failures `ExecutionUncertain` |
| Claude native hook | Claude Code | PreToolUse permit/deny from documented payload | No executor-owned lifecycle | Host owns execution; fixture-tested, native host unavailable |
| Cursor native hooks | Cursor | Separate documented shell/MCP format | No executor-owned lifecycle | Desktop-targeted fixtures; native desktop/CLI unavailable |
| Legacy stdio MCP proxy | Upstream server | Inspects command-like arguments; catalog/taint evidence | No RuntimeGate lifecycle | Can prevent forwarding; not executor-owned authorization |
| Legacy HTTP proxy | Upstream server | Same limited inspection | No lifecycle | Custom JSON POST bridge; not full Streamable HTTP |
| CLI `check`, `scan`, `trajectory`, `explain`; evaluation/pipeline SDK | Caller | Evaluation only | No | Only `ALLOW` may be executed by a trusted caller |
| Advisory ApprovalStore | Nobody | Local review records | No | Not RuntimeGate execution authority |
| Native tools, other MCP servers, direct subprocess calls | Host/caller | Outside this path | No | Not protected by configuring ACB-mediated tools |

`ALLOW`, `BLOCK`, `UNKNOWN`, `PENDING_APPROVAL`, and `ERROR` remain distinct.
Unknown/failed checks never become execution permission. Native hook JSON uses the
host's allow/deny schema while including the original ACB outcome in its reason.

An upstream transport write means forwarding started. A JSON-RPC error or timeout
cannot prove that no remote effect happened. A valid success is a **server-reported
completion**, not independent evidence of a remote effect. The demo collector
separately observes exact received bytes. Unresolved non-idempotent operations are
not retried automatically; reconcile using trusted external evidence.

Catalog hashes bind definitions, not implementation code, credentials, or server
trustworthiness. Legacy first-contact pinning is visibly labeled TOFU; changed/new
catalog entries require explicit review. The registered bridge requires owner-pinned
catalog definitions before first use.
