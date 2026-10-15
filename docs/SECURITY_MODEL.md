# Security Model

Agent Circuit Breaker is a deterministic pre-execution safety checkpoint for agent-proposed actions.

It is not a sandbox. It does not execute, isolate, monitor, roll back, or prevent operating-system actions by itself. Callers must place it before execution and must honor its decisions.

## Trust Boundary

The trusted boundary is the local Agent Circuit Breaker process and the rule set loaded from disk.

Untrusted inputs include:

- LLM or agent-generated actions.
- User-provided command text.
- SQL text proposed by an agent.
- External JSON rule files until they pass validation.

The caller is responsible for:

- sending every proposed action to Agent Circuit Breaker before execution.
- treating `BLOCK` and `ERROR` as stop conditions.
- treating `UNKNOWN` as a stop or review condition unless a separate allowlist
  explicitly accepts the ambiguity.
- preventing bypass paths that execute actions without evaluation.

## Decision Model

Agent Circuit Breaker returns one of five decisions:

- `ALLOW`: recognized safe operation or explicit allow rule with complete mandatory inspection.
- `BLOCK`: a built-in or custom rule matched and denied the action.
- `PENDING_APPROVAL`: action must not execute until a separate human approval workflow approves the same freshly evaluated action context.
- `ERROR`: input, parsing, rule loading, or evaluation failed.
- `UNKNOWN`: no rule matched and the action is not recognized as safe.

The recommended integration policy is:

- execute only on `ALLOW`.
- stop on `BLOCK`.
- stop on `PENDING_APPROVAL` unless a separate approval workflow revalidates the fresh action context before execution.
- stop on `ERROR`.
- treat `UNKNOWN` as review-required unless the integration has a separate allowlist.

## Inspection Coverage And Decision Validation

Every action result includes additive inspection coverage metadata. The coverage
record states whether mandatory filesystem, command, and SQL inspection
completed before the decision was returned. It also records whether an action is
eligible for automatic known-safe allow.

`ALLOW` is not permitted when mandatory inspection is incomplete. Automatic
known-safe allow is only permitted for a single complete command segment with no
shell operators, no command risk flags, valid SQL inspection, and no SQL risk
flags. A recognized safe first segment cannot make a later chained segment safe.

Integrations should execute only on `ALLOW`. v1.6.5 makes this the default for
the MCP proxy and the pipeline SDK: `UNKNOWN` stops forwarding/execution unless
the integration explicitly opts in with `--allow-unknown` or
`AgentCircuitBreaker(allow_core_unknown=True)`.

## Trajectory Evaluation

Trajectory mode evaluates an ordered list of proposed actions and adds deterministic checks that require run history or an explicit run contract. It can detect patterns such as repeated blocked actions, write-like actions outside allowed scopes, forbidden target references, output-channel drift, unknown-action volume, secret-like reads or transformations followed by egress, data export followed by upload, and external artifact download followed by local execution.

Trajectory egress checks are heuristic and deterministic. They look for concrete command text that combines sensitive references, data-export shapes, and external egress channels. They are not data-loss prevention, content inspection, or proof that a transfer happened.

Trajectory mode is still pre-execution analysis. It does not observe live operating-system side effects, prove that a secret was actually read, or prove that network egress occurred. Callers must send proposed actions in order and honor the aggregate trajectory verdict.

The MCP proxy can opt in to trajectory evaluation with `--trajectory` or `--trajectory-policy`. In that mode, the proxy keeps in-memory state for one proxy process and evaluates string-valued `tools/call` arguments as a run sequence. This state is not persisted across proxy restarts unless the caller separately records audit events.

## Stateful Runtime Gate

`RuntimeGate` is an in-process stateful authorization API for trusted local
agent harnesses. A caller creates a run contract, submits each proposed action
before execution, receives an explicit authorization decision, and records the
execution outcome only for the exact authorized action fingerprint.

The runtime gate enforces these local invariants:

- `authorized` is true only for aggregate trajectory verdict `allow`.
- `UNKNOWN`, `ERROR`, `BLOCK`, and `PENDING_APPROVAL` are not executable.
- every proposal is recorded in sequence before the next proposal is evaluated.
- run status, expiration, cancellation, and `max_actions` are checked before
  evaluating the next action.
- authorized proposals receive an unguessable, single-use `authorization_id`.
- `execute_authorized` rejects forged, denied, expired, cancelled, or replayed
  authorizations before calling the executor.
- `execute_authorized` records `started` before executor side effects and
  records `executed` or `failed` afterward.
- new proposals are blocked while a prior execution has `started` but has no
  final outcome, preventing dependent actions from silently advancing on
  unknown execution status inside one process.
- optional `actor_tokens` bind an actor ID to a token held by the trusted
  integration; token material is not serialized in public run state.
- outcome reporting is bound to an authorized action fingerprint in the same run.

The runtime gate does not authenticate operating-system users, execute tools,
spawn replacement agents, or sandbox the process. If no `actor_tokens` are
configured, `actor` and `delegated_by` are trusted integration metadata. If an
agent can call the underlying shell, MCP client, database driver, or filesystem
tool directly, it can bypass ACB. A trusted runtime must make ACB the only path
to privileged tool execution.

`propose_action` alone is an authorization decision, not execution binding. For
new integrations, prefer `execute_authorized` so the trusted harness consumes
the returned one-time authorization before side effects. Fingerprint-only
`record_outcome` is retained for compatibility and audit flows, but it is weaker
than consuming an authorization ID.

`RuntimeToolExecutor` is the first-party integration wrapper for this flow. It
does not execute shell commands itself. The host supplies a trusted executor
callable, while ACB owns the authorization, single-use consumption, started
event, and final outcome lifecycle. If the supplied executor is called directly
outside `RuntimeToolExecutor`, that is an explicit bypass outside ACB's boundary.

If a timeout or cancellation occurs after `started`, ACB records
`unknown_execution_status` and blocks dependent proposals in that run. It does
not automatically retry the action because the side effect may already have
occurred.

## Run Ledger

`agent-circuit-breaker trajectory --ledger` writes full trajectory results to a local hash-chained JSONL ledger. The ledger is replayable and tamper-evident in the same local-integrity sense as the audit timeline: hash-chain verification can detect after-the-fact edits to the ledger file, but it does not prevent deletion, rollback, or tampering by a user or process with write access to the file.

## Rule Ordering

Built-in rules are evaluated before custom rules.

This means a custom `allow` rule cannot override a built-in `block` rule. Custom rules are append-only policy extensions in the current design.

## Network Use

Core command evaluation is offline by default. The only built-in network path is explicit central policy loading with `--policy https://...`. Cleartext `http://` policy URLs are rejected by default because policy data can change enforcement behavior; callers that intentionally accept insecure transport risk must pass `--allow-insecure-remote-policy`. Local policy auto-discovery never performs network I/O.

ACB is not a TLS-intercepting network proxy. That keeps setup simple and avoids
local certificate/TLS handshake breakage, but it also means ACB does not provide
network-level egress enforcement. It can block a tool call whose proposed action
text visibly attempts exfiltration. It cannot stop network traffic that bypasses
the tool-call gate; use OS, container, VPC, firewall, or runtime egress controls
for that boundary.

## Signed Policy and Rule Packs

Policy files and external rule packs can include an embedded `signature` object. `--require-signature` rejects unsigned or tampered JSON before any rules are built. The stdlib verifier requires `hmac-sha256` for authenticity when `--require-signature` is used. Plain SHA-256 checksums are integrity checks only and are not accepted as required signatures because an attacker can recompute a same-file checksum after tampering. Heavier public-key or transparency-log verification should be added through an optional integration package so the core remains dependency-free.

## Strict and Approval Modes

Default `check` behavior preserves `UNKNOWN` for unclassified actions so callers
can see ambiguity directly. `--mode strict` converts `UNKNOWN` to `BLOCK` for
fail-secure environments. `team` and `prod` profiles route `UNKNOWN` to
`PENDING_APPROVAL`, making ambiguity visible to a human instead of silently
passing through. Executable adapters such as MCP forwarding and the pipeline SDK
stop on `UNKNOWN` by default.

Local approval records are an audit and review workflow by default. They are not a complete separation-of-duties control if the same agent process can run `agent-circuit-breaker approvals approve <ID>`. Approval records include warning metadata when `ACB_APPROVAL_TOKEN` is not configured. To require a human-held token for approve/deny decisions, set `ACB_APPROVAL_TOKEN` outside the agent runtime and pass `--approval-token` when deciding an approval. Approval validation must be performed against a fresh evaluation result; approval does not bypass inspection, policy, or decision validation. In high-stakes environments, keep the approval decision path outside the agent's shell and tool authority.

## Fail-Closed Behavior

The project intentionally treats these conditions as stop conditions:

- malformed command input.
- malformed SQL input.
- non-string action input.
- invalid JSON rule files.
- unsupported rule fields or matcher types.
- rule matcher exceptions.

CLI callers receive a non-zero exit code for `BLOCK`, `ERROR`, and `UNKNOWN`.

## Local-First Operation

The core package has no runtime dependency outside the Python standard library.

Agent Circuit Breaker does not by default:

- send telemetry.
- call an LLM.
- execute shell commands.
- connect to databases.

It fetches a remote policy only when the caller explicitly supplies a policy URL. HTTPS is accepted by default. HTTP requires explicit insecure opt-in.

## Persisted Record Redaction

Audit, approval, and ledger records are redacted by default before persistence.
The redactor covers common command-line and URL secret shapes, including bearer
tokens, token/password/secret assignments, basic-auth arguments, database URL
passwords, GitHub token prefixes, and package/database password flags.

Redaction is best-effort deterministic hygiene, not a DLP system. Callers should
still store local records with least privilege and avoid placing secrets in
agent-visible command text. `ACB_RETAIN_RAW_RECORDS=1` is an explicit opt-in for
controlled environments that require raw local records.

## Pipeline SDK Boundary

The pipeline SDK can validate proposed file writes when integrations route those writes through `AgentCircuitBreaker`, for example as a `filesystem` tool call with a `path` and `operation`. It does not intercept arbitrary editor, shell, or operating-system writes by itself. Blocking writes before they reach disk requires an editor integration, MCP/filesystem proxy, or OS sandbox.

## Explicit Non-Goals

Agent Circuit Breaker is not:

- a sandbox.
- an antivirus tool.
- an endpoint monitor.
- an identity or permissions system.
- a complete shell parser.
- a complete SQL parser.
- a substitute for backups, access control, or least-privilege execution.

Use it as a deterministic gate in a broader defense-in-depth design.
