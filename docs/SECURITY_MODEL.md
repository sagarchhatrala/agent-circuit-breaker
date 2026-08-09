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
- deciding whether `UNKNOWN` should stop or require human review.
- preventing bypass paths that execute actions without evaluation.

## Decision Model

Agent Circuit Breaker returns one of four decisions:

- `ALLOW`: recognized safe operation or explicit allow rule with complete mandatory inspection.
- `BLOCK`: a built-in or custom rule matched and denied the action.
- `ERROR`: input, parsing, rule loading, or evaluation failed.
- `UNKNOWN`: no rule matched and the action is not recognized as safe.

The recommended integration policy is:

- execute only on `ALLOW`.
- stop on `BLOCK`.
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

Integrations that need strict fail-secure behavior should continue to execute
only on `ALLOW`, stop on `BLOCK` and `ERROR`, and route `UNKNOWN` through strict
mode, approval mode, or their own explicit allowlist.

## Trajectory Evaluation

Trajectory mode evaluates an ordered list of proposed actions and adds deterministic checks that require run history or an explicit run contract. It can detect patterns such as repeated blocked actions, write-like actions outside allowed scopes, forbidden target references, output-channel drift, unknown-action volume, and secret-like reads followed by egress.

Trajectory egress checks are heuristic and deterministic. They look for concrete command text that combines sensitive references, data-export shapes, and external egress channels. They are not data-loss prevention, content inspection, or proof that a transfer happened.

Trajectory mode is still pre-execution analysis. It does not observe live operating-system side effects, prove that a secret was actually read, or prove that network egress occurred. Callers must send proposed actions in order and honor the aggregate trajectory verdict.

The MCP proxy can opt in to trajectory evaluation with `--trajectory` or `--trajectory-policy`. In that mode, the proxy keeps in-memory state for one proxy process and evaluates string-valued `tools/call` arguments as a run sequence. This state is not persisted across proxy restarts unless the caller separately records audit events.

## Run Ledger

`agent-circuit-breaker trajectory --ledger` writes full trajectory results to a local hash-chained JSONL ledger. The ledger is replayable and tamper-evident in the same local-integrity sense as the audit timeline: hash-chain verification can detect after-the-fact edits to the ledger file, but it does not prevent deletion, rollback, or tampering by a user or process with write access to the file.

## Rule Ordering

Built-in rules are evaluated before custom rules.

This means a custom `allow` rule cannot override a built-in `block` rule. Custom rules are append-only policy extensions in the current design.

## Network Use

Core command evaluation is offline by default. The only built-in network path is explicit central policy loading with `--policy https://...`. Cleartext `http://` policy URLs are rejected by default because policy data can change enforcement behavior; callers that intentionally accept insecure transport risk must pass `--allow-insecure-remote-policy`. Local policy auto-discovery never performs network I/O.

## Signed Policy and Rule Packs

Policy files and external rule packs can include an embedded `signature` object. `--require-signature` rejects unsigned or tampered JSON before any rules are built. The stdlib verifier requires `hmac-sha256` for authenticity when `--require-signature` is used. Plain SHA-256 checksums are integrity checks only and are not accepted as required signatures because an attacker can recompute a same-file checksum after tampering. Heavier public-key or transparency-log verification should be added through an optional integration package so the core remains dependency-free.

## Strict and Approval Modes

Default `check` behavior preserves `UNKNOWN` for unclassified actions. `--mode strict` converts `UNKNOWN` to `BLOCK` for fail-secure environments. `team` and `prod` profiles route `UNKNOWN` to `PENDING_APPROVAL`, making ambiguity visible to a human instead of silently passing through.

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
