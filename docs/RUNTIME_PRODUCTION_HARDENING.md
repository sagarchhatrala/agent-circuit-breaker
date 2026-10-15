# Runtime Production Hardening

Date: 2026-10-15

This document describes the implemented RuntimeGate hardening for the supported
trusted executor-bound model. It does not claim OS sandboxing, arbitrary-process
containment, distributed coordination, or tamper-proof local storage.

## Invariant Matrix

| Security property | Enforcement point | Test evidence | Limitation |
| --- | --- | --- | --- |
| Canonical action binding | `RuntimeAction.to_trajectory_record`, action fingerprint checks, `execute_authorized` | `test_runtime_tool_executor_executes_exact_authorized_action`, substitution tests | Unmediated tool calls are outside scope. |
| Principal/capability validation | `_precheck_state`, `_authority_error` | forged principal/capability tests | Trusted integration tokens, not external IdP auth. |
| Approval required means no direct authorization | `RuntimeGate.propose_action` returns `pending_approval` | `test_approval_required_action_needs_trusted_approval_before_execution` | Only configured action/target scopes require approval. |
| Approval bound to exact action and policy | `grant_approval`, `_matching_open_approval`, `execute_approved` | action/target/principal/policy/expiry/replay tests | Approval authority is host integration token based. |
| One-time approval consumption | `_mark_approved_execution_started` records `approval_consumed`, `proposal`, and `started` in one store update | in-process and OS-process approval race tests | SQLite scope is one local database file. |
| Authorization single use | `_mark_execution_started`, `_matching_open_authorization` | replay, failure, uncertainty, OS-process race tests | External side effects may be uncertain after start. |
| Durable suspension/revocation | `suspend_run`, `revoke_authorizations`, `_precheck_state` | suspension/revocation persistence tests | Does not kill already running arbitrary host processes. |
| Store schema compatibility | `SQLiteRunStore._ensure_schema_sync` | fresh DB, legacy two-table migration, future schema tests | Only real legacy two-table schema is migrated. |
| Store integrity | `_validate_database_sync`, `_validate_state_integrity` | malformed JSON, missing contract, bad fingerprint tests | Not tamper-proof against a privileged local writer. |
| Crash uncertainty | durable `started` before executor call | process-death-after-start test | Does not prove rollback or exactly-once external effects. |
| Reconciliation | `reconcile_execution` | wrong action, duplicate, token, unknown-outcome tests | Trust depends on integration/operator evidence. |
| Audit integrity | `AuditLog` hash chain and optional HMAC signatures | hash-chain and HMAC tamper tests | HMAC key must be outside the writable log trust boundary. |

## SQLite Schema Versioning

Schema version `1` consists of:

- `runtime_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)`
- `runtime_runs(run_id TEXT PRIMARY KEY, state_json TEXT NOT NULL)`
- `runtime_contracts(run_id TEXT PRIMARY KEY, contract_json TEXT NOT NULL)`

The previous supported format was the same two JSON tables without
`runtime_metadata`. `SQLiteRunStore` migrates that real legacy format by adding
metadata transactionally under `BEGIN IMMEDIATE`.

The store rejects:

- unsupported future schema versions;
- incomplete migration state;
- missing required tables or columns;
- malformed JSON records;
- missing private contracts;
- mismatched action fingerprints;
- inconsistent authorization, approval, start, and outcome event references.

The store never resets or recreates security state to recover from an integrity
failure. The safe recovery action is offline investigation and restore/migration
from trusted backup evidence.

## Approval-Bound Execution

Approval lifecycle:

`approval -> approval_consumed -> proposal -> started -> outcome`

`approval_consumed`, the approved `proposal`, and `started` are appended in one
atomic store update before the executor is called. If the process dies after
that transition and before outcome recording, the run contains unresolved
execution and subsequent proposals fail closed until explicit reconciliation.

Approvals bind:

- run ID through the enclosing run state;
- canonical action fingerprint;
- policy fingerprint;
- principal/capability/action/target fields contained in the canonical action;
- approver identity and expiry in approval event details.

Approver tokens are private contract material and are not serialized into public
events. A caller-supplied approval ID alone is not authority; the matching
approval event must be present, unexpired, unrevoked, unconsumed, and bound to
the current policy fingerprint.

## Diagnostics

Read-only CLI commands:

- `agent-circuit-breaker runtime-health <sqlite-path>`
- `agent-circuit-breaker runtime-inspect <sqlite-path> <run-id>`
- `agent-circuit-breaker production-check --runtime-store <sqlite-path>`

These commands validate the store before reporting. They do not execute tools,
resume runs, clear revocations, reset approvals, or reclassify unknown outcomes.
`production-check` also validates the configured audit posture and returns a
non-zero exit code until the declared local production baseline is satisfied.

## Reconciliation

`RuntimeGate.reconcile_execution(...)` records trusted evidence for a started
execution whose outcome was missing or unknown. It does not retry the action and
does not reuse the original authorization.

Reconciliation binds the run, authorization ID, action fingerprint, original
started action, reconciler identity, optional idempotency key, redaction-safe
evidence, and reconciled outcome. If `reconciler_tokens` are configured in the
run contract, a matching `reconciler_token` is required. Without configured
tokens, reconciler identity is trusted integration metadata and must not be
described as independently authenticated.

Reconciliation can reactivate a run only when the run was blocked specifically
because of unresolved or unknown execution. It does not clear suspension,
revocations, policy denials, or unrelated blocked states.

## Audit Integrity

The local `AuditLog` uses a canonical SHA-256 hash chain. This detects
accidental corruption, deletion, reordering, and partial manual edits when the
attacker does not recompute the whole chain.

If `ACB_AUDIT_HMAC_KEY` is set, each audit entry also receives an HMAC-SHA256
signature. The key must be non-empty and at least 16 bytes. Verification checks
that signature with constant-time comparison and fails when a signed entry is
verified without the key, with the wrong key, or with an unsupported signature
algorithm. Legacy unsigned hash-only logs remain verifiable only when HMAC is
not configured; once HMAC is required, unsigned entries fail verification rather
than silently downgrading to hash-only evidence.

The key must be controlled outside the writable audit log and database. If an
attacker can modify the audit file and read or replace the HMAC key, this
mechanism is not tamper-proof.

ACB does not transmit audit events to any external service. Deployments that
need stronger evidence against a local writer should forward audit entries or
checkpoints to an independently controlled append-only destination.

Audit checkpoints:

- `agent-circuit-breaker timeline --checkpoint <path>` writes a checkpoint for
  the current verified audit log.
- `agent-circuit-breaker timeline --verify --checkpoint <path>` verifies that
  the current log still contains the checkpointed entry count and last hash.
- If `ACB_AUDIT_HMAC_KEY` is configured, checkpoints are HMAC-signed and
  verification fails with the wrong or missing key.

The checkpoint must be retained outside the writable audit log/database trust
boundary to detect tail deletion. Keeping the checkpoint next to the log is
useful for smoke testing, but it is not stronger evidence against a local
writer who can modify both files.

## Safe Recovery

Implemented recovery remains intentionally narrow:

- `resume_run(...)` only resumes suspended runs and records a `resume` event.
- It does not clear unresolved execution or unknown outcomes; reconciliation is
  the explicit trusted-evidence path for that state.
- Approval consumption is not reversible.
- Revocations are not cleared by a generic recovery command.

If an external side effect is uncertain, an operator or trusted integration
needs resource-specific evidence before recording reconciliation.

## Deployment Assumptions

The verified deployment scope is a single host where every protected side effect
passes through `RuntimeToolExecutor`, `execute_authorized(...)`, or
`execute_approved(...)`, and all trusted workers share the same SQLite database
file.

Unsupported as production guarantees:

- multi-host coordination;
- direct subprocess/tool calls outside RuntimeGate;
- malicious host administrator resistance;
- tamper-proof local audit evidence;
- OS-level sandboxing;
- exactly-once external side effects.

## Benchmark Methodology

Measure with a temporary SQLite database and a no-op executor:

- run creation and integrity validation;
- proposal authorization;
- approval grant and consumption;
- end-to-end mediated execution.

Benchmarks should report Python version, platform, sample count, p50, p95, and
whether SQLite WAL and filesystem locking are available. Correctness checks must
not be disabled for benchmark runs.
