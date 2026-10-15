# Runtime Principals And Capabilities

Date: 2026-10-15

This note defines the current RuntimeGate identity and authority model. It is a
trusted-integration contract, not a claim that ACB authenticates arbitrary host
processes or contains arbitrary in-process Python code.

## Threat Model

RuntimeGate protects the side effects that pass through `RuntimeToolExecutor` or
`RuntimeGate.execute_authorized(...)`. The trusted host integration creates the
run contract, holds private token material, binds integration-controlled fields,
and routes the actual side effect through the executor-bound path.

ACB does not treat caller-supplied `actor`, `principal`, role, or metadata
fields as authentication by themselves. When `principal_tokens` are configured,
the trusted integration must supply a matching `principal_token`; token material
is stored in the private contract and is omitted from public run state and
runtime events. When `principal_tokens` are absent, `principal` remains trusted
integration metadata and must not be described as independently authenticated.

This model does not protect against:

- unmediated code paths that call a tool or subprocess directly;
- a caller with equivalent in-process privileges that can construct or mutate
  trusted objects;
- a host principal that can rewrite the SQLite database or private contract;
- a compromised trusted executor.

## API Contract

`RunContract` supports:

- `principal_tokens`: mapping of principal ID to private shared token for the
  trusted integration path.
- `capabilities`: explicit grants with `id`, `principal`, optional
  `action_types`, optional `target_resources`, optional `actors`, and optional
  absolute `expires_at` timestamp.

`RuntimeAction` supports:

- `principal`: authenticated or trusted-integration principal ID.
- `principal_token`: private token checked only when `principal_tokens` are
  configured. It is not serialized into public action records.
- `capability_id`: grant selected for the action.
- `action_type`: deterministic operation class; defaults to `command`.
- `target_resource`: resource string used for exact capability scope matching.

If a contract has `capabilities`, a proposed action must supply a matching
`capability_id` and `principal`. Missing, unknown, expired, cross-principal, or
out-of-scope capabilities deny authorization before an authorization ID is
created. Target scopes are exact string matches, except a scope ending in `*`
matches that prefix.

The capability policy is included in the run policy fingerprint. If a
capability, principal authentication mode, run policy, target, or action context
changes after authorization, `execute_authorized(...)` rejects the stale
authorization before the executor is called.

`RuntimeToolExecutor` can bind `principal`, `principal_token`,
`capability_id`, `action_type`, and `target_resource` in the trusted adapter.
Caller payloads that conflict with bound metadata are rejected before
authorization.

## Evidence And Privacy

Runtime events record public identity and authority context, including
`principal`, `capability_id`, `action_type`, and `target_resource` when supplied.
They do not record `principal_token` or `actor_token`.

Runtime decisions and events include stable `reason_code` values for identity and
capability denial cases, such as `PRINCIPAL_TOKEN_INVALID`,
`CAPABILITY_MISSING`, `CAPABILITY_EXPIRED`, and
`CAPABILITY_TARGET_SCOPE_MISMATCH`.

## Follow-Up: Versioned SQLite Schema And Integrity

Do not treat the current JSON-in-SQLite schema as final production storage.
The next schema design should add:

- `runtime_schema(version, applied_at, code_version)` with explicit migration
  ordering.
- Typed tables for runs, contracts, events, authorizations, revocations, and
  integrity checkpoints, while preserving JSON evidence export.
- Store open failure classes such as unavailable, locked, malformed,
  incompatible schema, integrity failure, missing contract, and corrupted row.
- A startup integrity check that verifies required tables, schema version,
  non-null critical fields, event sequence continuity, and contract presence.
- Transaction boundaries that update run state, event append, authorization
  consume, suspension, and revocation in one write transaction.
- A recovery rule for interrupted writes: no protected side effect can begin
  unless the authorization transition and `started` event are durably committed.

SQLite guarantees remain local-host guarantees that depend on one shared
database file and SQLite filesystem locking. They are not distributed consensus
or tamper-proof evidence against a writer with host access.

## Follow-Up: Approval-Bound Execution Grants

Approval grants should be separate from principal capabilities. An approval
should bind:

- run ID and principal;
- actor and delegated authority;
- canonical action fingerprint;
- target resource and action type;
- selected capability ID;
- policy fingerprint and relevant prior-event references;
- approver identity and authority;
- expiry and one-time consumption status.

Approval consumption must occur in the same transaction as execution-start
authorization. Races to approve, revoke, suspend, consume, or change policy must
produce one explicit winner; losing paths must fail closed. After process death
between start and outcome, the approval must not be reusable unless a trusted,
resource-specific reconciliation process proves the side effect did not occur.
