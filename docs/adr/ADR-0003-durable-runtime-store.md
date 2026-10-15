# ADR-0003: Durable Runtime Store Design

Date: 2026-10-15

## Status

Proposed. Do not claim durable runtime enforcement until the implementation and
tests in this ADR are complete.

## Context

`InMemoryRunStore` serializes proposals inside one Python process. It cannot
survive process restart, coordinate multiple processes, recover a run after a
crash, or preserve uncertain execution state. Production integrations need a
durable local store for runs whose security depends on prior events.

Durability is not the same as tamper resistance. A local SQLite database cannot
protect against a local attacker with write access to the database or its
directory. It can provide transactional state, restart recovery, and
best-effort corruption detection.

## Store Interface

The runtime store must provide these operations:

- `create(state, private_contract) -> RuntimeState`
- `read(run_id) -> RuntimeState`
- `contract_for(run_id) -> RunContract`
- `update(run_id, updater) -> RuntimeState`
- `recover(run_id) -> RuntimeState`
- `list_recoverable(statuses) -> list[RuntimeState]`

`update` is the transaction boundary. It must read the current state and private
contract inside the same transaction, call the updater exactly once, validate
that the resulting state version increments by one, write the next state, and
commit before returning.

## SQLite Schema

Initial schema version: `1`.

Tables:

- `runtime_schema(version integer not null)`
- `runtime_runs(run_id text primary key, status text not null, state_json text
  not null, contract_json text not null, state_hash text not null,
  updated_at real not null)`

`state_json` stores public runtime state. `contract_json` stores private
contract fields, including actor-token material if the caller chooses durable
actor-token enforcement. This has retention implications and must be documented.

`state_hash` is `sha256(canonical(state_json) + "." + canonical(contract_json))`.
It detects accidental corruption or casual edits when the attacker cannot also
update the hash consistently. It is not a MAC and is not rollback resistant.

## Migration Strategy

Each database has exactly one schema version. Opening a database with a higher
version than the code supports must fail closed. Opening an empty database
creates schema version `1` in one transaction. Interrupted migrations must leave
the database either at the old supported version or fail closed on next open.

No downgrade behavior is supported in v1.

## Locking And Concurrency

Use SQLite transactions with `BEGIN IMMEDIATE` for every `update`. This obtains
a write lock before reading the run row and prevents two writers from
authorizing against the same stale state.

Process-local locks may reduce thread contention, but correctness must rely on
SQLite transactions, not only Python locks. Tests must cover:

- multiple threads using one store object.
- multiple independent store objects in one process.
- subprocesses opening the same database.

## Atomic Authorization Consumption

Authorization consumption is a state transition:

1. transaction begins.
2. run state is read and hash-verified.
3. authorization is checked against current state.
4. `started` event is appended.
5. transaction commits.
6. executor side effect occurs outside the database transaction.
7. final outcome transition records `executed`, `failed`, or
   `unknown_execution_status`.

The side effect cannot be atomic with SQLite state unless the executor itself
participates in the same transaction, which shell/MCP/filesystem tools do not.
Therefore, any crash after `started` and before final outcome is an uncertain
execution.

## Crash Recovery

On restart, any run with a `started` event and no matching final outcome must be
treated as `unknown_execution_status` or `needs_reconciliation`. ACB must never
automatically replay the action. Dependent actions must remain blocked until a
trusted operator or integration records a reconciliation outcome.

Recovery API:

- `recover(run_id)` returns current state and marks stale started executions as
  requiring reconciliation when supported.
- `record_outcome(..., outcome="unknown_execution_status")` is valid for
  unresolved started executions.

## Expiration, Cancellation, Revocation

Expiration is checked during proposal and authorization consumption. A run may
expire between proposal and execution; `execute_authorized` must fail closed in
that case.

Cancellation is a state transition and must prevent later authorization
consumption.

Revocation is not implemented in current RuntimeGate. If added, it must be a
state transition that invalidates unconsumed authorization IDs.

## Policy Version Binding

Every run stores a `policy_fingerprint` derived from authorization-relevant
contract fields. Each proposal event and decision carries the policy
fingerprint. Authorization consumption must verify that the run's current
policy fingerprint still matches the proposal event's fingerprint.

Changing policy during an active run is not supported in v1. Create a new run.

## File Permissions And Sensitive Data

SQLite files should be created in a caller-selected local path. On POSIX, the
implementation should attempt owner-only file permissions. On Windows, document
that ACL management is host responsibility unless a platform-specific ACL
implementation is added.

Persisting actor tokens stores secret material locally. Durable actor-token
storage should be avoided unless the host protects the database path. Future
scoped capabilities should store only non-secret metadata or keyed hashes when
possible.

## Corruption Handling

On JSON parse failure, missing schema, unsupported schema version, hash mismatch,
or SQLite operational error during a security decision, the store must fail
closed. It must not create a fresh empty state for an existing run after
corruption.

## Unsupported Claims

This design does not provide:

- rollback resistance.
- protection against privileged local attackers.
- tamper-proof audit.
- OS process containment.
- network egress control.
- atomicity between SQLite state and external tool side effects.

## Compatibility

`InMemoryRunStore` remains supported for tests and single-process ephemeral
local runs. Durable production-like integrations should use the SQLite store
only after implementation and tests satisfy this ADR.

## Test Requirements Before Acceptance

- concurrent proposals from threads and processes.
- authorization consumption replay across store instances.
- restart recovery after `started` without final outcome.
- corrupt JSON and hash mismatch fail closed.
- schema version mismatch fail closed.
- expired run cannot consume authorization.
- cancelled run cannot consume authorization.
- duplicate/replayed outcomes rejected.
- policy fingerprint mismatch rejected.
- unavailable database path fails closed.
