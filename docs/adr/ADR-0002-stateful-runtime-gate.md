# ADR-0002: Minimal Stateful Runtime Gate

Date: 2026-10-15

## Status

Accepted for local Phase 2 implementation.

## Context

Retrospective trajectory evaluation is useful, but it does not itself prevent a
live agent from omitting, reordering, or resetting history. The actor and
delegation checks added to trajectory records are only as strong as the
integration that supplies those fields. If an untrusted agent can fabricate
`actor` or `delegated_by`, those fields are labels, not identity.

Market and research review points in the same direction: useful runtime
controls interrupt or mediate the proposed tool call before execution, preserve
state, and bind approval/recovery to the exact action context. LangGraph,
AutoGen, Microsoft Agent Framework, OpenAI Agents SDK tracing, MCP security
guidance, and AgentWall all emphasize live tool mediation, state, approval, or
auditability rather than only single-command classification.

## Decision

Add `RuntimeGate`, a small backwards-compatible async API:

1. create a run with an explicit contract.
2. submit one proposed action before execution.
3. evaluate the proposed action against current state and prior proposals.
4. authorize only aggregate `allow`.
5. return a single-use `authorization_id` for allowed proposals.
6. record the proposal atomically before the next proposal.
7. consume the authorization through `execute_authorized`, recording `started`
   before side effects and final outcome afterward.
8. bind post-execution outcome reporting to the exact authorized action
   fingerprint and authorization ID.
9. return recovery evidence for denied proposals without automatically spawning
   a new agent.

Add `RuntimeToolExecutor` as the first-party supported integration wrapper for
trusted local adapters. It normalizes proposed actions, binds
integration-controlled metadata before authorization, rejects metadata
substitution attempts, consumes the returned authorization ID through
`execute_authorized`, and returns both the decision and execution result.

The first store is `InMemoryRunStore`. It is intentionally local and
dependency-free. A durable store can be added behind the same API after
specifying crash recovery, locking, and integrity guarantees.

## Security Guarantees

Enforced by code:

- `UNKNOWN`, `ERROR`, `BLOCK`, and `PENDING_APPROVAL` are not executable
  runtime authorizations.
- run status, expiration, cancellation, and `max_actions` are checked before
  evaluating a proposed action.
- proposals are serialized inside one process by the in-memory store lock.
- `record_outcome` rejects fingerprints that do not match an authorized
  proposal in the same run.
- optional `actor_tokens` are checked before trajectory evaluation and are not
  serialized in public run state.
- forged, denied, and replayed authorization IDs are rejected before the
  executor is called.
- unresolved started executions block dependent proposals in the same process.
- `RuntimeToolExecutor` rejects caller metadata that conflicts with trusted
  integration metadata before side effects.
- cancellation/timeout records `unknown_execution_status` so dependent actions
  do not proceed automatically.

Guaranteed only when integration behaves correctly:

- every privileged tool call is submitted before execution.
- `authorized: false` actually stops execution.
- actor tokens remain outside model-visible state.
- the integration executes the same action that ACB authorized.

Dependent on external runtime or OS boundary:

- preventing direct shell, filesystem, database, MCP, or network access that
  bypasses ACB.
- killing or isolating a compromised agent process.
- network egress enforcement.
- durable local state across process crash with rollback resistance.

Not implemented:

- automatic subagent respawn.
- cryptographic run-state attestation.
- durable cross-process runtime locking.
- semantic dataflow across arbitrary transformations.
- full shell or SQL parsing.

Unknown and requiring further testing:

- exact adapter behavior across every third-party agent framework and MCP
  client/server variant.
- false-positive rate on large real developer workflows.

## Compatibility

The change is additive. Existing `evaluate_action`, `evaluate_trajectory`,
CLI, MCP proxy, pipeline SDK, approval, and ledger APIs remain available.

## Failure Modes

- If the integration exposes actor tokens to the model, actor authentication is
  weakened.
- If the process restarts, the default in-memory store loses run state.
- If multiple processes use separate stores, they can authorize from stale
  local state.
- If the caller ignores `authorized: false`, ACB cannot prevent execution.
- If the caller uses `propose_action` but executes outside `execute_authorized`,
  ACB cannot prove that the exact authorized action was executed.
- If the process is killed after `started` and after a tool side effect, the
  default in-memory store cannot recover that uncertain execution state.
- If callers invoke the underlying executor directly instead of through
  `RuntimeToolExecutor`, ACB is bypassed.

## Test Plan

Tests cover allowed proposals, unknown and blocked proposals, missing actor
identity, forged actor token metadata, valid actor tokens, unauthorized
delegation, replayed outcome fingerprints, outcome reporting for denied
actions, forged authorization IDs, denied-action execution, authorization
replay, executor failure recording, unresolved execution blocking,
cancellation, expiration, malformed inputs, and concurrent proposals under
`max_actions`.

## Consequences

ACB gains a concrete live enforcement API without becoming a sandbox or hosted
control plane. The next high-value work is to connect this runtime gate to one
trusted integration end to end and add an optional durable local store with
documented recovery semantics.
