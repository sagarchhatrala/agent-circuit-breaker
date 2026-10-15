"""Stateful local runtime authorization gate.

This module is intentionally small and local-first. It does not execute tools,
authenticate operating-system users, or sandbox agents. It gives trusted
integrations a stateful pre-execution gate: create a run, propose one action at
a time, authorize only explicit ALLOW decisions, and preserve local evidence.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import json
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import closing
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional

from agent_circuit_breaker.api import evaluate_action
from agent_circuit_breaker.trajectory import evaluate_trajectory


Evaluator = Callable[[str], Dict[str, Any]]
Executor = Callable[[Dict[str, Any]], Any]
SQLITE_RUN_STORE_SCHEMA_VERSION = 1
SUPPORTED_SQLITE_SCHEMA_VERSIONS = (1,)


class RuntimeStoreError(RuntimeError):
    """Base class for runtime persistence failures that must fail closed."""

    reason_code = "STORE_ERROR"


class RuntimeStoreUnavailable(RuntimeStoreError):
    reason_code = "STORE_UNAVAILABLE"


class RuntimeStoreBusy(RuntimeStoreError):
    reason_code = "STORE_BUSY"


class RuntimeSchemaError(RuntimeStoreError):
    reason_code = "SCHEMA_INCOMPATIBLE"


class RuntimeMigrationError(RuntimeStoreError):
    reason_code = "MIGRATION_FAILURE"


class RuntimeIntegrityError(RuntimeStoreError):
    reason_code = "INTEGRITY_VERIFICATION_FAILURE"


class RuntimeMissingStateError(RuntimeStoreError):
    reason_code = "MISSING_REQUIRED_STATE"


class RuntimeInvalidRecordError(RuntimeStoreError):
    reason_code = "INVALID_PERSISTED_RECORD"


class RuntimeStateConflictError(RuntimeStoreError):
    reason_code = "STATE_CONFLICT"


@dataclass(frozen=True)
class CapabilityGrant:
    """Least-privilege authority granted to a principal for one run."""

    capability_id: str
    principal: str
    action_types: tuple[str, ...] = ()
    target_resources: tuple[str, ...] = ()
    actors: tuple[str, ...] = ()
    expires_at: Optional[float] = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CapabilityGrant":
        if not isinstance(value, Mapping):
            raise ValueError("capabilities entries must be objects")
        capability_id = value.get("id", value.get("capability_id"))
        principal = value.get("principal")
        if not isinstance(capability_id, str) or not capability_id:
            raise ValueError("capability id must be a non-empty string")
        if not isinstance(principal, str) or not principal:
            raise ValueError(f"capabilities[{capability_id}].principal must be a non-empty string")
        expires_at_value = value.get("expires_at")
        if expires_at_value is not None and not isinstance(expires_at_value, (int, float)):
            raise ValueError(f"capabilities[{capability_id}].expires_at must be a number")
        return cls(
            capability_id=capability_id,
            principal=principal,
            action_types=tuple(_string_list(value.get("action_types"), f"capabilities[{capability_id}].action_types")),
            target_resources=tuple(
                _string_list(value.get("target_resources"), f"capabilities[{capability_id}].target_resources")
            ),
            actors=tuple(_string_list(value.get("actors"), f"capabilities[{capability_id}].actors")),
            expires_at=float(expires_at_value) if expires_at_value is not None else None,
        )

    def public_summary(self) -> Dict[str, Any]:
        return {
            "id": self.capability_id,
            "principal": self.principal,
            "action_types": list(self.action_types),
            "target_resources": list(self.target_resources),
            "actors": list(self.actors),
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class RunContract:
    """Stateful runtime contract for one agent run."""

    goal: Optional[str] = None
    allowed_scopes: tuple[str, ...] = ()
    forbidden_targets: tuple[str, ...] = ()
    allowed_outputs: tuple[str, ...] = ()
    allowed_actors: tuple[str, ...] = ()
    forbidden_actors: tuple[str, ...] = ()
    allowed_delegations: tuple[tuple[str, str], ...] = ()
    require_actor: bool = False
    max_blocked_attempts: int = 1
    max_unknown_actions: Optional[int] = None
    max_actions: Optional[int] = None
    ttl_seconds: Optional[int] = None
    actor_tokens: Mapping[str, str] = field(default_factory=dict, repr=False, compare=False)
    principal_tokens: Mapping[str, str] = field(default_factory=dict, repr=False, compare=False)
    capabilities: tuple[CapabilityGrant, ...] = ()
    approval_required_action_types: tuple[str, ...] = ()
    approval_required_targets: tuple[str, ...] = ()
    approver_tokens: Mapping[str, str] = field(default_factory=dict, repr=False, compare=False)
    allow_self_approval: bool = False
    reconciler_tokens: Mapping[str, str] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_mapping(cls, value: Optional[Mapping[str, Any]]) -> "RunContract":
        """Build a contract from a JSON-compatible mapping."""
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            raise ValueError("runtime contract must be an object")

        return cls(
            goal=_optional_string(value.get("goal"), "goal"),
            allowed_scopes=tuple(_string_list(value.get("allowed_scopes"), "allowed_scopes")),
            forbidden_targets=tuple(_string_list(value.get("forbidden_targets"), "forbidden_targets")),
            allowed_outputs=tuple(_string_list(value.get("allowed_outputs"), "allowed_outputs")),
            allowed_actors=tuple(_string_list(value.get("allowed_actors"), "allowed_actors")),
            forbidden_actors=tuple(_string_list(value.get("forbidden_actors"), "forbidden_actors")),
            allowed_delegations=tuple(_delegation_pairs(value.get("allowed_delegations"))),
            require_actor=_optional_bool(value.get("require_actor"), "require_actor", False),
            max_blocked_attempts=_optional_int(value.get("max_blocked_attempts"), "max_blocked_attempts", 1) or 1,
            max_unknown_actions=_optional_int(value.get("max_unknown_actions"), "max_unknown_actions", None),
            max_actions=_optional_int(value.get("max_actions"), "max_actions", None),
            ttl_seconds=_optional_int(value.get("ttl_seconds"), "ttl_seconds", None),
            actor_tokens=_actor_tokens(value.get("actor_tokens")),
            principal_tokens=_principal_tokens(value.get("principal_tokens")),
            capabilities=tuple(_capability_grants(value.get("capabilities"))),
            approval_required_action_types=tuple(
                _string_list(value.get("approval_required_action_types"), "approval_required_action_types")
            ),
            approval_required_targets=tuple(
                _string_list(value.get("approval_required_targets"), "approval_required_targets")
            ),
            approver_tokens=_approver_tokens(value.get("approver_tokens")),
            allow_self_approval=_optional_bool(value.get("allow_self_approval"), "allow_self_approval", False),
            reconciler_tokens=_reconciler_tokens(value.get("reconciler_tokens")),
        )

    def to_trajectory_contract(self) -> Dict[str, Any]:
        """Return the subset understood by trajectory evaluation."""
        return {
            "goal": self.goal,
            "allowed_scopes": list(self.allowed_scopes),
            "forbidden_targets": list(self.forbidden_targets),
            "allowed_outputs": list(self.allowed_outputs),
            "allowed_actors": list(self.allowed_actors),
            "forbidden_actors": list(self.forbidden_actors),
            "allowed_delegations": [
                {"from": source, "to": target}
                for source, target in self.allowed_delegations
            ],
            "require_actor": self.require_actor,
            "max_blocked_attempts": self.max_blocked_attempts,
            "max_unknown_actions": self.max_unknown_actions,
        }

    def public_summary(self) -> Dict[str, Any]:
        """Return a public summary without actor token material."""
        summary = self.to_trajectory_contract()
        summary.update(
            {
                "max_actions": self.max_actions,
                "ttl_seconds": self.ttl_seconds,
                "policy_fingerprint": self.policy_fingerprint,
                "actor_authentication": "token" if self.actor_tokens else "trusted_integration_metadata",
                "principal_authentication": "token" if self.principal_tokens else "trusted_integration_metadata",
                "capabilities": [capability.public_summary() for capability in self.capabilities],
                "approval_required_action_types": list(self.approval_required_action_types),
                "approval_required_targets": list(self.approval_required_targets),
                "approval_authority": "token" if self.approver_tokens else "trusted_integration_metadata",
                "allow_self_approval": self.allow_self_approval,
                "reconciliation_authority": "token" if self.reconciler_tokens else "trusted_integration_metadata",
            }
        )
        return summary

    @property
    def policy_fingerprint(self) -> str:
        """Return a stable fingerprint for policy fields that affect authorization."""
        payload = {
            **self.to_trajectory_contract(),
            "max_actions": self.max_actions,
            "ttl_seconds": self.ttl_seconds,
            "actor_authentication": "token" if self.actor_tokens else "trusted_integration_metadata",
            "principal_authentication": "token" if self.principal_tokens else "trusted_integration_metadata",
            "capabilities": [capability.public_summary() for capability in self.capabilities],
            "approval_required_action_types": list(self.approval_required_action_types),
            "approval_required_targets": list(self.approval_required_targets),
            "approval_authority": "token" if self.approver_tokens else "trusted_integration_metadata",
            "allow_self_approval": self.allow_self_approval,
            "reconciliation_authority": "token" if self.reconciler_tokens else "trusted_integration_metadata",
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RuntimeAction:
    """One proposed action before execution."""

    command: str
    actor: Optional[str] = None
    delegated_by: Optional[str] = None
    tool_name: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    actor_token: Optional[str] = field(default=None, repr=False, compare=False)
    principal: Optional[str] = None
    capability_id: Optional[str] = None
    action_type: str = "command"
    target_resource: Optional[str] = None
    principal_token: Optional[str] = field(default=None, repr=False, compare=False)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RuntimeAction":
        if not isinstance(value, Mapping):
            raise ValueError("runtime action must be an object")
        command = value.get("command", value.get("action"))
        if not isinstance(command, str) or not command:
            raise ValueError("runtime action command must be a non-empty string")
        return cls(
            command=command,
            actor=_optional_string(value.get("actor"), "actor"),
            delegated_by=_optional_string(value.get("delegated_by"), "delegated_by"),
            tool_name=_optional_string(value.get("tool_name"), "tool_name"),
            request_id=_optional_string(value.get("request_id"), "request_id"),
            metadata=_metadata(value.get("metadata")),
            actor_token=_optional_string(value.get("actor_token"), "actor_token"),
            principal=_optional_string(value.get("principal"), "principal"),
            capability_id=_optional_string(value.get("capability_id", value.get("capability")), "capability_id"),
            action_type=_action_type(value.get("action_type")),
            target_resource=_optional_string(value.get("target_resource", value.get("target")), "target_resource"),
            principal_token=_optional_string(value.get("principal_token"), "principal_token"),
        )

    def to_trajectory_record(self) -> Dict[str, Any]:
        record: Dict[str, Any] = {"command": self.command}
        if self.action_type != "command":
            record["action_type"] = self.action_type
        for field_name in (
            "actor",
            "delegated_by",
            "tool_name",
            "request_id",
            "principal",
            "capability_id",
            "target_resource",
        ):
            value = getattr(self, field_name)
            if value is not None:
                record[field_name] = value
        if self.metadata:
            record["metadata"] = dict(self.metadata)
        return _json_data(record)

    @property
    def fingerprint(self) -> str:
        encoded = json.dumps(self.to_trajectory_record(), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RuntimeEvent:
    """Recorded runtime proposal outcome."""

    sequence: int
    event_type: str
    action: Optional[Dict[str, Any]]
    verdict: str
    decision: str
    authorized: bool
    reason: str
    action_fingerprint: Optional[str]
    timestamp: float
    authorization_id: Optional[str] = None
    policy_fingerprint: Optional[str] = None
    trajectory: Optional[Dict[str, Any]] = None
    outcome: Optional[str] = None
    reason_code: Optional[str] = None
    approval_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeState:
    """Current state for one run."""

    run_id: str
    status: str
    contract: Dict[str, Any]
    created_at: float
    expires_at: Optional[float]
    version: int
    events: tuple[RuntimeEvent, ...] = ()
    last_reason: Optional[str] = None

    def action_records(self) -> list[Dict[str, Any]]:
        return [
            event.action
            for event in self.events
            if event.action is not None and event.event_type == "proposal"
        ]

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["events"] = [event.to_dict() for event in self.events]
        return payload


@dataclass(frozen=True)
class RuntimeDecision:
    """Authorization result for one proposed runtime action."""

    run_id: str
    run_status: str
    authorized: bool
    verdict: str
    decision: str
    reason: str
    sequence: int
    state_version: int
    action_fingerprint: str
    trajectory: Optional[Dict[str, Any]]
    authorization_id: Optional[str] = None
    policy_fingerprint: Optional[str] = None
    recovery: Optional[Dict[str, Any]] = None
    reason_code: Optional[str] = None
    approval_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeExecutionResult:
    """Result of executing through a consumed runtime authorization."""

    run_id: str
    authorization_id: str
    action_fingerprint: str
    outcome: str
    result: Any
    state: RuntimeState

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["state"] = self.state.to_dict()
        return payload


@dataclass(frozen=True)
class RuntimeApproval:
    """Trusted approval grant bound to one canonical runtime action."""

    run_id: str
    approval_id: str
    action_fingerprint: str
    policy_fingerprint: str
    approver: str
    expires_at: Optional[float]
    sequence: int
    reason: str
    reason_code: str = "APPROVAL_GRANTED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeToolCallResult:
    """Result from the first-party runtime tool executor integration."""

    decision: RuntimeDecision
    execution: Optional[RuntimeExecutionResult] = None

    @property
    def executed(self) -> bool:
        return self.execution is not None and self.execution.outcome == "executed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.to_dict(),
            "execution": self.execution.to_dict() if self.execution else None,
            "executed": self.executed,
        }


class InMemoryRunStore:
    """Atomic in-memory run store for local integrations and tests."""

    def __init__(self) -> None:
        self._states: Dict[str, RuntimeState] = {}
        self._contracts: Dict[str, RunContract] = {}
        self._lock = asyncio.Lock()

    async def create(self, state: RuntimeState) -> RuntimeState:
        async with self._lock:
            if state.run_id in self._states:
                raise ValueError(f"runtime run already exists: {state.run_id}")
            self._states[state.run_id] = state
            return state

    async def read(self, run_id: str) -> RuntimeState:
        async with self._lock:
            try:
                return self._states[run_id]
            except KeyError as exc:
                raise KeyError(f"runtime run not found: {run_id}") from exc

    async def update(self, run_id: str, updater: Callable[[RuntimeState], RuntimeState]) -> RuntimeState:
        async with self._lock:
            try:
                state = self._states[run_id]
            except KeyError as exc:
                raise KeyError(f"runtime run not found: {run_id}") from exc
            next_state = updater(state)
            self._states[run_id] = next_state
            return next_state

    async def set_contract(self, run_id: str, contract: RunContract) -> None:
        async with self._lock:
            if run_id not in self._states:
                raise KeyError(f"runtime run not found: {run_id}")
            self._contracts[run_id] = contract
            state = self._states[run_id]
            self._states[run_id] = RuntimeState(
                run_id=state.run_id,
                status=state.status,
                contract=contract.public_summary(),
                created_at=state.created_at,
                expires_at=state.expires_at,
                version=state.version,
                events=state.events,
                last_reason=state.last_reason,
            )

    def contract_for(self, run_id: str) -> RunContract:
        try:
            return self._contracts[run_id]
        except KeyError as exc:
            raise KeyError(f"runtime contract not found: {run_id}") from exc


class SQLiteRunStore:
    """Durable SQLite-backed run store for local trusted executors.

    The store persists runtime state and private contract material in the same
    SQLite database. It provides atomic update transitions with
    ``BEGIN IMMEDIATE`` so multiple local processes using the same database
    cannot silently consume the same authorization twice.

    Security boundary: this is a local durability and coordination mechanism,
    not encryption. A host principal with read/write access to the database can
    inspect or rewrite local state. Use filesystem permissions appropriate for
    the deployment.
    """

    def __init__(self, path: str, *, timeout_seconds: float = 5.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = Path(path)
        self.timeout_seconds = timeout_seconds
        self._lock = threading.RLock()
        self._local = threading.local()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    async def create(self, state: RuntimeState) -> RuntimeState:
        return await asyncio.to_thread(self._create_sync, state)

    async def read(self, run_id: str) -> RuntimeState:
        return await asyncio.to_thread(self._read_sync, run_id)

    async def update(self, run_id: str, updater: Callable[[RuntimeState], RuntimeState]) -> RuntimeState:
        return await asyncio.to_thread(self._update_sync, run_id, updater)

    async def set_contract(self, run_id: str, contract: RunContract) -> None:
        await asyncio.to_thread(self._set_contract_sync, run_id, contract)

    async def validate_integrity(self) -> Dict[str, Any]:
        return await asyncio.to_thread(self._validate_integrity_sync)

    async def health(self) -> Dict[str, Any]:
        return await self.validate_integrity()

    def contract_for(self, run_id: str) -> RunContract:
        cached = getattr(self._local, "contracts", None)
        if isinstance(cached, dict) and run_id in cached:
            return cached[run_id]
        return self._read_contract_sync(run_id)

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.path, timeout=self.timeout_seconds)
        except sqlite3.Error as exc:
            raise RuntimeStoreUnavailable(f"runtime store unavailable: {exc}") from exc
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1000)}")
        return connection

    def _initialize(self) -> None:
        try:
            with self._lock, closing(self._connect()) as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("BEGIN IMMEDIATE")
                self._ensure_schema_sync(connection)
                self._validate_database_sync(connection)
                connection.commit()
        except sqlite3.OperationalError as exc:
            raise _sqlite_runtime_error(exc) from exc
        except sqlite3.Error as exc:
            raise RuntimeStoreUnavailable(f"runtime store unavailable: {exc}") from exc

    def _create_sync(self, state: RuntimeState) -> RuntimeState:
        try:
            with self._lock, closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_database_sync(connection)
                exists = connection.execute(
                    "SELECT 1 FROM runtime_runs WHERE run_id = ?",
                    (state.run_id,),
                ).fetchone()
                if exists is not None:
                    connection.rollback()
                    raise ValueError(f"runtime run already exists: {state.run_id}")
                connection.execute(
                    "INSERT INTO runtime_runs (run_id, state_json) VALUES (?, ?)",
                    (state.run_id, _encode_state(state)),
                )
                connection.commit()
                return state
        except sqlite3.OperationalError as exc:
            raise _sqlite_runtime_error(exc) from exc
        except sqlite3.Error as exc:
            raise RuntimeStoreUnavailable(f"runtime store unavailable: {exc}") from exc

    def _read_sync(self, run_id: str) -> RuntimeState:
        try:
            with self._lock, closing(self._connect()) as connection:
                self._validate_schema_metadata_sync(connection)
                row = connection.execute(
                    "SELECT state_json FROM runtime_runs WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if row is None:
                    raise KeyError(f"runtime run not found: {run_id}")
                state = _decode_state(row[0])
                contract = self._read_contract_for_connection(connection, run_id)
                _validate_state_integrity(state, contract)
                return state
        except sqlite3.OperationalError as exc:
            raise _sqlite_runtime_error(exc) from exc
        except sqlite3.Error as exc:
            raise RuntimeStoreUnavailable(f"runtime store unavailable: {exc}") from exc

    def _update_sync(self, run_id: str, updater: Callable[[RuntimeState], RuntimeState]) -> RuntimeState:
        try:
            with self._lock, closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_schema_metadata_sync(connection)
                state_row = connection.execute(
                    "SELECT state_json FROM runtime_runs WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if state_row is None:
                    connection.rollback()
                    raise KeyError(f"runtime run not found: {run_id}")
                contract_row = connection.execute(
                    "SELECT contract_json FROM runtime_contracts WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if contract_row is None:
                    connection.rollback()
                    raise RuntimeMissingStateError(f"runtime contract not found: {run_id}")

                state = _decode_state(state_row[0])
                contract = _decode_contract(contract_row[0])
                _validate_state_integrity(state, contract)
                previous_cache = getattr(self._local, "contracts", None)
                cache = dict(previous_cache or {})
                cache[run_id] = contract
                self._local.contracts = cache
                try:
                    next_state = updater(state)
                    _validate_state_integrity(next_state, contract)
                finally:
                    if previous_cache is None:
                        try:
                            del self._local.contracts
                        except AttributeError:
                            pass
                    else:
                        self._local.contracts = previous_cache

                connection.execute(
                    "UPDATE runtime_runs SET state_json = ? WHERE run_id = ?",
                    (_encode_state(next_state), run_id),
                )
                connection.commit()
                return next_state
        except sqlite3.OperationalError as exc:
            raise _sqlite_runtime_error(exc) from exc
        except sqlite3.Error as exc:
            raise RuntimeStoreUnavailable(f"runtime store unavailable: {exc}") from exc

    def _set_contract_sync(self, run_id: str, contract: RunContract) -> None:
        try:
            with self._lock, closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_schema_metadata_sync(connection)
                state_row = connection.execute(
                    "SELECT state_json FROM runtime_runs WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if state_row is None:
                    connection.rollback()
                    raise KeyError(f"runtime run not found: {run_id}")
                state = _decode_state(state_row[0])
                next_state = RuntimeState(
                    run_id=state.run_id,
                    status=state.status,
                    contract=contract.public_summary(),
                    created_at=state.created_at,
                    expires_at=state.expires_at,
                    version=state.version,
                    events=state.events,
                    last_reason=state.last_reason,
                )
                _validate_state_integrity(next_state, contract)
                connection.execute(
                    """
                    INSERT INTO runtime_contracts (run_id, contract_json)
                    VALUES (?, ?)
                    ON CONFLICT(run_id) DO UPDATE SET contract_json = excluded.contract_json
                    """,
                    (run_id, _encode_contract(contract)),
                )
                connection.execute(
                    "UPDATE runtime_runs SET state_json = ? WHERE run_id = ?",
                    (_encode_state(next_state), run_id),
                )
                connection.commit()
        except sqlite3.OperationalError as exc:
            raise _sqlite_runtime_error(exc) from exc
        except sqlite3.Error as exc:
            raise RuntimeStoreUnavailable(f"runtime store unavailable: {exc}") from exc

    def _read_contract_sync(self, run_id: str) -> RunContract:
        try:
            with self._lock, closing(self._connect()) as connection:
                self._validate_schema_metadata_sync(connection)
                return self._read_contract_for_connection(connection, run_id)
        except sqlite3.OperationalError as exc:
            raise _sqlite_runtime_error(exc) from exc
        except sqlite3.Error as exc:
            raise RuntimeStoreUnavailable(f"runtime store unavailable: {exc}") from exc

    def _read_contract_for_connection(self, connection: sqlite3.Connection, run_id: str) -> RunContract:
        row = connection.execute(
            "SELECT contract_json FROM runtime_contracts WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise RuntimeMissingStateError(f"runtime contract not found: {run_id}")
        return _decode_contract(row[0])

    def _validate_integrity_sync(self) -> Dict[str, Any]:
        try:
            with self._lock, closing(self._connect()) as connection:
                self._validate_database_sync(connection)
                run_count = connection.execute("SELECT COUNT(*) FROM runtime_runs").fetchone()[0]
                unresolved = 0
                for (payload,) in connection.execute("SELECT state_json FROM runtime_runs"):
                    state = _decode_state(payload)
                    if _has_unresolved_execution(state):
                        unresolved += 1
                return {
                    "ok": True,
                    "schema_version": SQLITE_RUN_STORE_SCHEMA_VERSION,
                    "run_count": int(run_count),
                    "unresolved_execution_runs": unresolved,
                    "store": str(self.path),
                }
        except sqlite3.OperationalError as exc:
            raise _sqlite_runtime_error(exc) from exc
        except sqlite3.Error as exc:
            raise RuntimeStoreUnavailable(f"runtime store unavailable: {exc}") from exc

    def _ensure_schema_sync(self, connection: sqlite3.Connection) -> None:
        tables = _sqlite_tables(connection)
        has_metadata = "runtime_metadata" in tables
        has_runs = "runtime_runs" in tables
        has_contracts = "runtime_contracts" in tables

        if has_metadata:
            migration_state = _metadata_value(connection, "migration_state")
            if migration_state not in {None, "complete"}:
                raise RuntimeMigrationError("runtime store migration is incomplete")
            version_value = _metadata_value(connection, "schema_version")
            if version_value is None:
                raise RuntimeSchemaError("runtime metadata missing schema_version")
            version = _parse_schema_version(version_value)
            if version > SQLITE_RUN_STORE_SCHEMA_VERSION:
                raise RuntimeSchemaError(f"unsupported future runtime schema version: {version}")
            if version not in SUPPORTED_SQLITE_SCHEMA_VERSIONS:
                raise RuntimeSchemaError(f"unsupported runtime schema version: {version}")

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_runs (
                run_id TEXT PRIMARY KEY,
                state_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_contracts (
                run_id TEXT PRIMARY KEY,
                contract_json TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES runtime_runs(run_id) ON DELETE CASCADE
            )
            """
        )

        if (has_runs and not has_contracts) or (has_contracts and not has_runs):
            raise RuntimeSchemaError("partial legacy runtime schema is missing required tables")

        connection.execute(
            "INSERT OR REPLACE INTO runtime_metadata (key, value) VALUES (?, ?)",
            ("schema_version", str(SQLITE_RUN_STORE_SCHEMA_VERSION)),
        )
        connection.execute(
            "INSERT OR REPLACE INTO runtime_metadata (key, value) VALUES (?, ?)",
            ("migration_state", "complete"),
        )

    def _validate_schema_metadata_sync(self, connection: sqlite3.Connection) -> None:
        tables = _sqlite_tables(connection)
        for table_name in ("runtime_metadata", "runtime_runs", "runtime_contracts"):
            if table_name not in tables:
                raise RuntimeSchemaError(f"runtime store missing table: {table_name}")
        version = _parse_schema_version(_metadata_value(connection, "schema_version"))
        if version not in SUPPORTED_SQLITE_SCHEMA_VERSIONS:
            raise RuntimeSchemaError(f"unsupported runtime schema version: {version}")
        if _metadata_value(connection, "migration_state") != "complete":
            raise RuntimeMigrationError("runtime store migration is incomplete")
        _require_columns(connection, "runtime_runs", {"run_id", "state_json"})
        _require_columns(connection, "runtime_contracts", {"run_id", "contract_json"})

    def _validate_database_sync(self, connection: sqlite3.Connection) -> None:
        self._validate_schema_metadata_sync(connection)
        quick_check = connection.execute("PRAGMA quick_check").fetchone()
        if quick_check is None or quick_check[0] != "ok":
            raise RuntimeIntegrityError(f"sqlite quick_check failed: {quick_check}")
        rows = connection.execute(
            """
            SELECT r.run_id, r.state_json, c.contract_json
            FROM runtime_runs r
            LEFT JOIN runtime_contracts c ON c.run_id = r.run_id
            """
        ).fetchall()
        for run_id, state_json, contract_json in rows:
            if contract_json is None:
                raise RuntimeMissingStateError(f"runtime contract not found: {run_id}")
            state = _decode_state(state_json)
            contract = _decode_contract(contract_json)
            if state.run_id != run_id:
                raise RuntimeIntegrityError("runtime state run_id does not match row key")
            _validate_state_integrity(state, contract)

        dangling_contract = connection.execute(
            """
            SELECT c.run_id
            FROM runtime_contracts c
            LEFT JOIN runtime_runs r ON r.run_id = c.run_id
            WHERE r.run_id IS NULL
            LIMIT 1
            """
        ).fetchone()
        if dangling_contract is not None:
            raise RuntimeIntegrityError(f"runtime contract has no run: {dangling_contract[0]}")

class RuntimeGate:
    """Stateful pre-execution authorization gate."""

    def __init__(
        self,
        *,
        store: InMemoryRunStore | None = None,
        evaluator: Evaluator | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store or InMemoryRunStore()
        self.evaluator = evaluator or evaluate_action
        self.clock = clock

    async def create_run(
        self,
        contract: Mapping[str, Any] | RunContract | None = None,
        *,
        run_id: Optional[str] = None,
    ) -> RuntimeState:
        """Create a local runtime run."""
        parsed = contract if isinstance(contract, RunContract) else RunContract.from_mapping(contract)
        now = self.clock()
        state = RuntimeState(
            run_id=run_id or uuid.uuid4().hex,
            status="active",
            contract=parsed.public_summary(),
            created_at=now,
            expires_at=(now + parsed.ttl_seconds) if parsed.ttl_seconds else None,
            version=0,
            events=(),
        )
        created = await self.store.create(state)
        # Keep private token material outside public state. RuntimeGate and its
        # store are trusted integration objects; returned RuntimeState is safe to
        # serialize for diagnostics.
        await self.store.set_contract(created.run_id, parsed)
        return await self.store.read(created.run_id)

    async def propose_action(self, run_id: str, action: RuntimeAction | Mapping[str, Any]) -> RuntimeDecision:
        """Evaluate and record one proposed action before execution."""
        proposed = action if isinstance(action, RuntimeAction) else RuntimeAction.from_mapping(action)
        holder: Dict[str, RuntimeDecision] = {}

        def update(state: RuntimeState) -> RuntimeState:
            contract = self.store.contract_for(state.run_id)
            now = self.clock()
            precheck = _precheck_state(state, proposed, contract, now)
            if precheck is not None:
                event, decision = precheck
            else:
                trajectory_actions = state.action_records() + [proposed.to_trajectory_record()]
                trajectory = evaluate_trajectory(
                    trajectory_actions,
                    self.evaluator,
                    contract=contract.to_trajectory_contract(),
                )
                authorized = trajectory.get("verdict") == "allow"
                reason = _reason_from_trajectory(trajectory)
                if not authorized:
                    reason = reason or "runtime action was not authorized"
                reason_code = "AUTHORIZED" if authorized else _reason_code_from_trajectory(trajectory)
                approval_required = authorized and _approval_required(proposed, contract)
                if approval_required:
                    authorized = False
                    reason = "approval required before execution"
                    reason_code = "APPROVAL_REQUIRED"
                authorization_id = _new_authorization_id() if authorized else None
                event = RuntimeEvent(
                    sequence=len(state.events),
                    event_type="proposal",
                    action=proposed.to_trajectory_record(),
                    verdict="pending_approval" if approval_required else str(trajectory.get("verdict")),
                    decision="PENDING_APPROVAL" if approval_required else str(trajectory.get("decision")),
                    authorized=authorized,
                    reason=reason,
                    action_fingerprint=proposed.fingerprint,
                    timestamp=now,
                    authorization_id=authorization_id,
                    policy_fingerprint=contract.policy_fingerprint,
                    trajectory=trajectory,
                    reason_code=reason_code,
                )
                next_status = "active" if (authorized or approval_required) else "blocked"
                decision = RuntimeDecision(
                    run_id=state.run_id,
                    run_status=next_status,
                    authorized=authorized,
                    verdict=event.verdict,
                    decision=event.decision,
                    reason=reason,
                    sequence=event.sequence,
                    state_version=state.version + 1,
                    action_fingerprint=proposed.fingerprint,
                    trajectory=trajectory,
                    authorization_id=authorization_id,
                    policy_fingerprint=contract.policy_fingerprint,
                    recovery=None if (authorized or approval_required) else _recovery_recommendation(state, event),
                    reason_code=reason_code,
                )

            holder["decision"] = decision
            return RuntimeState(
                run_id=state.run_id,
                status=decision.run_status,
                contract=state.contract,
                created_at=state.created_at,
                expires_at=state.expires_at,
                version=state.version + 1,
                events=state.events + (event,),
                last_reason=decision.reason,
            )

        await self.store.update(run_id, update)
        return holder["decision"]

    async def record_outcome(
        self,
        run_id: str,
        *,
        action_fingerprint: Optional[str] = None,
        authorization_id: Optional[str] = None,
        outcome: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> RuntimeState:
        """Record execution outcome after an authorized caller executes the action."""
        if outcome not in {"executed", "failed", "skipped", "unknown_execution_status"}:
            raise ValueError("outcome must be executed, failed, skipped, or unknown_execution_status")
        if not action_fingerprint and not authorization_id:
            raise ValueError("action_fingerprint or authorization_id is required")

        def update(state: RuntimeState) -> RuntimeState:
            matching = _matching_open_authorization(
                state,
                action_fingerprint=action_fingerprint,
                authorization_id=authorization_id,
            )
            if matching is None:
                raise ValueError("outcome does not match an authorized action in this run")
            event = RuntimeEvent(
                sequence=len(state.events),
                event_type="outcome",
                action=None,
                verdict=matching.verdict,
                decision=matching.decision,
                authorized=matching.authorized,
                reason="execution outcome recorded",
                action_fingerprint=matching.action_fingerprint,
                timestamp=self.clock(),
                authorization_id=matching.authorization_id,
                policy_fingerprint=matching.policy_fingerprint,
                trajectory=None,
                outcome=outcome,
                reason_code="EXECUTION_OUTCOME_RECORDED",
            )
            metadata = dict(details or {})
            if metadata:
                event = RuntimeEvent(**{**event.to_dict(), "trajectory": {"details": metadata}})
            return RuntimeState(
                run_id=state.run_id,
                status=state.status,
                contract=state.contract,
                created_at=state.created_at,
                expires_at=state.expires_at,
                version=state.version + 1,
                events=state.events + (event,),
                last_reason=state.last_reason,
            )

        return await self.store.update(run_id, update)

    async def execute_authorized(
        self,
        run_id: str,
        *,
        authorization_id: str,
        executor: Executor,
    ) -> RuntimeExecutionResult:
        """Consume a single-use authorization and execute through a trusted caller.

        The executor receives the exact public action record that was authorized.
        A `started` event is recorded before the executor is called. A final
        `outcome` event is recorded after success or failure. If the executor
        raises, the failure is recorded and the original exception is re-raised.
        """
        started = await self._mark_execution_started(run_id, authorization_id)
        action = dict(started.action or {})
        try:
            result = executor(action)
            if inspect.isawaitable(result):
                result = await result
        except asyncio.CancelledError as exc:
            await self.record_outcome(
                run_id,
                authorization_id=authorization_id,
                outcome="unknown_execution_status",
                details={
                    "error_type": exc.__class__.__name__,
                    "error": "execution was cancelled; side effect status is unknown",
                },
            )
            raise
        except BaseException as exc:
            await self.record_outcome(
                run_id,
                authorization_id=authorization_id,
                outcome="failed",
                details={
                    "error_type": exc.__class__.__name__,
                    "error": str(exc),
                },
            )
            raise

        state = await self.record_outcome(
            run_id,
            authorization_id=authorization_id,
            outcome="executed",
        )
        return RuntimeExecutionResult(
            run_id=run_id,
            authorization_id=authorization_id,
            action_fingerprint=started.action_fingerprint or "",
            outcome="executed",
            result=result,
            state=state,
        )

    async def grant_approval(
        self,
        run_id: str,
        action: RuntimeAction | Mapping[str, Any],
        *,
        approver: str,
        approver_token: Optional[str] = None,
        reason: str = "approved by trusted authority",
        ttl_seconds: Optional[int] = 300,
        expires_at: Optional[float] = None,
    ) -> RuntimeApproval:
        """Grant a short-lived approval for one exact canonical action."""
        proposed = action if isinstance(action, RuntimeAction) else RuntimeAction.from_mapping(action)
        if not isinstance(approver, str) or not approver:
            raise ValueError("approver must be a non-empty string")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("approval reason must be a non-empty string")
        if expires_at is None:
            if ttl_seconds is None or ttl_seconds <= 0:
                raise ValueError("approval ttl_seconds must be positive")
            expires_at = self.clock() + ttl_seconds
        holder: Dict[str, RuntimeApproval] = {}

        def update(state: RuntimeState) -> RuntimeState:
            contract = self.store.contract_for(state.run_id)
            now = self.clock()
            precheck = _precheck_state(state, proposed, contract, now)
            if precheck is not None:
                raise ValueError(precheck[1].reason)
            if not _approval_required(proposed, contract):
                raise ValueError("approval is not required for this action")
            approval_error = _approval_authority_error(proposed, contract, approver, approver_token)
            if approval_error is not None:
                raise ValueError(approval_error[1])
            trajectory_actions = state.action_records() + [proposed.to_trajectory_record()]
            trajectory = evaluate_trajectory(
                trajectory_actions,
                self.evaluator,
                contract=contract.to_trajectory_contract(),
            )
            if trajectory.get("verdict") != "allow":
                raise ValueError(_reason_from_trajectory(trajectory))
            approval_id = _new_approval_id()
            event = RuntimeEvent(
                sequence=len(state.events),
                event_type="approval",
                action=proposed.to_trajectory_record(),
                verdict="allow",
                decision="APPROVED",
                authorized=True,
                reason=reason,
                action_fingerprint=proposed.fingerprint,
                timestamp=now,
                policy_fingerprint=contract.policy_fingerprint,
                trajectory={"details": {"approver": approver, "expires_at": expires_at}},
                reason_code="APPROVAL_GRANTED",
                approval_id=approval_id,
            )
            holder["approval"] = RuntimeApproval(
                run_id=state.run_id,
                approval_id=approval_id,
                action_fingerprint=proposed.fingerprint,
                policy_fingerprint=contract.policy_fingerprint,
                approver=approver,
                expires_at=expires_at,
                sequence=event.sequence,
                reason=reason,
            )
            return RuntimeState(
                run_id=state.run_id,
                status=state.status,
                contract=state.contract,
                created_at=state.created_at,
                expires_at=state.expires_at,
                version=state.version + 1,
                events=state.events + (event,),
                last_reason=reason,
            )

        await self.store.update(run_id, update)
        return holder["approval"]

    async def revoke_approval(
        self,
        run_id: str,
        approval_id: str,
        reason: str,
        *,
        evidence: Optional[Mapping[str, Any]] = None,
    ) -> RuntimeState:
        if not isinstance(approval_id, str) or not approval_id:
            raise ValueError("approval_id must be a non-empty string")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("approval revocation reason must be a non-empty string")

        def update(state: RuntimeState) -> RuntimeState:
            event = RuntimeEvent(
                sequence=len(state.events),
                event_type="approval_revocation",
                action=None,
                verdict="block",
                decision="REVOKED",
                authorized=False,
                reason=reason,
                action_fingerprint=None,
                timestamp=self.clock(),
                policy_fingerprint=state.contract.get("policy_fingerprint"),
                trajectory={"details": dict(evidence or {})} if evidence else None,
                reason_code="APPROVAL_REVOKED",
                approval_id=approval_id,
            )
            return RuntimeState(
                run_id=state.run_id,
                status=state.status,
                contract=state.contract,
                created_at=state.created_at,
                expires_at=state.expires_at,
                version=state.version + 1,
                events=state.events + (event,),
                last_reason=reason,
            )

        return await self.store.update(run_id, update)

    async def reconcile_execution(
        self,
        run_id: str,
        *,
        authorization_id: str,
        action_fingerprint: str,
        outcome: str,
        reconciler: str,
        reconciler_token: Optional[str] = None,
        evidence: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> RuntimeState:
        """Record trusted reconciliation for an unresolved or uncertain execution.

        This does not retry the operation or reuse the authorization. It only
        records external evidence supplied by a trusted integration/operator.
        """
        if outcome not in {"executed", "failed", "skipped", "unknown_execution_status"}:
            raise ValueError("reconciliation outcome must be executed, failed, skipped, or unknown_execution_status")
        if not isinstance(authorization_id, str) or not authorization_id:
            raise ValueError("authorization_id must be a non-empty string")
        if not isinstance(action_fingerprint, str) or not action_fingerprint:
            raise ValueError("action_fingerprint must be a non-empty string")
        if not isinstance(reconciler, str) or not reconciler:
            raise ValueError("reconciler must be a non-empty string")

        def update(state: RuntimeState) -> RuntimeState:
            contract = self.store.contract_for(state.run_id)
            authority_error = _reconciliation_authority_error(contract, reconciler, reconciler_token)
            if authority_error is not None:
                raise ValueError(authority_error[1])
            started = _started_event(state, authorization_id)
            if started is None:
                raise ValueError("execution attempt was not started")
            if started.action_fingerprint != action_fingerprint:
                raise ValueError("reconciliation action fingerprint does not match execution attempt")
            if _authorization_has_reconciliation(state, authorization_id):
                raise ValueError("execution attempt already has a terminal outcome")
            details = {
                "reconciler": reconciler,
                "evidence": dict(evidence or {}),
                "idempotency_key": idempotency_key,
            }
            event = RuntimeEvent(
                sequence=len(state.events),
                event_type="reconciliation",
                action=started.action,
                verdict=started.verdict,
                decision="RECONCILED",
                authorized=True,
                reason="execution outcome reconciled from trusted evidence",
                action_fingerprint=started.action_fingerprint,
                timestamp=self.clock(),
                authorization_id=authorization_id,
                policy_fingerprint=started.policy_fingerprint,
                trajectory={"details": details},
                outcome=outcome,
                reason_code="EXECUTION_RECONCILED",
                approval_id=started.approval_id,
            )
            next_status = state.status
            if state.status == "blocked" and state.last_reason in {
                "run has unresolved execution",
                "run has uncertain execution status",
            }:
                next_status = "active"
            return RuntimeState(
                run_id=state.run_id,
                status=next_status,
                contract=state.contract,
                created_at=state.created_at,
                expires_at=state.expires_at,
                version=state.version + 1,
                events=state.events + (event,),
                last_reason=event.reason,
            )

        return await self.store.update(run_id, update)

    async def execute_approved(
        self,
        run_id: str,
        action: RuntimeAction | Mapping[str, Any],
        *,
        approval_id: str,
        executor: Executor,
    ) -> RuntimeExecutionResult:
        """Consume an approval and start execution in one trusted transition."""
        proposed = action if isinstance(action, RuntimeAction) else RuntimeAction.from_mapping(action)
        started = await self._mark_approved_execution_started(run_id, proposed, approval_id)
        authorization_id = started.authorization_id or ""
        action_record = dict(started.action or {})
        try:
            result = executor(action_record)
            if inspect.isawaitable(result):
                result = await result
        except asyncio.CancelledError as exc:
            await self.record_outcome(
                run_id,
                authorization_id=authorization_id,
                outcome="unknown_execution_status",
                details={
                    "error_type": exc.__class__.__name__,
                    "error": "execution was cancelled; side effect status is unknown",
                },
            )
            raise
        except BaseException as exc:
            await self.record_outcome(
                run_id,
                authorization_id=authorization_id,
                outcome="failed",
                details={
                    "error_type": exc.__class__.__name__,
                    "error": str(exc),
                },
            )
            raise

        state = await self.record_outcome(
            run_id,
            authorization_id=authorization_id,
            outcome="executed",
        )
        return RuntimeExecutionResult(
            run_id=run_id,
            authorization_id=authorization_id,
            action_fingerprint=started.action_fingerprint or "",
            outcome="executed",
            result=result,
            state=state,
        )

    async def _mark_execution_started(self, run_id: str, authorization_id: str) -> RuntimeEvent:
        holder: Dict[str, RuntimeEvent] = {}

        def update(state: RuntimeState) -> RuntimeState:
            now = self.clock()
            if state.status != "active":
                raise ValueError(f"run is {state.status}")
            if state.expires_at is not None and now >= state.expires_at:
                raise ValueError("run expired")
            matching = _matching_open_authorization(state, authorization_id=authorization_id, for_execution=True)
            if matching is None:
                raise ValueError("authorization is not valid or has already been consumed")
            if _authorization_started(state, authorization_id):
                raise ValueError("authorization has already been consumed")
            contract = self.store.contract_for(state.run_id)
            if matching.policy_fingerprint != contract.policy_fingerprint:
                raise ValueError("authorization policy context changed")
            event = RuntimeEvent(
                sequence=len(state.events),
                event_type="started",
                action=matching.action,
                verdict=matching.verdict,
                decision=matching.decision,
                authorized=True,
                reason="execution started",
                action_fingerprint=matching.action_fingerprint,
                timestamp=now,
                authorization_id=authorization_id,
                policy_fingerprint=matching.policy_fingerprint,
                reason_code="EXECUTION_STARTED",
            )
            holder["event"] = event
            return RuntimeState(
                run_id=state.run_id,
                status=state.status,
                contract=state.contract,
                created_at=state.created_at,
                expires_at=state.expires_at,
                version=state.version + 1,
                events=state.events + (event,),
                last_reason=state.last_reason,
            )

        await self.store.update(run_id, update)
        return holder["event"]

    async def _mark_approved_execution_started(
        self,
        run_id: str,
        action: RuntimeAction,
        approval_id: str,
    ) -> RuntimeEvent:
        holder: Dict[str, RuntimeEvent] = {}

        def update(state: RuntimeState) -> RuntimeState:
            now = self.clock()
            contract = self.store.contract_for(state.run_id)
            precheck = _precheck_state(state, action, contract, now)
            if precheck is not None:
                raise ValueError(precheck[1].reason)
            if not _approval_required(action, contract):
                raise ValueError("approval is not required for this action")
            trajectory_actions = state.action_records() + [action.to_trajectory_record()]
            trajectory = evaluate_trajectory(
                trajectory_actions,
                self.evaluator,
                contract=contract.to_trajectory_contract(),
            )
            if trajectory.get("verdict") != "allow":
                raise ValueError(_reason_from_trajectory(trajectory))
            approval = _matching_open_approval(
                state,
                approval_id=approval_id,
                action_fingerprint=action.fingerprint,
                policy_fingerprint=contract.policy_fingerprint,
                now=now,
            )
            if approval is None:
                raise ValueError("approval is not valid or has already been consumed")
            authorization_id = _new_authorization_id()
            consume_event = RuntimeEvent(
                sequence=len(state.events),
                event_type="approval_consumed",
                action=approval.action,
                verdict="allow",
                decision="APPROVAL_CONSUMED",
                authorized=True,
                reason="approval consumed for execution",
                action_fingerprint=approval.action_fingerprint,
                timestamp=now,
                policy_fingerprint=contract.policy_fingerprint,
                reason_code="APPROVAL_CONSUMED",
                approval_id=approval.approval_id,
            )
            proposal_event = RuntimeEvent(
                sequence=len(state.events) + 1,
                event_type="proposal",
                action=action.to_trajectory_record(),
                verdict=str(trajectory.get("verdict")),
                decision=str(trajectory.get("decision")),
                authorized=True,
                reason=_reason_from_trajectory(trajectory),
                action_fingerprint=action.fingerprint,
                timestamp=now,
                authorization_id=authorization_id,
                policy_fingerprint=contract.policy_fingerprint,
                trajectory=trajectory,
                reason_code="AUTHORIZED",
                approval_id=approval.approval_id,
            )
            started_event = RuntimeEvent(
                sequence=len(state.events) + 2,
                event_type="started",
                action=action.to_trajectory_record(),
                verdict=proposal_event.verdict,
                decision=proposal_event.decision,
                authorized=True,
                reason="execution started",
                action_fingerprint=action.fingerprint,
                timestamp=now,
                authorization_id=authorization_id,
                policy_fingerprint=contract.policy_fingerprint,
                reason_code="EXECUTION_STARTED",
                approval_id=approval.approval_id,
            )
            holder["event"] = started_event
            return RuntimeState(
                run_id=state.run_id,
                status=state.status,
                contract=state.contract,
                created_at=state.created_at,
                expires_at=state.expires_at,
                version=state.version + 3,
                events=state.events + (consume_event, proposal_event, started_event),
                last_reason=state.last_reason,
            )

        await self.store.update(run_id, update)
        return holder["event"]

    async def suspend_run(
        self,
        run_id: str,
        reason: str,
        *,
        evidence: Optional[Mapping[str, Any]] = None,
    ) -> RuntimeState:
        """Suspend a run so no new supported execution can start."""
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("suspension reason must be a non-empty string")

        def update(state: RuntimeState) -> RuntimeState:
            event = RuntimeEvent(
                sequence=len(state.events),
                event_type="suspension",
                action=None,
                verdict="block",
                decision="BLOCK",
                authorized=False,
                reason=reason,
                action_fingerprint=None,
                timestamp=self.clock(),
                policy_fingerprint=state.contract.get("policy_fingerprint"),
                trajectory={"details": dict(evidence or {})} if evidence else None,
                reason_code="RUN_SUSPENDED",
            )
            return RuntimeState(
                run_id=state.run_id,
                status="suspended",
                contract=state.contract,
                created_at=state.created_at,
                expires_at=state.expires_at,
                version=state.version + 1,
                events=state.events + (event,),
                last_reason=reason,
            )

        return await self.store.update(run_id, update)

    async def resume_run(
        self,
        run_id: str,
        reason: str,
        *,
        evidence: Optional[Mapping[str, Any]] = None,
    ) -> RuntimeState:
        """Explicitly recover a suspended run.

        Resume does not erase prior uncertainty. If the run has unresolved or
        unknown execution state, normal pre-execution checks still block the next
        proposal until a trusted reconciliation path records a safe outcome.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("resume reason must be a non-empty string")

        def update(state: RuntimeState) -> RuntimeState:
            if state.status != "suspended":
                raise ValueError(f"run is {state.status}")
            event = RuntimeEvent(
                sequence=len(state.events),
                event_type="resume",
                action=None,
                verdict="allow",
                decision="ALLOW",
                authorized=False,
                reason=reason,
                action_fingerprint=None,
                timestamp=self.clock(),
                policy_fingerprint=state.contract.get("policy_fingerprint"),
                trajectory={"details": dict(evidence or {})} if evidence else None,
                reason_code="RUN_RESUMED",
            )
            return RuntimeState(
                run_id=state.run_id,
                status="active",
                contract=state.contract,
                created_at=state.created_at,
                expires_at=state.expires_at,
                version=state.version + 1,
                events=state.events + (event,),
                last_reason=reason,
            )

        return await self.store.update(run_id, update)

    async def revoke_authorizations(
        self,
        run_id: str,
        reason: str,
        *,
        authorization_id: Optional[str] = None,
        action_fingerprint: Optional[str] = None,
        evidence: Optional[Mapping[str, Any]] = None,
    ) -> RuntimeState:
        """Revoke outstanding authorizations for a run.

        With no authorization_id or action_fingerprint, all currently
        outstanding authorizations issued before the revocation event are no
        longer executable through execute_authorized.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("revocation reason must be a non-empty string")

        def update(state: RuntimeState) -> RuntimeState:
            event = RuntimeEvent(
                sequence=len(state.events),
                event_type="revocation",
                action=None,
                verdict="block",
                decision="BLOCK",
                authorized=False,
                reason=reason,
                action_fingerprint=action_fingerprint,
                timestamp=self.clock(),
                authorization_id=authorization_id,
                policy_fingerprint=state.contract.get("policy_fingerprint"),
                trajectory={"details": dict(evidence or {})} if evidence else None,
                reason_code="AUTHORIZATION_REVOKED",
            )
            return RuntimeState(
                run_id=state.run_id,
                status=state.status,
                contract=state.contract,
                created_at=state.created_at,
                expires_at=state.expires_at,
                version=state.version + 1,
                events=state.events + (event,),
                last_reason=reason,
            )

        return await self.store.update(run_id, update)

    async def cancel_run(self, run_id: str, reason: str = "cancelled by caller") -> RuntimeState:
        """Cancel a run locally."""
        def update(state: RuntimeState) -> RuntimeState:
            event = RuntimeEvent(
                sequence=len(state.events),
                event_type="cancel",
                action=None,
                verdict="block",
                decision="BLOCK",
                authorized=False,
                reason=reason,
                action_fingerprint=None,
                timestamp=self.clock(),
                policy_fingerprint=state.contract.get("policy_fingerprint"),
                reason_code="RUN_CANCELLED",
            )
            return RuntimeState(
                run_id=state.run_id,
                status="cancelled",
                contract=state.contract,
                created_at=state.created_at,
                expires_at=state.expires_at,
                version=state.version + 1,
                events=state.events + (event,),
                last_reason=reason,
            )

        return await self.store.update(run_id, update)

    async def read_run(self, run_id: str) -> RuntimeState:
        return await self.store.read(run_id)


class RuntimeToolExecutor:
    """First-party integration wrapper for one trusted tool execution path.

    The wrapper is intentionally narrow: it does not run shell commands itself.
    A trusted host supplies the executor callable. This class binds the public
    integration flow so denied, malformed, forged, stale, or replayed actions do
    not reach that executor through this path.
    """

    def __init__(
        self,
        gate: RuntimeGate,
        *,
        run_id: str,
        executor: Executor,
        actor: Optional[str] = None,
        delegated_by: Optional[str] = None,
        tool_name: Optional[str] = None,
        actor_token: Optional[str] = None,
        principal: Optional[str] = None,
        principal_token: Optional[str] = None,
        capability_id: Optional[str] = None,
        action_type: Optional[str] = None,
        target_resource: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
    ) -> None:
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.gate = gate
        self.run_id = run_id
        self.executor = executor
        self.actor = actor
        self.delegated_by = delegated_by
        self.tool_name = tool_name
        self.actor_token = actor_token
        self.principal = principal
        self.principal_token = principal_token
        self.capability_id = capability_id
        self.action_type = action_type
        self.target_resource = target_resource
        self.timeout_seconds = timeout_seconds

    async def execute(
        self,
        action: RuntimeAction | Mapping[str, Any] | str,
        *,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        approval_id: Optional[str] = None,
    ) -> RuntimeToolCallResult:
        """Authorize and execute one proposed action through this integration."""
        proposed = self._runtime_action(action, request_id=request_id, metadata=metadata)
        if approval_id is not None:
            execution = self.gate.execute_approved(
                self.run_id,
                proposed,
                approval_id=approval_id,
                executor=self.executor,
            )
            if self.timeout_seconds is not None:
                execution = asyncio.wait_for(execution, timeout=self.timeout_seconds)
            result = await execution
            decision = _decision_from_execution_state(self.run_id, result)
            return RuntimeToolCallResult(decision=decision, execution=result)

        decision = await self.gate.propose_action(self.run_id, proposed)
        if not decision.authorized or not decision.authorization_id:
            return RuntimeToolCallResult(decision=decision)

        execution = self.gate.execute_authorized(
            self.run_id,
            authorization_id=decision.authorization_id,
            executor=self.executor,
        )
        if self.timeout_seconds is not None:
            execution = asyncio.wait_for(execution, timeout=self.timeout_seconds)
        result = await execution
        return RuntimeToolCallResult(decision=decision, execution=result)

    def _runtime_action(
        self,
        action: RuntimeAction | Mapping[str, Any] | str,
        *,
        request_id: Optional[str],
        metadata: Optional[Mapping[str, Any]],
    ) -> RuntimeAction:
        if isinstance(action, RuntimeAction):
            if any(
                value is not None
                for value in (
                    self.actor,
                    self.delegated_by,
                    self.tool_name,
                    self.actor_token,
                    self.principal,
                    self.principal_token,
                    self.capability_id,
                    self.action_type,
                    self.target_resource,
                    request_id,
                    metadata,
                )
            ):
                raise ValueError("RuntimeAction cannot be combined with executor default metadata")
            return action

        if isinstance(action, str):
            payload: Dict[str, Any] = {"command": action}
        elif isinstance(action, Mapping):
            payload = dict(action)
        else:
            raise ValueError("runtime tool action must be a string or object")

        for field_name, value in (
            ("actor", self.actor),
            ("delegated_by", self.delegated_by),
            ("tool_name", self.tool_name),
            ("actor_token", self.actor_token),
            ("principal", self.principal),
            ("principal_token", self.principal_token),
            ("capability_id", self.capability_id),
            ("action_type", self.action_type),
            ("target_resource", self.target_resource),
            ("request_id", request_id),
        ):
            if value is not None:
                if field_name in payload and payload[field_name] != value:
                    raise ValueError(f"action {field_name} conflicts with executor-bound metadata")
                payload[field_name] = value

        if metadata is not None:
            existing = payload.get("metadata")
            if existing is not None and existing != metadata:
                raise ValueError("action metadata conflicts with executor-bound metadata")
            payload["metadata"] = dict(metadata)

        return RuntimeAction.from_mapping(payload)


def _precheck_state(
    state: RuntimeState,
    action: RuntimeAction,
    contract: RunContract,
    now: float,
) -> Optional[tuple[RuntimeEvent, RuntimeDecision]]:
    reason = None
    reason_code = None
    status = state.status
    verdict = "block"
    decision = "BLOCK"

    if state.status != "active":
        reason = f"run is {state.status}"
        reason_code = "RUN_NOT_ACTIVE"
    elif state.expires_at is not None and now >= state.expires_at:
        reason = "run expired"
        reason_code = "RUN_EXPIRED"
        status = "expired"
    elif contract.max_actions is not None and len(state.action_records()) >= contract.max_actions:
        reason = "run exceeded max_actions"
        reason_code = "RUN_ACTION_LIMIT_EXCEEDED"
        status = "blocked"
    elif _has_uncertain_execution(state):
        reason = "run has uncertain execution status"
        reason_code = "EXECUTION_OUTCOME_UNKNOWN"
        status = "blocked"
    elif _has_unresolved_execution(state):
        reason = "run has unresolved execution"
        reason_code = "EXECUTION_UNRESOLVED"
        status = "blocked"
    elif not _actor_token_valid(action, contract):
        reason = "actor token is missing or invalid"
        reason_code = "ACTOR_TOKEN_INVALID"
        status = "blocked"
    else:
        authority_error = _authority_error(action, contract, now)
        if authority_error is not None:
            reason_code, reason = authority_error
            status = "blocked"

    if reason is None:
        return None

    event = RuntimeEvent(
        sequence=len(state.events),
        event_type="proposal",
        action=action.to_trajectory_record(),
        verdict=verdict,
        decision=decision,
        authorized=False,
        reason=reason,
        action_fingerprint=action.fingerprint,
        timestamp=now,
        authorization_id=None,
        policy_fingerprint=contract.policy_fingerprint,
        trajectory=None,
        reason_code=reason_code,
    )
    runtime_decision = RuntimeDecision(
        run_id=state.run_id,
        run_status=status,
        authorized=False,
        verdict=verdict,
        decision=decision,
        reason=reason,
        sequence=event.sequence,
        state_version=state.version + 1,
        action_fingerprint=action.fingerprint,
        trajectory=None,
        authorization_id=None,
        policy_fingerprint=contract.policy_fingerprint,
        recovery=_recovery_recommendation(state, event),
        reason_code=reason_code,
    )
    return event, runtime_decision


def _new_authorization_id() -> str:
    return secrets.token_urlsafe(32)


def _new_approval_id() -> str:
    return secrets.token_urlsafe(32)


def _matching_open_authorization(
    state: RuntimeState,
    *,
    action_fingerprint: Optional[str] = None,
    authorization_id: Optional[str] = None,
    for_execution: bool = False,
) -> Optional[RuntimeEvent]:
    completed = {
        event.authorization_id
        for event in state.events
        if event.event_type == "outcome" and event.authorization_id
    }
    for event in reversed(state.events):
        if event.event_type not in {"proposal", "started"}:
            continue
        if not event.authorized:
            continue
        if event.authorization_id in completed:
            continue
        if for_execution and _authorization_revoked(state, event):
            continue
        if for_execution and _authorization_invalidated_by_reconciliation(state, event):
            continue
        if authorization_id is not None and event.authorization_id != authorization_id:
            continue
        if action_fingerprint is not None and event.action_fingerprint != action_fingerprint:
            continue
        return event
    return None


def _matching_open_approval(
    state: RuntimeState,
    *,
    approval_id: str,
    action_fingerprint: str,
    policy_fingerprint: str,
    now: float,
) -> Optional[RuntimeEvent]:
    consumed = {
        event.approval_id
        for event in state.events
        if event.event_type == "approval_consumed" and event.approval_id
    }
    revoked = {
        event.approval_id
        for event in state.events
        if event.event_type == "approval_revocation" and event.approval_id
    }
    for event in reversed(state.events):
        if event.event_type != "approval":
            continue
        if event.approval_id != approval_id:
            continue
        if event.approval_id in consumed or event.approval_id in revoked:
            return None
        if event.action_fingerprint != action_fingerprint:
            return None
        if event.policy_fingerprint != policy_fingerprint:
            return None
        details = (event.trajectory or {}).get("details", {}) if isinstance(event.trajectory, Mapping) else {}
        expires_at = details.get("expires_at") if isinstance(details, Mapping) else None
        if expires_at is None:
            return None
        if float(expires_at) <= now:
            return None
        return event
    return None


def _authorization_started(state: RuntimeState, authorization_id: str) -> bool:
    return any(
        event.event_type == "started" and event.authorization_id == authorization_id
        for event in state.events
    )


def _authorization_revoked(state: RuntimeState, authorization: RuntimeEvent) -> bool:
    return any(
        event.event_type == "revocation"
        and event.sequence > authorization.sequence
        and (
            event.authorization_id is None
            or event.authorization_id == authorization.authorization_id
        )
        and (
            event.action_fingerprint is None
            or event.action_fingerprint == authorization.action_fingerprint
        )
        for event in state.events
    )


def _authorization_invalidated_by_reconciliation(state: RuntimeState, authorization: RuntimeEvent) -> bool:
    return any(
        event.event_type == "reconciliation"
        and event.sequence > authorization.sequence
        and event.authorization_id != authorization.authorization_id
        for event in state.events
    )


def _started_event(state: RuntimeState, authorization_id: str) -> Optional[RuntimeEvent]:
    for event in reversed(state.events):
        if event.event_type == "started" and event.authorization_id == authorization_id:
            return event
    return None


def _authorization_has_terminal_event(
    state: RuntimeState,
    authorization_id: str,
    *,
    include_reconciliation: bool = False,
) -> bool:
    terminal_types = {"outcome"}
    if include_reconciliation:
        terminal_types.add("reconciliation")
    return any(
        event.event_type in terminal_types and event.authorization_id == authorization_id
        for event in state.events
    )


def _authorization_has_reconciliation(state: RuntimeState, authorization_id: str) -> bool:
    return any(
        event.event_type == "reconciliation" and event.authorization_id == authorization_id
        for event in state.events
    )


def _has_unresolved_execution(state: RuntimeState) -> bool:
    started = {
        event.authorization_id
        for event in state.events
        if event.event_type == "started" and event.authorization_id
    }
    completed = {
        event.authorization_id
        for event in state.events
        if event.event_type in {"outcome", "reconciliation"} and event.authorization_id
    }
    return bool(started - completed)


def _has_uncertain_execution(state: RuntimeState) -> bool:
    reconciled = {
        event.authorization_id
        for event in state.events
        if event.event_type == "reconciliation" and event.authorization_id
    }
    return any(
        event.event_type == "outcome"
        and event.outcome == "unknown_execution_status"
        and event.authorization_id not in reconciled
        for event in state.events
    )


def _actor_token_valid(action: RuntimeAction, contract: RunContract) -> bool:
    if not contract.actor_tokens:
        return True
    if not action.actor:
        return False
    expected = contract.actor_tokens.get(action.actor)
    if expected is None:
        return False
    if action.actor_token is None:
        return False
    return hmac.compare_digest(expected, action.actor_token)


def _authority_error(action: RuntimeAction, contract: RunContract, now: float) -> Optional[tuple[str, str]]:
    if contract.principal_tokens:
        if not action.principal:
            return "PRINCIPAL_MISSING", "principal is required"
        expected = contract.principal_tokens.get(action.principal)
        if expected is None or action.principal_token is None:
            return "PRINCIPAL_TOKEN_INVALID", "principal token is missing or invalid"
        if not hmac.compare_digest(expected, action.principal_token):
            return "PRINCIPAL_TOKEN_INVALID", "principal token is missing or invalid"

    if not contract.capabilities:
        return None
    if not action.capability_id:
        return "CAPABILITY_MISSING", "capability is required"
    if not action.principal:
        return "PRINCIPAL_MISSING", "principal is required for capability validation"

    grant = next(
        (capability for capability in contract.capabilities if capability.capability_id == action.capability_id),
        None,
    )
    if grant is None:
        return "CAPABILITY_UNKNOWN", "capability is unknown"
    if grant.principal != action.principal:
        return "CAPABILITY_PRINCIPAL_MISMATCH", "capability does not belong to principal"
    if grant.expires_at is not None and now >= grant.expires_at:
        return "CAPABILITY_EXPIRED", "capability expired"
    if grant.action_types and action.action_type not in grant.action_types:
        return "CAPABILITY_ACTION_SCOPE_MISMATCH", "capability does not permit action type"
    if grant.actors and (action.actor is None or action.actor not in grant.actors):
        return "CAPABILITY_ACTOR_SCOPE_MISMATCH", "capability does not permit actor"
    if grant.target_resources:
        if not action.target_resource:
            return "CAPABILITY_TARGET_SCOPE_MISMATCH", "capability requires a target resource"
        if not any(_target_matches(scope, action.target_resource) for scope in grant.target_resources):
            return "CAPABILITY_TARGET_SCOPE_MISMATCH", "capability does not permit target resource"
    return None


def _target_matches(scope: str, target: str) -> bool:
    if scope.endswith("*"):
        return target.startswith(scope[:-1])
    return target == scope


def _approval_required(action: RuntimeAction, contract: RunContract) -> bool:
    if contract.approval_required_action_types and action.action_type in contract.approval_required_action_types:
        return True
    if contract.approval_required_targets and action.target_resource:
        return any(_target_matches(scope, action.target_resource) for scope in contract.approval_required_targets)
    return False


def _approval_authority_error(
    action: RuntimeAction,
    contract: RunContract,
    approver: str,
    approver_token: Optional[str],
) -> Optional[tuple[str, str]]:
    if not contract.allow_self_approval and action.principal and action.principal == approver:
        return "APPROVAL_SELF_DENIED", "principal cannot approve its own action"
    if not contract.approver_tokens:
        return None
    expected = contract.approver_tokens.get(approver)
    if expected is None or approver_token is None:
        return "APPROVER_TOKEN_INVALID", "approver token is missing or invalid"
    if not hmac.compare_digest(expected, approver_token):
        return "APPROVER_TOKEN_INVALID", "approver token is missing or invalid"
    return None


def _reconciliation_authority_error(
    contract: RunContract,
    reconciler: str,
    reconciler_token: Optional[str],
) -> Optional[tuple[str, str]]:
    if not contract.reconciler_tokens:
        return None
    expected = contract.reconciler_tokens.get(reconciler)
    if expected is None or reconciler_token is None:
        return "RECONCILER_TOKEN_INVALID", "reconciler token is missing or invalid"
    if not hmac.compare_digest(expected, reconciler_token):
        return "RECONCILER_TOKEN_INVALID", "reconciler token is missing or invalid"
    return None


def _decision_from_execution_state(run_id: str, execution: RuntimeExecutionResult) -> RuntimeDecision:
    proposal = next(
        (
            event
            for event in reversed(execution.state.events)
            if event.event_type == "proposal" and event.authorization_id == execution.authorization_id
        ),
        None,
    )
    if proposal is None or proposal.action_fingerprint is None:
        raise RuntimeIntegrityError("approved execution missing proposal event")
    return RuntimeDecision(
        run_id=run_id,
        run_status=execution.state.status,
        authorized=True,
        verdict=proposal.verdict,
        decision=proposal.decision,
        reason=proposal.reason,
        sequence=proposal.sequence,
        state_version=execution.state.version,
        action_fingerprint=proposal.action_fingerprint,
        trajectory=proposal.trajectory,
        authorization_id=proposal.authorization_id,
        policy_fingerprint=proposal.policy_fingerprint,
        reason_code=proposal.reason_code,
        approval_id=proposal.approval_id,
    )


def _reason_from_trajectory(trajectory: Mapping[str, Any]) -> str:
    findings = trajectory.get("trajectory_findings") or []
    if findings:
        return str(findings[0].get("reason") or findings[0].get("id"))
    if trajectory.get("verdict") == "allow":
        return "runtime action authorized"
    if trajectory.get("verdict") == "unknown":
        return "runtime action is unknown and not executable by default"
    if trajectory.get("verdict") == "error":
        return str(trajectory.get("error") or "runtime trajectory evaluation failed")
    return f"runtime trajectory verdict is {trajectory.get('verdict')}"


def _reason_code_from_trajectory(trajectory: Mapping[str, Any]) -> str:
    if trajectory.get("verdict") == "unknown":
        return "POLICY_UNKNOWN"
    if trajectory.get("verdict") == "error":
        return "POLICY_EVALUATION_ERROR"
    finding = _first_finding_id(trajectory)
    if finding:
        return str(finding).upper()
    return "ACTION_NOT_PERMITTED"


def _recovery_recommendation(state: RuntimeState, event: RuntimeEvent) -> Dict[str, Any]:
    return {
        "recommended_action": "stop_current_execution_path",
        "automatic_respawn": False,
        "reason": event.reason,
        "new_run_required": True,
        "evidence": {
            "run_id": state.run_id,
            "sequence": event.sequence,
            "action_fingerprint": event.action_fingerprint,
            "finding": _first_finding_id(event.trajectory),
            "reason_code": event.reason_code,
        },
    }


def _first_finding_id(trajectory: Optional[Mapping[str, Any]]) -> Optional[str]:
    if not trajectory:
        return None
    findings = trajectory.get("trajectory_findings") or []
    if not findings:
        return None
    first = findings[0]
    return first.get("id") if isinstance(first, Mapping) else None


def _optional_string(value: Any, field: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value


def _string_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return value


def _optional_int(value: Any, field: str, default: Optional[int]) -> Optional[int]:
    if value is None:
        return default
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _optional_bool(value: Any, field: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _delegation_pairs(value: Any) -> list[tuple[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("allowed_delegations must be a list")
    pairs: list[tuple[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError(f"allowed_delegations[{index}] must be an object")
        source = item.get("from")
        target = item.get("to")
        if not isinstance(source, str) or not source:
            raise ValueError(f"allowed_delegations[{index}].from must be a non-empty string")
        if not isinstance(target, str) or not target:
            raise ValueError(f"allowed_delegations[{index}].to must be a non-empty string")
        pairs.append((source, target))
    return pairs


def _actor_tokens(value: Any) -> Mapping[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("actor_tokens must be an object")
    tokens: Dict[str, str] = {}
    for actor, token in value.items():
        if not isinstance(actor, str) or not actor:
            raise ValueError("actor_tokens keys must be non-empty strings")
        if not isinstance(token, str) or not token:
            raise ValueError(f"actor_tokens[{actor}] must be a non-empty string")
        tokens[actor] = token
    return tokens


def _principal_tokens(value: Any) -> Mapping[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("principal_tokens must be an object")
    tokens: Dict[str, str] = {}
    for principal, token in value.items():
        if not isinstance(principal, str) or not principal:
            raise ValueError("principal_tokens keys must be non-empty strings")
        if not isinstance(token, str) or not token:
            raise ValueError(f"principal_tokens[{principal}] must be a non-empty string")
        tokens[principal] = token
    return tokens


def _approver_tokens(value: Any) -> Mapping[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("approver_tokens must be an object")
    tokens: Dict[str, str] = {}
    for approver, token in value.items():
        if not isinstance(approver, str) or not approver:
            raise ValueError("approver_tokens keys must be non-empty strings")
        if not isinstance(token, str) or not token:
            raise ValueError(f"approver_tokens[{approver}] must be a non-empty string")
        tokens[approver] = token
    return tokens


def _reconciler_tokens(value: Any) -> Mapping[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("reconciler_tokens must be an object")
    tokens: Dict[str, str] = {}
    for reconciler, token in value.items():
        if not isinstance(reconciler, str) or not reconciler:
            raise ValueError("reconciler_tokens keys must be non-empty strings")
        if not isinstance(token, str) or not token:
            raise ValueError(f"reconciler_tokens[{reconciler}] must be a non-empty string")
        tokens[reconciler] = token
    return tokens


def _capability_grants(value: Any) -> list[CapabilityGrant]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("capabilities must be a list")
    grants = [CapabilityGrant.from_mapping(item) for item in value]
    seen: set[str] = set()
    for grant in grants:
        if grant.capability_id in seen:
            raise ValueError(f"duplicate capability id: {grant.capability_id}")
        seen.add(grant.capability_id)
    return grants


def _action_type(value: Any) -> str:
    if value is None:
        return "command"
    if not isinstance(value, str) or not value:
        raise ValueError("action_type must be a non-empty string")
    return value


def _sqlite_runtime_error(exc: sqlite3.OperationalError) -> RuntimeStoreError:
    message = str(exc).lower()
    if "locked" in message or "busy" in message:
        return RuntimeStoreBusy(f"runtime store busy: {exc}")
    if "unable to open" in message or "readonly" in message:
        return RuntimeStoreUnavailable(f"runtime store unavailable: {exc}")
    if "database disk image is malformed" in message or "file is not a database" in message:
        return RuntimeIntegrityError(f"runtime store integrity failure: {exc}")
    return RuntimeStoreUnavailable(f"runtime store unavailable: {exc}")


def _sqlite_tables(connection: sqlite3.Connection) -> set[str]:
    try:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    except sqlite3.DatabaseError as exc:
        raise RuntimeIntegrityError(f"runtime store catalog is invalid: {exc}") from exc
    return {str(row[0]) for row in rows}


def _metadata_value(connection: sqlite3.Connection, key: str) -> Optional[str]:
    if "runtime_metadata" not in _sqlite_tables(connection):
        return None
    row = connection.execute("SELECT value FROM runtime_metadata WHERE key = ?", (key,)).fetchone()
    return str(row[0]) if row is not None else None


def _parse_schema_version(value: Optional[str]) -> int:
    if value is None:
        raise RuntimeSchemaError("runtime metadata missing schema_version")
    try:
        version = int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeSchemaError("runtime schema_version is invalid") from exc
    if version <= 0:
        raise RuntimeSchemaError("runtime schema_version must be positive")
    return version


def _require_columns(connection: sqlite3.Connection, table_name: str, required: set[str]) -> None:
    try:
        rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    except sqlite3.DatabaseError as exc:
        raise RuntimeSchemaError(f"runtime table {table_name} is invalid: {exc}") from exc
    columns = {str(row[1]) for row in rows}
    missing = required - columns
    if missing:
        raise RuntimeSchemaError(f"runtime table {table_name} missing columns: {sorted(missing)}")


def _metadata(value: Any) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("metadata must be an object")
    return _json_data(dict(value))


def _encode_state(state: RuntimeState) -> str:
    return json.dumps(state.to_dict(), sort_keys=True, separators=(",", ":"), default=str)


def _json_data(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str))


def _fingerprint_action_record(record: Mapping[str, Any]) -> str:
    encoded = json.dumps(_json_data(dict(record)), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_state_integrity(state: RuntimeState, contract: RunContract) -> None:
    if not isinstance(state.run_id, str) or not state.run_id:
        raise RuntimeIntegrityError("runtime state has invalid run_id")
    if state.status not in {"active", "blocked", "suspended", "cancelled", "expired"}:
        raise RuntimeIntegrityError("runtime state has invalid status")
    if not isinstance(state.version, int) or state.version < 0:
        raise RuntimeIntegrityError("runtime state has invalid version")
    if not isinstance(state.contract, Mapping):
        raise RuntimeIntegrityError("runtime state contract summary is invalid")
    if state.contract.get("policy_fingerprint") != contract.policy_fingerprint:
        raise RuntimeIntegrityError("runtime state contract fingerprint does not match private contract")
    if len(state.events) > state.version:
        raise RuntimeIntegrityError("runtime state version is behind event count")

    seen_authorizations: set[str] = set()
    started_authorizations: set[str] = set()
    completed_authorizations: set[str] = set()
    reconciled_authorizations: set[str] = set()
    approvals: set[str] = set()
    consumed_approvals: set[str] = set()
    revoked_approvals: set[str] = set()
    last_timestamp: Optional[float] = None

    for index, event in enumerate(state.events):
        if event.sequence != index:
            raise RuntimeIntegrityError("runtime event sequence is not contiguous")
        if not isinstance(event.event_type, str) or not event.event_type:
            raise RuntimeIntegrityError("runtime event has invalid event_type")
        if not isinstance(event.timestamp, (int, float)):
            raise RuntimeIntegrityError("runtime event has invalid timestamp")
        if last_timestamp is not None and float(event.timestamp) < last_timestamp:
            raise RuntimeIntegrityError("runtime event timestamps move backwards")
        last_timestamp = float(event.timestamp)
        if event.action is not None:
            if not isinstance(event.action, Mapping):
                raise RuntimeIntegrityError("runtime event action is invalid")
            if event.action_fingerprint != _fingerprint_action_record(event.action):
                raise RuntimeIntegrityError("runtime event action fingerprint mismatch")
        if event.event_type == "proposal":
            if event.authorized:
                if not event.authorization_id:
                    raise RuntimeIntegrityError("authorized proposal missing authorization_id")
                if event.authorization_id in seen_authorizations:
                    raise RuntimeIntegrityError("duplicate authorization_id")
                if event.policy_fingerprint != contract.policy_fingerprint:
                    # Historical proposals may have an older policy; they are safe
                    # because execution rechecks the current policy fingerprint.
                    pass
                seen_authorizations.add(event.authorization_id)
            continue
        elif event.event_type == "started":
            if not event.authorization_id or event.authorization_id not in seen_authorizations:
                raise RuntimeIntegrityError("started event references unknown authorization")
            if event.authorization_id in started_authorizations:
                raise RuntimeIntegrityError("duplicate started event for authorization")
            started_authorizations.add(event.authorization_id)
        elif event.event_type == "outcome":
            if not event.authorization_id or event.authorization_id not in seen_authorizations:
                raise RuntimeIntegrityError("outcome references unknown authorization")
            if event.authorization_id in completed_authorizations:
                raise RuntimeIntegrityError("duplicate outcome for authorization")
            if event.outcome not in {"executed", "failed", "skipped", "unknown_execution_status"}:
                raise RuntimeIntegrityError("outcome event has invalid outcome")
            completed_authorizations.add(event.authorization_id)
        elif event.event_type == "reconciliation":
            if not event.authorization_id or event.authorization_id not in seen_authorizations:
                raise RuntimeIntegrityError("reconciliation references unknown authorization")
            if event.authorization_id not in started_authorizations:
                raise RuntimeIntegrityError("reconciliation references execution that was not started")
            if event.authorization_id in reconciled_authorizations:
                raise RuntimeIntegrityError("duplicate reconciliation for authorization")
            if event.outcome not in {"executed", "failed", "skipped", "unknown_execution_status"}:
                raise RuntimeIntegrityError("reconciliation event has invalid outcome")
            if not isinstance((event.trajectory or {}).get("details", {}), Mapping):
                raise RuntimeIntegrityError("reconciliation evidence is invalid")
            reconciled_authorizations.add(event.authorization_id)
        elif event.event_type == "approval":
            if not event.approval_id:
                raise RuntimeIntegrityError("approval event missing approval_id")
            if event.approval_id in approvals:
                raise RuntimeIntegrityError("duplicate approval_id")
            approvals.add(event.approval_id)
        elif event.event_type == "approval_consumed":
            if not event.approval_id or event.approval_id not in approvals:
                raise RuntimeIntegrityError("approval consumption references unknown approval")
            if event.approval_id in consumed_approvals:
                raise RuntimeIntegrityError("duplicate approval consumption")
            consumed_approvals.add(event.approval_id)
        elif event.event_type == "approval_revocation":
            if not event.approval_id:
                raise RuntimeIntegrityError("approval revocation missing approval_id")
            revoked_approvals.add(event.approval_id)
        elif event.event_type in {"suspension", "resume", "revocation", "cancel"}:
            continue
        else:
            raise RuntimeIntegrityError(f"unknown runtime event type: {event.event_type}")

    if consumed_approvals & revoked_approvals:
        raise RuntimeIntegrityError("approval is both consumed and revoked")


def _decode_state(payload: str) -> RuntimeState:
    try:
        data = json.loads(payload)
        if not isinstance(data, Mapping):
            raise ValueError("runtime state must be an object")
        events = tuple(RuntimeEvent(**event) for event in data.get("events", []))
        return RuntimeState(
            run_id=data["run_id"],
            status=data["status"],
            contract=dict(data["contract"]),
            created_at=float(data["created_at"]),
            expires_at=data.get("expires_at"),
            version=int(data["version"]),
            events=events,
            last_reason=data.get("last_reason"),
        )
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise RuntimeInvalidRecordError(f"invalid runtime state record: {exc}") from exc


def _encode_contract(contract: RunContract) -> str:
    return json.dumps(asdict(contract), sort_keys=True, separators=(",", ":"), default=str)


def _decode_contract(payload: str) -> RunContract:
    try:
        data = json.loads(payload)
        if not isinstance(data, Mapping):
            raise ValueError("runtime contract must be an object")
        return RunContract(
            goal=data.get("goal"),
            allowed_scopes=tuple(data.get("allowed_scopes") or ()),
            forbidden_targets=tuple(data.get("forbidden_targets") or ()),
            allowed_outputs=tuple(data.get("allowed_outputs") or ()),
            allowed_actors=tuple(data.get("allowed_actors") or ()),
            forbidden_actors=tuple(data.get("forbidden_actors") or ()),
            allowed_delegations=tuple(
                (str(pair[0]), str(pair[1]))
                for pair in data.get("allowed_delegations") or ()
            ),
            require_actor=bool(data.get("require_actor", False)),
            max_blocked_attempts=int(data.get("max_blocked_attempts", 1)),
            max_unknown_actions=data.get("max_unknown_actions"),
            max_actions=data.get("max_actions"),
            ttl_seconds=data.get("ttl_seconds"),
            actor_tokens=dict(data.get("actor_tokens") or {}),
            principal_tokens=dict(data.get("principal_tokens") or {}),
            capabilities=tuple(
                CapabilityGrant(
                    capability_id=str(item["capability_id"]),
                    principal=str(item["principal"]),
                    action_types=tuple(item.get("action_types") or ()),
                    target_resources=tuple(item.get("target_resources") or ()),
                    actors=tuple(item.get("actors") or ()),
                    expires_at=item.get("expires_at"),
                )
                for item in data.get("capabilities") or ()
            ),
            approval_required_action_types=tuple(data.get("approval_required_action_types") or ()),
            approval_required_targets=tuple(data.get("approval_required_targets") or ()),
            approver_tokens=dict(data.get("approver_tokens") or {}),
            allow_self_approval=bool(data.get("allow_self_approval", False)),
            reconciler_tokens=dict(data.get("reconciler_tokens") or {}),
        )
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise RuntimeInvalidRecordError(f"invalid runtime contract record: {exc}") from exc
