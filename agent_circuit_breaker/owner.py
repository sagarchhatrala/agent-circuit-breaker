"""Owner service: protected resources, durable review, and a narrow agent socket.

Linux peer credentials (or macOS getpeereid) identify callers. Production mode
requires different owner and agent UIDs. A same-UID local development mode is
explicitly labeled and does not provide process isolation.
"""
from __future__ import annotations

import argparse
import asyncio
import ctypes
import errno
import fcntl
import hashlib
import hmac
import json
import os
import socket
import sqlite3
import struct
import sys
import uuid
from contextlib import closing
from pathlib import Path

from agent_circuit_breaker.effects import usage
from agent_circuit_breaker.integrations import atomic_write
from agent_circuit_breaker.operations import Operations
from agent_circuit_breaker.redaction import redact_record
from agent_circuit_breaker.workflow import MAX_BYTES, canonical, digest


def peer_uid(connection):
    if sys.platform.startswith("linux"):
        return struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
    if sys.platform == "darwin":
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if ctypes.CDLL(None, use_errno=True).getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise OSError("cannot identify Unix peer")
        return uid.value
    raise ValueError("owner isolation requires Linux or macOS peer credentials")


def request(path, payload):
    data = (canonical(payload) + "\n").encode()
    if len(data) > MAX_BYTES:
        raise ValueError("request exceeds limit")
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(45)
        connection.connect(str(path))
        connection.sendall(data)
        with connection.makefile("rb") as stream:
            response = stream.readline(MAX_BYTES + 1)
    if not response or len(response) > MAX_BYTES:
        raise ValueError("missing or oversized owner response")
    return json.loads(response)


def verify_bundle(bundle, key):
    if not isinstance(bundle, dict) or set(bundle) != {"payload", "signature", "algorithm"} or bundle["algorithm"] != "hmac-sha256":
        raise ValueError("invalid evidence bundle")
    if len(key) < 16:
        raise ValueError("evidence verification requires a protected key of at least 16 bytes")
    expected = hmac.new(key, canonical(bundle["payload"]).encode(), hashlib.sha256).hexdigest()
    if not isinstance(bundle["signature"], str) or not hmac.compare_digest(expected, bundle["signature"]):
        raise ValueError("evidence signature mismatch")
    return {"verified": True, "run_id": bundle["payload"]["run_id"], "events": len(bundle["payload"]["events"])}


class OwnerService:
    def __init__(self, workspace, state, configuration, agent_uid, *, development=False):
        if type(agent_uid) is not int or agent_uid < 0:
            raise ValueError("agent UID must be a nonnegative integer")
        if agent_uid == os.getuid() and not development:
            raise ValueError("agent and owner must use different OS identities; --development is only for local rehearsal")
        self.agent_uid, self.development = agent_uid, development
        self.state = Path(state).absolute()
        if self.state.is_symlink() or any(p.is_symlink() for p in self.state.parents):
            raise ValueError("state path must not contain symlinks")
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.state.stat().st_uid != os.getuid() or self.state.stat().st_mode & 0o077:
            raise ValueError("state must be owner-owned and private (0700)")
        self.lock = os.open(self.state / "owner.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.operations = Operations(Path(workspace), self.state, configuration)
            self.jobs_path = self.state / "requests.sqlite3"
            if self.jobs_path.is_symlink():
                raise ValueError("request store must not be a symlink")
            with closing(sqlite3.connect(self.jobs_path)) as db, db:
                db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result TEXT)")
                db.execute("CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, name TEXT NOT NULL, args TEXT NOT NULL, fingerprint TEXT NOT NULL, approval TEXT, status TEXT NOT NULL)")
            self.serial = asyncio.Lock()
        except BaseException:
            os.close(self.lock)
            self.lock = None
            raise

    def close(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None

    async def start(self):
        index = self.state / "current-run"
        if index.is_symlink():
            raise ValueError("run index must not be a symlink")
        run_id = index.read_text().strip() if index.exists() else None
        if index.exists() and not run_id:
            raise ValueError("empty durable run index")
        if run_id is None:
            with closing(sqlite3.connect(self.state / "runtime.sqlite3")) as db:
                if db.execute("SELECT COUNT(*) FROM runtime_runs").fetchone()[0]:
                    raise ValueError("run index missing; owner must inspect existing authority")
        await self.operations.start(run_id)
        if run_id is None:
            atomic_write(index, self.operations.run_id.encode())

    def catalog(self):
        return self.operations.catalog() + [
            {"name": "review_operation", "description": "Preview an operation and its exact resource/effects without executing it.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "arguments": {"type": "object"}}, "required": ["name", "arguments"], "additionalProperties": False}},
            {"name": "execute_review", "description": "Execute an exact operation only after the owner has approved its review ID.", "inputSchema": {"type": "object", "properties": {"review_id": {"type": "string"}}, "required": ["review_id"], "additionalProperties": False}},
        ]

    async def dispatch(self, payload, *, administrative=False):
        if not isinstance(payload, dict) or not isinstance(payload.get("method"), str):
            raise ValueError("invalid owner request")
        method = payload["method"]
        fields = {
            "status": set(), "tools": set(), "call": {"name", "arguments", "request_id"},
            "review": {"name", "arguments"}, "commit": {"review_id", "request_id"},
            "inspect": {"review_id"}, "approve": {"review_id", "fingerprint", "ttl_seconds"}, "reject": {"review_id"},
            "artifact": {"artifact_id"}, "declassify": {"artifact_id", "path", "labels", "sha256", "reason"},
            "reconcile": {"authorization_id", "action_fingerprint", "outcome", "evidence"}, "export": {"from_sequence", "limit"},
        }
        if method not in fields or set(payload) - fields[method] - {"method"}:
            raise ValueError("unexpected request fields")
        public = {"status", "tools", "call", "review", "commit"}
        if method not in public and not administrative:
            raise ValueError("operation requires the owner control socket")
        # One owner service serializes operations; RuntimeGate additionally owns
        # durable start/approval/budget transitions across processes and restarts.
        async with self.serial:
            if method == "status":
                state = await self.operations.gate.read_run(self.operations.run_id)
                return {"run_id": state.run_id, "status": state.status, "effects": usage(state),
                        "limits": self.operations.effect_limits, "owner_uid": os.getuid(), "agent_uid": self.agent_uid,
                        "isolation": "development: same identity may bypass protection" if self.development else "separate UID; mount/network policy must also be enforced"}
            if method == "tools":
                return {"tools": self.catalog()}
            if method == "review":
                return await self.operations.review(payload["name"], payload["arguments"])
            if method in {"call", "commit"}:
                return await self._once(payload)
            if method in {"inspect", "approve", "reject"}:
                return await self._review_control(payload)
            if method == "artifact":
                artifact = self.operations.provenance.get(payload["artifact_id"])
                data = self.operations.workspace.read(artifact["path"])
                if digest(data) != artifact["sha256"]:
                    raise ValueError("artifact changed")
                return {"artifact": artifact, "text": data.decode("utf-8", errors="replace")}
            if method == "declassify":
                return await self.operations.declassify(payload["artifact_id"], payload["path"], payload["labels"], payload["sha256"], payload["reason"], approver="owner-uid-" + str(os.getuid()))
            if method == "reconcile":
                state = await self.operations.gate.reconcile_execution(self.operations.run_id, authorization_id=payload["authorization_id"], action_fingerprint=payload["action_fingerprint"],
                    outcome=payload["outcome"], reconciler="owner-uid-" + str(os.getuid()), evidence=payload.get("evidence"))
                return {"status": state.status, "effects": usage(state)}
            if method == "export":
                state = await self.operations.gate.read_run(self.operations.run_id)
                start, limit = payload.get("from_sequence", 0), payload.get("limit", 25)
                if type(start) is not int or not 0 <= start <= len(state.events) or type(limit) is not int or not 1 <= limit <= 100:
                    raise ValueError("export requires a valid from_sequence and limit between 1 and 100")
                end = min(start + limit, len(state.events))
                data = {"schema_version": 1, "run_id": state.run_id, "policy_fingerprint": state.contract["policy_fingerprint"],
                        "state_version": state.version, "total_events": len(state.events), "from_sequence": start,
                        "next_sequence": end if end < len(state.events) else None,
                        "events": redact_record([event.to_dict() for event in state.events[start:end]]), "effects": usage(state)}
                return {"payload": data, "algorithm": "hmac-sha256", "signature": hmac.new(self.operations.provenance.key, canonical(data).encode(), hashlib.sha256).hexdigest()}
            raise ValueError("unsupported owner operation")

    async def _once(self, payload):
        request_id = payload.get("request_id")
        if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
            raise ValueError("unique request_id required")
        fingerprint = digest(canonical(payload).encode())
        with closing(sqlite3.connect(self.jobs_path)) as db, db:
            row = db.execute("SELECT fingerprint,result FROM jobs WHERE id=?", (request_id,)).fetchone()
            if row:
                if row[0] != fingerprint:
                    raise ValueError("request ID reused with different arguments")
                return json.loads(row[1]) if row[1] else {"decision": "ERROR", "executor_started": None, "reason": "request interrupted; inspect owner state before any retry", "outcome": "unknown_execution_status"}
            db.execute("INSERT INTO jobs VALUES (?,?,NULL)", (request_id, fingerprint))
        if payload["method"] == "commit":
            row = self._review(payload["review_id"])
            if row[5] != "approved" or not row[4]:
                result = {"decision": "BLOCK", "executor_started": False, "reason": "review has no active owner approval"}
            elif self.operations.prepare(row[1], json.loads(row[2])).fingerprint != row[3]:
                result = {"decision": "BLOCK", "executor_started": False, "reason": "operation changed after review; request a new review"}
            else:
                result = await self.operations.call(row[1], json.loads(row[2]), approval_id=row[4])
                with closing(sqlite3.connect(self.jobs_path)) as db, db:
                    db.execute("UPDATE reviews SET status='consumed' WHERE id=?", (row[0],))
        else:
            name, args = payload["name"], payload["arguments"]
            result = await self.operations.call(name, args)
            if result["decision"] == "PENDING_APPROVAL":
                review_id = uuid.uuid4().hex
                action = self.operations.prepare(name, args)
                with closing(sqlite3.connect(self.jobs_path)) as db, db:
                    db.execute("INSERT INTO reviews VALUES (?,?,?,?,NULL,'pending')", (review_id, name, canonical(args), action.fingerprint))
                result.update({"review_id": review_id, "review": await self.operations.review(name, args)})
        with closing(sqlite3.connect(self.jobs_path)) as db, db:
            db.execute("UPDATE jobs SET result=? WHERE id=?", (canonical(result), request_id))
        return result

    def _review(self, review_id):
        with closing(sqlite3.connect(self.jobs_path)) as db:
            row = db.execute("SELECT id,name,args,fingerprint,approval,status FROM reviews WHERE id=?", (review_id,)).fetchone()
        if row is None:
            raise ValueError("review not found")
        return row

    async def _review_control(self, payload):
        row = self._review(payload["review_id"])
        if payload["method"] == "inspect":
            current = await self.operations.review(row[1], json.loads(row[2]))
            return {**current, "review_id": row[0], "status": row[5], "reviewed_fingerprint": row[3], "unchanged": current["action_fingerprint"] == row[3]}
        if row[5] not in {"pending", "approved"}:
            raise ValueError("review is no longer active")
        if payload["method"] == "reject":
            if row[4]:
                await self.operations.gate.revoke_approval(self.operations.run_id, row[4], "owner rejected review")
            status, approval_id = "rejected", None
        else:
            if row[5] != "pending":
                raise ValueError("review already has an approval")
            fresh = self.operations.prepare(row[1], json.loads(row[2]))
            if payload.get("fingerprint") != row[3] or fresh.fingerprint != row[3]:
                raise ValueError("approval must match the exact inspected fingerprint")
            approval = await self.operations.approve(row[1], json.loads(row[2]), approver="owner-uid-" + str(os.getuid()), ttl_seconds=payload.get("ttl_seconds", 300))
            status, approval_id = "approved", approval["approval_id"]
        with closing(sqlite3.connect(self.jobs_path)) as db, db:
            db.execute("UPDATE reviews SET status=?,approval=? WHERE id=?", (status, approval_id, row[0]))
        return {"review_id": row[0], "status": status}


async def serve(service, agent_socket):
    agent_socket = Path(agent_socket).absolute()
    parent = agent_socket.parent
    if parent.is_symlink() or any(p.is_symlink() for p in parent.parents):
        raise ValueError("socket directory must not contain symlinks")
    parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    info = parent.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError("socket directory must be owner-owned and not writable by other identities")
    owner_socket = service.state / "control.sock"
    if agent_socket == owner_socket:
        raise ValueError("agent and control sockets must be separate")
    for path in (agent_socket, owner_socket):
        if path.is_symlink() or path.exists() and not path.is_socket():
            raise ValueError("refusing to replace non-socket path")
        if path.exists():
            if path.stat().st_uid != os.getuid():
                raise ValueError("existing socket is not owner-owned")
            with socket.socket(socket.AF_UNIX) as probe:
                try:
                    probe.connect(str(path))
                except OSError as exc:
                    if exc.errno != errno.ECONNREFUSED:
                        raise
                else:
                    raise ValueError("socket is already served by another process")
        path.unlink(missing_ok=True)
    async def handle(reader, writer, administrative):
        dispatched = False
        try:
            allowed = os.getuid() if administrative else service.agent_uid
            if peer_uid(writer.get_extra_info("socket")) != allowed:
                raise ValueError("caller OS identity is not authorized")
            line = await asyncio.wait_for(reader.readline(), 10)
            if not line or len(line) > MAX_BYTES:
                raise ValueError("invalid request size")
            payload = json.loads(line)
            dispatched = True
            result = await service.dispatch(payload, administrative=administrative)
            encoded = (canonical(result) + "\n").encode()
            if len(encoded) > MAX_BYTES:
                raise ValueError("response exceeds limit; use narrower operations")
        except Exception as exc:
            encoded = (canonical({"decision": "ERROR", "reason": str(exc), "executor_started": None if dispatched else False, "check_owner_state": True}) + "\n").encode()
        try:
            writer.write(encoded)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    agent = await asyncio.start_unix_server(lambda r, w: handle(r, w, False), str(agent_socket), limit=MAX_BYTES + 1)
    os.chmod(agent_socket, 0o666)
    owner = await asyncio.start_unix_server(lambda r, w: handle(r, w, True), str(owner_socket), limit=MAX_BYTES + 1)
    os.chmod(owner_socket, 0o600)
    print(canonical({"ready": True, "agent_socket": str(agent_socket), "control_socket": str(owner_socket), "run_id": service.operations.run_id}), flush=True)
    async with agent, owner:
        await asyncio.gather(agent.serve_forever(), owner.serve_forever())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    initializer = commands.add_parser("init")
    initializer.add_argument("directory", type=Path)
    route = commands.add_parser("verify")
    route.add_argument("--socket", type=Path, required=True)
    route.add_argument("--control-socket", type=Path, required=True)
    route.add_argument("--source", default="incident.json")
    route.add_argument("--report", required=True, help="new report path inside the permitted report directory")
    server = commands.add_parser("serve")
    server.add_argument("--workspace", type=Path, required=True)
    server.add_argument("--state", type=Path, required=True)
    server.add_argument("--config", type=Path, required=True)
    server.add_argument("--socket", type=Path, required=True)
    server.add_argument("--agent-uid", type=int, required=True)
    server.add_argument("--development", action="store_true")
    for command in ("status", "tools", "call", "review", "commit", "inspect", "approve", "reject", "artifact", "declassify", "reconcile", "export"):
        sub = commands.add_parser(command)
        sub.add_argument("--socket", type=Path, required=True)
        sub.add_argument("--json", default="{}", help="request fields as JSON; omit method")
        if command in {"inspect", "approve", "reject", "commit"}:
            sub.add_argument("review_id", nargs="?")
        if command == "approve":
            sub.add_argument("--fingerprint")
            sub.add_argument("--ttl-seconds", type=int, default=300)
        if command in {"call", "review"}:
            sub.add_argument("name", nargs="?")
            sub.add_argument("--arguments", help="tool arguments as JSON")
        if command == "export":
            sub.add_argument("--output", type=Path, required=True)
            sub.add_argument("--from-sequence", type=int, default=0)
            sub.add_argument("--limit", type=int, default=25)
    verify = commands.add_parser("verify-evidence")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--key-file", type=Path, required=True)
    args = parser.parse_args(argv)
    service = None
    try:
        if args.command == "init":
            from agent_circuit_breaker.owner_setup import initialize
            print(json.dumps(initialize(args.directory), indent=2))
            return 0
        if args.command == "verify":
            from agent_circuit_breaker.owner_setup import verify_route
            print(json.dumps(verify_route(args.socket, args.control_socket, args.source, args.report), indent=2))
            return 0
        if args.command == "serve":
            service = OwnerService(args.workspace, args.state, json.loads(args.config.read_text()), args.agent_uid, development=args.development)
            async def run():
                await service.start()
                await serve(service, args.socket)
            asyncio.run(run())
            return 0
        if args.command == "verify-evidence":
            result = verify_bundle(json.loads(args.bundle.read_text()), args.key_file.read_bytes())
        else:
            payload = json.loads(args.json)
            if not isinstance(payload, dict) or "method" in payload:
                raise ValueError("request fields must be an object without method")
            for key in ("review_id", "fingerprint", "name"):
                if getattr(args, key, None) is not None:
                    payload[key] = getattr(args, key)
            if getattr(args, "arguments", None) is not None:
                payload["arguments"] = json.loads(args.arguments)
            if args.command == "approve":
                payload.setdefault("ttl_seconds", args.ttl_seconds)
            if args.command == "export":
                payload.setdefault("from_sequence", args.from_sequence)
                payload.setdefault("limit", args.limit)
            payload["method"] = args.command
            if args.command in {"call", "commit"}:
                payload.setdefault("request_id", uuid.uuid4().hex)
            result = request(args.socket, payload)
            if args.command == "export" and "signature" in result:
                atomic_write(args.output, (canonical(result) + "\n").encode())
                result = {"exported": str(args.output), "next_sequence": result["payload"]["next_sequence"],
                          "state_version": result["payload"]["state_version"],
                          "retention": "retain all pages independently; protect the verification key"}
        print(json.dumps(result, indent=2))
        return {"ERROR": 1, "BLOCK": 1, "UNKNOWN": 2, "PENDING_APPROVAL": 3}.get(result.get("decision"), 0)
    except (ValueError, OSError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if service:
            service.close()


if __name__ == "__main__":
    raise SystemExit(main())
