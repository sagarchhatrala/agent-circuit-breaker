"""Typed, executor-owned local workflows. No shell strings or agent authority labels.

The owner must isolate this process, state directory, and policy from the agent.
POSIX no-follow directory descriptors confine file operations; this is not an OS
sandbox. Arbitrary programs, free-form report transformations and declassification
are deliberately absent from the agent-facing tools.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import re
import tempfile
import sqlite3
import stat
import sys
import subprocess
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from agent_circuit_breaker.runtime import ExecutionUncertain, RuntimeAction, RuntimeGate, SQLiteRunStore

MAX_BYTES = 1024 * 1024
LABELS = {"public", "internal", "sensitive", "unknown"}


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class WorkflowDenied(ValueError):
    pass


class WorkflowUnknown(ValueError):
    pass


def relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise WorkflowDenied("expected a workspace-relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ("", ".", "..") for p in value.split("/")):
        raise WorkflowDenied("path traversal or ambiguous path")
    if any(p.startswith(".") for p in path.parts):
        raise WorkflowDenied("hidden files and configuration are outside this profile")
    return path.as_posix()


class Workspace:
    """Open files beneath a pinned root without following any symlink."""

    def __init__(self, root: Path):
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise WorkflowUnknown("typed file executor requires POSIX no-follow descriptors")
        self.root = root.resolve(strict=True)
        self.identity = self.root.stat().st_dev, self.root.stat().st_ino

    @contextmanager
    def root_descriptor(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self.identity:
                raise WorkflowDenied("workspace root changed")
            yield fd
        finally:
            os.close(fd)

    @contextmanager
    def parent(self, path: str):
        parts = relative_path(path).split("/")
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self.identity:
                raise WorkflowDenied("workspace root changed")
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            yield fd, parts[-1]
        finally:
            os.close(fd)

    def read(self, path: str) -> bytes:
        with self.parent(path) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES or before.st_nlink != 1:
                    raise WorkflowDenied("only bounded, regular, single-link files are supported")
                data = stream.read(MAX_BYTES + 1)
                after = os.fstat(stream.fileno())
                if len(data) > MAX_BYTES or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise WorkflowDenied("file changed while reading")
                return data

    def write_new(self, path: str, data: bytes) -> None:
        if len(data) > MAX_BYTES:
            raise WorkflowDenied("artifact exceeds size limit")
        with self.parent(path) as (parent, name):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())


class ProvenanceStore:
    """Authenticated versioned records, stored outside agent-writable paths.

    The key and DB are owner-only. This detects metadata edits without the key;
    it does not defend against an attacker running as the owner's OS identity.
    """

    def __init__(self, directory: Path):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.is_symlink() or directory.stat().st_mode & 0o077:
            raise WorkflowDenied("state directory must be private (mode 0700)")
        self.path = directory / "provenance.sqlite3"
        key_path = directory / "provenance.key"
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())
        if key_path.is_symlink() or key_path.stat().st_mode & 0o077:
            raise WorkflowDenied("provenance key must be private")
        self.key = key_path.read_bytes()
        if len(self.key) != 32 or self.path.is_symlink():
            raise WorkflowDenied("invalid provenance store")
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY, payload TEXT NOT NULL, mac TEXT NOT NULL)")
        os.chmod(self.path, 0o600)

    def put(self, path: str, data: bytes, labels: list[str], *, sources: list[str], operation: str) -> dict:
        artifact = {"id": uuid.uuid4().hex, "path": path, "sha256": digest(data), "labels": sorted(set(labels)), "sources": sources, "operation": operation, "created_at": time.time()}
        payload = canonical(artifact)
        mac = hmac.new(self.key, payload.encode(), "sha256").hexdigest()
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("INSERT INTO artifacts VALUES (?, ?, ?)", (artifact["id"], payload, mac))
        return artifact

    def get(self, artifact_id: str) -> dict:
        with closing(sqlite3.connect(self.path)) as conn:
            row = conn.execute("SELECT payload, mac FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
        if row is None:
            raise WorkflowDenied("unknown artifact; agent-provided labels are not authority")
        if not hmac.compare_digest(hmac.new(self.key, row[0].encode(), "sha256").hexdigest(), row[1]):
            raise WorkflowDenied("provenance integrity verification failed")
        return json.loads(row[0])


# These schemas are shared by MCP and Responses. Additional properties are denied.
TOOL_FIELDS = {
    "read_file": {"path": "string"},
    "repository_status": {},
    "copy_artifact": {"artifact_id": "string", "path": "string"},
    "encode_artifact": {"artifact_id": "string", "path": "string"},
    "write_report": {"sources": "array", "path": "string"},
    "publish_artifact": {"artifact_id": "string", "destination": "string"},
}
DESCRIPTIONS = {
    "read_file": "Read a permitted workspace file and return its versioned artifact identity.",
    "repository_status": "Inspect tracked repository status using a fixed, isolated Git invocation.",
    "copy_artifact": "Copy an exact artifact version into the report directory; preserve sensitivity.",
    "encode_artifact": "Base64 encode an exact artifact version; preserve sensitivity.",
    "write_report": "Render a fixed report from versioned sources; preserve all source labels.",
    "publish_artifact": "Publish an exact artifact to a configured destination; requires separate owner approval.",
}


def tool_catalog() -> list[dict]:
    return [{"name": name, "description": DESCRIPTIONS[name], "inputSchema": {
        "type": "object", "properties": {k: ({"type": t, "items": {"type": "string"}} if t == "array" else {"type": t}) for k, t in fields.items()},
        "required": list(fields), "additionalProperties": False,
    }} for name, fields in TOOL_FIELDS.items()]


class Workflow:
    """Trusted dispatcher. Construct with owner policy; expose only call to agents."""

    def __init__(self, root: Path, state_dir: Path, policy: dict, *, publisher: Callable[[str, bytes, dict], Any] | None = None):
        self.workspace = Workspace(root)
        # Deep-copy so callers cannot mutate effective authority after construction.
        self.policy = json.loads(canonical(policy))
        self._validate_policy()
        self.policy_hash = digest(canonical(self.policy).encode())
        self.provenance = ProvenanceStore(state_dir)
        self.gate = RuntimeGate(store=SQLiteRunStore(str(state_dir / "runtime.sqlite3")), evaluator=self._evaluate, compact_trajectory_events=True)
        self.publisher = publisher
        self.run_id: str | None = None
        self._lock = asyncio.Lock()

    def _validate_policy(self) -> None:
        allowed = {"principal", "read_paths", "report_directory", "destinations", "goal", "repository_status"}
        if set(self.policy) - allowed:
            raise ValueError("unknown policy fields")
        if not isinstance(self.policy.get("principal"), str) or not self.policy["principal"]:
            raise ValueError("owner policy must specify principal")
        if not isinstance(self.policy.get("read_paths"), dict):
            raise ValueError("read_paths must map exact paths to trusted labels")
        for path, source in self.policy["read_paths"].items():
            relative_path(path)
            if not isinstance(source, dict) or set(source) != {"labels", "sha256"}:
                raise ValueError("each read permission must bind labels to an exact SHA-256")
            labels = source["labels"]
            if not isinstance(source["sha256"], str) or len(source["sha256"]) != 64:
                raise ValueError("invalid source SHA-256")
            if not isinstance(labels, list) or not labels or not all(x in LABELS for x in labels):
                raise ValueError("invalid sensitivity labels")
        relative_path(self.policy["report_directory"])
        if not isinstance(self.policy.get("destinations", {}), dict):
            raise ValueError("destinations must be an object")
        for name, labels in self.policy.get("destinations", {}).items():
            if not isinstance(name, str) or not name or not isinstance(labels, list) or not labels or not all(x in LABELS for x in labels):
                raise ValueError("invalid destination policy")
            if "unknown" in labels or "sensitive" in labels:
                raise ValueError("sensitive/unknown export requires separate declassification; not agent-accessible")
        if not isinstance(self.policy.get("repository_status", False), bool):
            raise ValueError("repository_status must be boolean")

    def preview(self) -> dict:
        return {"policy": self.policy, "policy_sha256": self.policy_hash, "tools": tool_catalog(), "goal_semantics": "explanatory metadata only", "boundary": "owner process and state must be inaccessible to the agent"}

    async def start(self, run_id: str | None = None) -> str:
        contract = {"goal": self.policy.get("goal"), "allowed_actors": ["workflow"], "require_actor": True,
                    "capabilities": [{"id": self.policy_hash, "principal": self.policy["principal"], "action_types": list(TOOL_FIELDS), "actors": ["workflow"]}],
                    "approval_required_action_types": ["publish_artifact"], "max_actions": 100, "ttl_seconds": 3600}
        if run_id:
            state = await self.gate.read_run(run_id)
            if state.contract["capabilities"][0]["id"] != self.policy_hash:
                raise WorkflowDenied("workflow policy changed; existing authority cannot be reused")
            self.run_id = run_id
        else:
            self.run_id = (await self.gate.create_run(contract)).run_id
        return self.run_id

    def _args(self, name: str, arguments: Any) -> dict:
        if name not in TOOL_FIELDS:
            raise WorkflowUnknown("tool has no trusted registration")
        if not isinstance(arguments, dict) or set(arguments) != set(TOOL_FIELDS[name]):
            raise WorkflowDenied("arguments do not match registered schema; authority metadata is forbidden")
        args = json.loads(canonical(arguments))
        for key, kind in TOOL_FIELDS[name].items():
            if kind == "string" and (not isinstance(args[key], str) or not args[key] or len(args[key]) > 4096):
                raise WorkflowDenied("invalid string argument")
            if kind == "array" and (not isinstance(args[key], list) or not 1 <= len(args[key]) <= 16 or not all(isinstance(x, str) and x for x in args[key])):
                raise WorkflowDenied("sources must contain 1–16 artifact IDs")
        if "path" in args:
            args["path"] = relative_path(args["path"])
            if name == "read_file":
                if args["path"] not in self.policy["read_paths"]:
                    raise WorkflowDenied("file is outside explicit read permissions")
            elif not args["path"].startswith(self.policy["report_directory"] + "/"):
                raise WorkflowDenied("output is outside report directory")
        if name == "repository_status" and not self.policy.get("repository_status"):
            raise WorkflowDenied("repository status is not permitted")
        if name == "publish_artifact" and args["destination"] not in self.policy.get("destinations", {}):
            raise WorkflowDenied("destination is outside explicit publish permissions")
        return args

    def prepare(self, name: str, arguments: Any) -> RuntimeAction:
        args = self._args(name, arguments)
        versions = []
        if name == "repository_status":
            with self.workspace.root_descriptor():
                pass
        if name == "read_file":
            data = self.workspace.read(args["path"])
            source = self.policy["read_paths"][args["path"]]
            if digest(data) != source["sha256"]:
                raise WorkflowDenied("source changed since owner classified its version")
            versions = [{"path": args["path"], "sha256": digest(data), "labels": source["labels"]}]
        for artifact_id in ([args["artifact_id"]] if "artifact_id" in args else args.get("sources", [])):
            artifact = self.provenance.get(artifact_id)
            data = self.workspace.read(artifact["path"])
            if digest(data) != artifact["sha256"]:
                raise WorkflowDenied("artifact changed; approval/provenance applies only to its exact version")
            versions.append(artifact)
        if name == "publish_artifact":
            labels = set(versions[0]["labels"])
            if not labels <= set(self.policy["destinations"][args["destination"]]):
                raise WorkflowDenied("artifact sensitivity is forbidden at this destination")
        payload = {"operation": name, "arguments": args, "versions": versions, "policy": self.policy_hash}
        resource = args.get("destination", args.get("path", str(self.workspace.root)))
        return RuntimeAction(command="acb-workflow " + canonical(payload), actor="workflow", principal=self.policy["principal"], capability_id=self.policy_hash, action_type=name, target_resource=resource, tool_name=name, metadata={"adapter": "typed-workflow-v1", "payload": payload})

    def _evaluate(self, command: str) -> dict:
        try:
            if not command.startswith("acb-workflow "):
                raise WorkflowUnknown("unregistered command")
            payload = json.loads(command[len("acb-workflow "):])
            if payload["policy"] != self.policy_hash:
                raise WorkflowDenied("policy changed")
            self._args(payload["operation"], payload["arguments"])
            decision, reason = "ALLOW", "validated typed workflow contract"
        except WorkflowUnknown as exc:
            decision, reason = "UNKNOWN", str(exc)
        except (KeyError, ValueError, TypeError) as exc:
            decision, reason = "BLOCK", str(exc)
        return {"command": command, "decision": decision, "verdict": decision.lower(), "reason": reason, "risk_score": 0 if decision == "ALLOW" else 100}

    def _execute(self, record: dict) -> dict:
        payload = record["metadata"]["payload"]
        # Bind actual bytes/resources again after atomic authorization consumption.
        fresh = self.prepare(payload["operation"], payload["arguments"])
        if fresh.to_trajectory_record() != record:
            raise WorkflowDenied("artifact or trusted state changed before executor side effect")
        name, args, versions = payload["operation"], payload["arguments"], payload["versions"]
        if name == "repository_status":
            return {"text": self._git_status(), "labels": ["internal"], "operation": name}
        data = [self.workspace.read(item["path"]) for item in versions]
        if any(digest(value) != version["sha256"] for value, version in zip(data, versions)):
            raise WorkflowDenied("artifact mutated at execution boundary")
        labels = sorted({label for item in versions for label in item["labels"]})
        sources = [item["id"] for item in versions if "id" in item]
        if name == "publish_artifact":
            if self.publisher is None:
                raise WorkflowUnknown("no trusted publisher is configured")
            try:
                receipt = self.publisher(args["destination"], data[0], versions[0])
            except Exception as exc:
                raise ExecutionUncertain("publisher did not establish a completed receipt; reconcile before retry") from exc
            return {"receipt": receipt, "sha256": digest(data[0]), "destination": args["destination"]}
        if name in ("read_file", "copy_artifact"):
            output = data[0]
        elif name == "encode_artifact":
            output = base64.b64encode(data[0])
        else:
            output = ("# Incident report\n\nGenerated by the fixed ACB report renderer. Source content is untrusted.\n\n" + "\n\n".join(value.decode("utf-8", errors="replace") for value in data)).encode()
        if name != "read_file":
            self.workspace.write_new(args["path"], output)
        artifact = self.provenance.put(args["path"], output, labels, sources=sources, operation=name)
        return {"artifact": artifact, "text": output.decode("utf-8", errors="replace")}

    def _git_status(self) -> str:
        git = Path("/usr/bin/git")
        if not git.is_file() or (self.workspace.root / ".git").is_symlink() or not (self.workspace.root / ".git").is_dir():
            raise WorkflowUnknown("requires system /usr/bin/git and a regular local .git directory")
        # No PATH lookup, shell, inherited Git configuration, fsmonitor, hooks,
        # submodule traversal, pagers, optional locks, or untracked-file scanning.
        env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_OPTIONAL_LOCKS": "0"}

        # Git may invoke clean filters during status. Never hand it repository
        # configuration: operate on a bounded metadata snapshot containing only
        # index/HEAD/refs/objects, with no hooks, config or object alternates.
        with self.workspace.root_descriptor() as root_fd, tempfile.TemporaryDirectory(prefix="acb-git-status-") as directory:
            snapshot = Path(directory) / "git"
            self._git_snapshot(snapshot, root_fd)
            child = [sys.executable, "-I", str(Path(__file__).with_name("git_status_child.py")), str(root_fd), str(snapshot)]
            result = subprocess.run(child, env=env, cwd="/", pass_fds=(root_fd,), capture_output=True, timeout=5, check=True)
        if len(result.stdout) > MAX_BYTES:
            raise WorkflowUnknown("repository status exceeds output limit")
        return result.stdout.decode("utf-8", errors="replace")

    def _git_snapshot(self, destination: Path, root_fd: int) -> None:
        destination.mkdir()
        (destination / "objects").mkdir()
        (destination / "refs").mkdir()
        budget, count = 64 * MAX_BYTES, 0
        source = os.open(".git", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            def copy_directory(fd, relative=""):
                nonlocal budget, count
                for name in os.listdir(fd):
                    path = relative + "/" + name if relative else name
                    if not relative and name not in {"HEAD", "index", "packed-refs", "objects", "refs"}:
                        continue
                    if path == "objects/info":
                        # Includes alternates, which could escape the repository.
                        continue
                    if path.startswith("objects/"):
                        tail = path[len("objects/"):]
                        if not (tail == "pack" or re.fullmatch(r"[0-9a-f]{2}(?:/[0-9a-f]{38}|/[0-9a-f]{62})?", tail) or re.fullmatch(r"pack/pack-[0-9a-f]{40,64}\.(?:pack|idx|rev)", tail)):
                            continue
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    target = destination / path
                    if stat.S_ISDIR(info.st_mode):
                        target.mkdir(exist_ok=True)
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        try:
                            copy_directory(child, path)
                        finally:
                            os.close(child)
                    else:
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            raise WorkflowUnknown("Git metadata symlinks/hardlinks/special files unsupported")
                        count += 1
                        budget -= info.st_size
                        if count > 10000 or budget < 0:
                            raise WorkflowUnknown("Git metadata exceeds bounded snapshot profile")
                        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                        with os.fdopen(child, "rb") as stream:
                            content = stream.read(info.st_size + 1)
                            after = os.fstat(stream.fileno())
                        if len(content) != info.st_size or (info.st_ino, info.st_mtime_ns, info.st_ctime_ns) != (after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
                            raise WorkflowUnknown("Git metadata changed during snapshot")
                        if path == "HEAD" and not re.fullmatch(rb"(?:[0-9a-f]{40}|ref: refs/[A-Za-z0-9_./-]+)\n?", content):
                            raise WorkflowUnknown("unsupported Git HEAD")
                        target.write_bytes(content)
            copy_directory(source)
        finally:
            os.close(source)

    async def call(self, name: str, arguments: Any, *, approval_id: str | None = None) -> dict:
        if self.run_id is None:
            raise RuntimeError("start a workflow run first")
        async with self._lock:
            started = False
            def execute(record):
                nonlocal started
                started = True
                return self._execute(record)
            try:
                action = self.prepare(name, arguments)
                if approval_id:
                    result = await self.gate.execute_approved(self.run_id, action, approval_id=approval_id, executor=execute)
                    return {"decision": "ALLOW", "reason": "exact approval consumed", "executor_started": True, "outcome": result.outcome, "result": result.result}
                decision = await self.gate.propose_action(self.run_id, action)
                if not decision.authorized:
                    return {"decision": decision.decision, "reason": decision.reason, "executor_started": False, "resource": action.target_resource}
                result = await self.gate.execute_authorized(self.run_id, authorization_id=decision.authorization_id, executor=execute)
                return {"decision": decision.decision, "reason": decision.reason, "executor_started": True, "outcome": result.outcome, "resource": action.target_resource, "result": result.result}
            except ExecutionUncertain as exc:
                return {"decision": "ERROR", "reason": str(exc), "executor_started": True, "outcome": "unknown_execution_status"}
            except WorkflowUnknown as exc:
                return {"decision": "UNKNOWN", "reason": str(exc), "executor_started": started, "outcome": "failed" if started else None}
            except (ValueError, OSError) as exc:
                return {"decision": "ERROR" if started else "BLOCK", "reason": str(exc), "executor_started": started, "outcome": "failed" if started else None}

    async def approve(self, name: str, arguments: dict, *, approver: str, ttl_seconds: int = 300) -> dict:
        """Owner control plane only; never register this as an agent tool."""
        action = self.prepare(name, arguments)
        return (await self.gate.grant_approval(self.run_id, action, approver=approver, ttl_seconds=ttl_seconds)).to_dict()
