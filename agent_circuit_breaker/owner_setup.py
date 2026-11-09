"""Create a disposable, usable owner-service project and verify its real route."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path

from agent_circuit_breaker.integrations import atomic_write
from agent_circuit_breaker.workflow import canonical, digest


def initialize(directory):
    root = Path(directory).resolve()
    root.mkdir(mode=0o755, parents=True, exist_ok=False)
    workspace = root / "workspace"
    workspace.mkdir(mode=0o700)
    (workspace / "reports").mkdir(mode=0o700)
    (root / "state").mkdir(mode=0o700)
    (root / "socket").mkdir(mode=0o755)
    source = (canonical({"incident": "synthetic failed login report", "count": 3}) + "\n").encode()
    atomic_write(workspace / "incident.json", source)
    database = root / "tickets.sqlite3"
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("CREATE TABLE tickets (id INTEGER PRIMARY KEY, status TEXT NOT NULL)")
        connection.executemany("INSERT INTO tickets VALUES (?,?)", [(1, "open"), (2, "open"), (3, "closed")])
    os.chmod(database, 0o600)
    configuration = {
        "workflow": {"principal": "maintenance-agent", "read_paths": {"incident.json": {"sha256": digest(source), "labels": ["internal"]}},
                     "report_directory": "reports", "destinations": {}},
        "database": {"path": str(database), "operations": {"close_ticket": {"sql": "UPDATE tickets SET status = :status WHERE id = :id",
            "table": "tickets", "parameters": ["status", "id"], "max_rows": 1}}},
        "effect_limits": {"database_rows": 2, "files_written": 10, "export_bytes": 1048576},
    }
    atomic_write(root / "owner.json", (json.dumps(configuration, indent=2) + "\n").encode())
    return {"created": str(root), "workspace": str(workspace), "state": str(root / "state"), "config": str(root / "owner.json"),
            "agent_socket": str(root / "socket" / "agent.sock"), "control_socket": str(root / "state" / "control.sock"),
            "data": "synthetic local examples; configure actual permissions before using real resources",
            "isolation": "run owner and agent under different UIDs for protected deployment; development mode alone provides no isolation"}


def verify_route(agent_socket, control_socket, source, report):
    """Perform a real read/copy, inspect resulting bytes, and try a denied write."""
    from agent_circuit_breaker.owner import request
    def call(name, arguments):
        return request(agent_socket, {"method": "call", "name": name, "arguments": arguments, "request_id": uuid.uuid4().hex})
    original = call("read_file", {"path": source})
    if original.get("outcome") != "executed":
        raise ValueError("read did not execute: " + canonical(original))
    artifact = original["result"]["artifact"]
    copied = call("copy_artifact", {"artifact_id": artifact["id"], "path": report})
    if copied.get("outcome") != "executed":
        raise ValueError("copy did not execute: " + canonical(copied))
    observed = request(control_socket, {"method": "artifact", "artifact_id": copied["result"]["artifact"]["id"]})
    if observed.get("artifact", {}).get("sha256") != artifact["sha256"] or observed.get("text") != original["result"]["text"]:
        raise ValueError("owner inspection did not observe the exact copied bytes")
    denied = call("copy_artifact", {"artifact_id": artifact["id"], "path": "../outside.txt"})
    if denied.get("decision") != "BLOCK" or denied.get("executor_started") is not False:
        raise ValueError("out-of-scope write was not rejected before execution")
    return {"verified": True, "report": report, "sha256": artifact["sha256"], "checks": ["actual source read", "actual artifact copy", "independent owner byte inspection", "traversal denied before executor"],
            "scope": "configured owner-service route; native shell and other MCP servers are not certified"}
