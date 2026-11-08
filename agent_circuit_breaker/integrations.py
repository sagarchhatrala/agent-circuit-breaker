"""Project-scoped integration preview, merge, verification and restoration."""
from __future__ import annotations

import argparse
import copy
import json
import os
import shlex
import shutil
import sys
import tomllib
from pathlib import Path

from agent_circuit_breaker.hooks_native import decide

PATHS = {("claude", "hooks"): ".claude/settings.json", ("cursor", "hooks"): ".cursor/hooks.json", ("claude", "mcp"): ".mcp.json", ("cursor", "mcp"): ".cursor/mcp.json", ("codex", "mcp"): ".codex/config.toml"}


def additions(host: str, mode: str, workspace: Path, state: Path | None, policy: Path | None) -> dict:
    executable = sys.executable
    if mode == "hooks":
        if host == "claude":
            command = shlex.join([executable, "-I", "-m", "agent_circuit_breaker.hooks_native", "claude", "PreToolUse"])
            return {"hooks": {"PreToolUse": [{"matcher": "Bash|mcp__.*", "hooks": [{"type": "command", "command": command, "timeout": 10, "onFailure": "block"}]}]}}
        commands = {event: [{"command": shlex.join([executable, "-I", "-m", "agent_circuit_breaker.hooks_native", "cursor", event]), "timeout": 10, "failClosed": True}] for event in ("beforeShellExecution", "beforeMCPExecution")}
        return {"version": 1, "hooks": commands}
    if state is None or policy is None:
        raise ValueError("MCP configuration requires --state and --policy (owner-protected paths)")
    server = {"command": executable, "args": ["-I", "-m", "agent_circuit_breaker_mcp.workflow_server", "--workspace", str(workspace), "--state", str(state.resolve()), "--policy", str(policy.resolve())]}
    return {"mcp_servers" if host == "codex" else "mcpServers": {"acb": server}}


def merge(existing: dict, patch: dict) -> dict:
    result = copy.deepcopy(existing)
    for key, value in patch.items():
        if key not in result:
            result[key] = copy.deepcopy(value)
        elif isinstance(value, dict) and isinstance(result[key], dict):
            result[key] = merge(result[key], value)
        elif isinstance(value, list) and isinstance(result[key], list):
            for entry in value:
                if entry not in result[key]:
                    result[key].append(copy.deepcopy(entry))
        elif value != result[key]:
            raise ValueError("configuration conflict at " + key + "; existing value preserved")
    return result


def subtract(current: dict, before: dict, installed: dict) -> dict:
    result = copy.deepcopy(current)
    for key, value in installed.items():
        if key not in before:
            if result.get(key) != value:
                if isinstance(value, dict) and isinstance(result.get(key), dict):
                    result[key] = subtract(result[key], {}, value)
                    if not result[key]:
                        result.pop(key)
                    continue
                raise ValueError("managed configuration changed; restore manually from private backup")
            result.pop(key, None)
        elif isinstance(value, dict) and isinstance(before[key], dict) and isinstance(result.get(key), dict):
            result[key] = subtract(result[key], before[key], value)
        elif isinstance(value, list) and isinstance(before[key], list) and isinstance(result.get(key), list):
            for entry in value:
                if entry not in before[key] and entry in result[key]:
                    result[key].remove(entry)
    return result


def atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError("configuration symlinks are not supported")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".acb-new")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def integrate(host: str, project: Path, *, mode="hooks", operation="preview", state: Path | None = None, policy: Path | None = None) -> dict:
    project = project.resolve(strict=True)
    if (host, mode) not in PATHS:
        raise ValueError("unsupported host/mode; Codex supports mediated MCP configuration")
    path = project / PATHS[host, mode]
    receipt = project / ".acb-integrations" / (host + "-" + mode + ".json")
    detected = shutil.which({"claude": "claude", "cursor": "cursor-agent", "codex": "codex"}[host]) is not None
    if operation == "detect":
        return {"host": host, "executable_detected": detected, "configuration_exists": path.exists(), "native_validation": "not established by detection"}
    if operation == "uninstall":
        if not receipt.exists():
            return {"status": "not_installed", "path": str(path)}
        record = json.loads(receipt.read_text())
        current = path.read_text() if path.exists() else ""
        if current == record["installed"]:
            restored = record["before"]
        elif path.suffix == ".toml":
            if record["section"] not in current:
                raise ValueError("managed TOML section changed; private backup retained")
            restored = current.replace(record["section"], "", 1)
        else:
            restored = json.dumps(subtract(json.loads(current), json.loads(record["before"] or "{}"), json.loads(record["installed"])), indent=2) + "\n"
        if not record["existed"] and (not restored.strip() or restored.strip() == "{}"):
            path.unlink(missing_ok=True)
        else:
            atomic_write(path, restored.encode())
        receipt.unlink()
        return {"status": "restored", "path": str(path)}
    if operation == "verify":
        if not receipt.exists() or not path.exists():
            raise ValueError("integration not installed by ACB")
        record = json.loads(receipt.read_text())
        raw = path.read_text()
        parsed = tomllib.loads(raw) if path.suffix == ".toml" else json.loads(raw)
        if mode == "hooks":
            event = "PreToolUse" if host == "claude" else "beforeShellExecution"
            make = lambda command: {"hook_event_name": event, "tool_name": "Bash", "tool_input": {"command": command}} if host == "claude" else {"command": command}
            outcomes = [decide(host, event, make(command))["decision"] for command in ("mkdir /tmp/acb-hook-fixture", "rm -rf /")]
            if outcomes != ["ALLOW", "BLOCK"]:
                raise ValueError("hook fixture verification failed")
        if merge(parsed, record["patch"]) != parsed:
            raise ValueError("installed integration has drifted")
        return {"status": "verified", "verification": "configuration and hook fixtures only" if mode == "hooks" else "configuration only; use MCP client to verify execution", "native_host": "unverified", "path": str(path)}
    patch = additions(host, mode, project, state, policy)
    before = path.read_text() if path.exists() else ""
    if path.suffix == ".toml":
        parsed = tomllib.loads(before)
        if "acb" in parsed.get("mcp_servers", {}):
            if parsed["mcp_servers"]["acb"] != patch["mcp_servers"]["acb"]:
                raise ValueError("existing acb server differs; preserved")
            installed, section = before, ""
        else:
            server = patch["mcp_servers"]["acb"]
            section = "\n# ACB managed MCP server\n[mcp_servers.acb]\ncommand = " + json.dumps(server["command"]) + "\nargs = " + json.dumps(server["args"]) + "\n"
            installed = before + section
            tomllib.loads(installed)
    else:
        parsed = json.loads(before or "{}")
        if not isinstance(parsed, dict):
            raise ValueError("configuration must be an object")
        installed = json.dumps(merge(parsed, patch), indent=2) + "\n"
        section = ""
    if operation == "preview":
        return {"status": "preview", "path": str(path), "addition": patch, "executable_detected": detected}
    if receipt.exists():
        if json.loads(receipt.read_text())["installed"] != before:
            # Repeat install leaves unrelated edits intact; verify managed portion.
            if merge(parsed, patch) != parsed:
                raise ValueError("managed installation drifted")
        return {"status": "already_installed", "path": str(path)}
    record = {"before": before, "existed": path.exists(), "installed": installed, "section": section, "patch": patch}
    # Backup before touching the host file. Never print its potentially private contents.
    atomic_write(receipt, json.dumps(record).encode())
    atomic_write(path, installed.encode())
    return {"status": "written", "path": str(path), "verification": "run integrate verify, then native host smoke tests"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", choices=("claude", "cursor", "codex"))
    parser.add_argument("operation", choices=("detect", "preview", "install", "verify", "uninstall"), default="preview", nargs="?")
    parser.add_argument("--mode", choices=("hooks", "mcp"), default="mcp")
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--state", type=Path)
    parser.add_argument("--policy", type=Path)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(integrate(args.host, args.project, mode=args.mode, operation=args.operation, state=args.state, policy=args.policy), indent=2))
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0
