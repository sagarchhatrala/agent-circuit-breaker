"""Native hook config scaffolds for common coding agents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


HOST_CONFIGS = {
    "claude": (".claude/settings.json", True),
    "cursor": (".cursor/hooks.json", False),
    "codex": (".codex/hooks.json", False),
    "gemini": (".gemini/settings.json", True),
    "copilot": (".copilot/hooks.json", False),
}


def write_native_hook_scaffold(agent: str, home: str, *, force: bool = False) -> Dict[str, Any]:
    """Write a conservative user-level hook config for a supported host."""
    normalized = agent.strip().lower()
    if normalized not in HOST_CONFIGS:
        raise ValueError(f"agent must be one of: {', '.join(sorted(HOST_CONFIGS))}")
    relative_settings, claude_style = HOST_CONFIGS[normalized]
    settings_path = Path(home) / relative_settings
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_json(settings_path)
    command = "agent-circuit-breaker check"

    if existing and not force and "agent-circuit-breaker" not in json.dumps(existing):
        return {
            "agent": normalized,
            "path": str(settings_path),
            "status": "unknown_existing_config",
            "reason": "existing hook config is not managed by Agent Circuit Breaker",
        }

    updated = _merge_hook_config(existing or {}, command, claude_style=claude_style)
    settings_path.write_text(json.dumps(updated, indent=2, sort_keys=True), encoding="utf-8")
    return {"agent": normalized, "path": str(settings_path), "status": "written"}


def _merge_hook_config(config: Dict[str, Any], command: str, *, claude_style: bool) -> Dict[str, Any]:
    hooks = config.setdefault("hooks", {})
    if claude_style:
        for event in ("PreToolUse", "PostToolUse"):
            entries = hooks.setdefault(event, [])
            if command not in json.dumps(entries):
                entries.append({"matcher": "*", "hooks": [{"type": "command", "command": command}]})
    else:
        for event in ("preToolUse", "postToolUse", "beforeShellExecution", "beforeMCPExecution"):
            entries = hooks.setdefault(event, [])
            if command not in json.dumps(entries):
                entries.append({"type": "command", "command": command})
    return config


def _read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"hook config must be a JSON object: {path}")
    return value
