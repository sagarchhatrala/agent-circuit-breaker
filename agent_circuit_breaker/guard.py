"""One-shot guard checks for ACB hook drift."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from agent_circuit_breaker.hooks_native import HOST_CONFIGS, write_native_hook_scaffold


def check_hook_drift(home: str) -> Dict[str, Any]:
    """Report supported host configs that exist but no longer reference ACB."""
    root = Path(home)
    findings: List[Dict[str, str]] = []
    for agent, (relative_path, _claude_style) in HOST_CONFIGS.items():
        path = root / relative_path
        if not path.exists():
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        if "agent-circuit-breaker" not in raw:
            findings.append({"agent": agent, "path": str(path), "status": "missing_acb_hook"})
    return {"schema_version": 1, "findings": findings, "drifted": bool(findings)}


def restore_managed_hooks(home: str) -> Dict[str, Any]:
    """Restore ACB hook entries for supported hosts with existing managed configs."""
    report = check_hook_drift(home)
    restored = []
    for finding in report["findings"]:
        result = write_native_hook_scaffold(finding["agent"], home, force=True)
        restored.append(result)
    return {"schema_version": 1, "restored": restored, "restored_count": len(restored)}
