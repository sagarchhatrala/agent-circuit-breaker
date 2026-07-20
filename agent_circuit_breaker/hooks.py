"""Hook scaffold generation for local agent workflows."""

from pathlib import Path
from typing import Dict


HOOK_SCRIPT = """#!/usr/bin/env python3
import subprocess
import sys


def main() -> int:
    command = " ".join(sys.argv[1:]).strip()
    if not command:
        return 0
    result = subprocess.run(
        ["circuit-breaker", "check", command],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode in (0, 2):
        return 0
    sys.stderr.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
"""


def hook_instructions(agent: str = "generic") -> str:
    """Return non-vendor-specific hook instructions."""
    return (
        "Create a pre-command hook that calls:\n"
        "  circuit-breaker check \"<command>\"\n\n"
        "Allow exit code 0, stop on exit code 1, and treat exit code 2 as not vetted. "
        f"Selected agent profile: {agent}."
    )


def write_hook_scaffold(directory: str) -> Dict[str, str]:
    """Write a local hook scaffold under the requested directory."""
    root = Path(directory)
    hook_dir = root / ".agent-circuit-breaker" / "hooks"
    hook_dir.mkdir(parents=True, exist_ok=True)
    script_path = hook_dir / "pre-command.py"
    script_path.write_text(HOOK_SCRIPT, encoding="utf-8")
    return {
        "path": str(script_path),
        "status": "written",
    }
