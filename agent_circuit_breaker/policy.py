"""Central policy loading and precedence helpers."""

import json
import os
from urllib.request import urlopen
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


POLICY_FILENAMES = (
    ".agent-circuit-breaker/policy.json",
    "agent-circuit-breaker-policy.json",
)


def load_policy(path: Optional[str] = None, *, start_dir: Optional[str] = None) -> Dict[str, Any]:
    """Load a policy from explicit path, environment, or repository defaults."""
    if path and path.startswith(("https://", "http://")):
        with urlopen(path, timeout=10) as response:  # nosec: caller-selected policy source
            raw = response.read(1024 * 1024).decode("utf-8")
        return _validate_policy(json.loads(raw), path)

    candidates = _policy_candidates(path, start_dir)
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return _validate_policy(json.loads(candidate.read_text(encoding="utf-8")), str(candidate))
    return {"path": None, "profile": None, "mode": None, "rules": None, "strict": False}


def _policy_candidates(path: Optional[str], start_dir: Optional[str]) -> Iterable[Path]:
    if path:
        yield Path(path)
        return

    env_path = os.environ.get("ACB_POLICY")
    if env_path:
        yield Path(env_path)

    root = Path(start_dir or ".").resolve()
    for parent in (root, *root.parents):
        for filename in POLICY_FILENAMES:
            yield parent / filename


def _validate_policy(policy: Dict[str, Any], path: str) -> Dict[str, Any]:
    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")
    allowed = {"profile", "mode", "rules", "strict"}
    for key in policy:
        if key not in allowed:
            raise ValueError(f"unsupported policy field: {key}")
    return {
        "path": path,
        "profile": policy.get("profile"),
        "mode": policy.get("mode"),
        "rules": policy.get("rules"),
        "strict": bool(policy.get("strict", False)),
    }
