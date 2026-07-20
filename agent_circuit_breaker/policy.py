"""Central policy loading and precedence helpers."""

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.request import urlopen

from agent_circuit_breaker.signing import strip_signature, verify_signed_document


POLICY_FILENAMES = (
    ".agent-circuit-breaker/policy.json",
    "agent-circuit-breaker-policy.json",
)


def load_policy(
    path: Optional[str] = None,
    *,
    start_dir: Optional[str] = None,
    require_signature: bool = False,
) -> Dict[str, Any]:
    """Load a policy from explicit path, environment, or repository defaults."""
    if path and path.startswith(("https://", "http://")):
        with urlopen(path, timeout=10) as response:  # nosec: caller-selected policy source
            raw = response.read(1024 * 1024).decode("utf-8")
        return _validate_policy(json.loads(raw), path, require_signature=require_signature)

    candidates = _policy_candidates(path, start_dir)
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return _validate_policy(
                json.loads(candidate.read_text(encoding="utf-8")),
                str(candidate),
                require_signature=require_signature,
            )
    return {
        "path": None,
        "profile": None,
        "mode": None,
        "rules": None,
        "rules_path": None,
        "rules_definition": None,
        "strict": False,
        "signature": None,
    }


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


def _validate_policy(policy: Dict[str, Any], path: str, *, require_signature: bool = False) -> Dict[str, Any]:
    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")
    signature_result = verify_signed_document(policy, require_signature=require_signature)
    if not signature_result["is_valid"]:
        raise ValueError("; ".join(signature_result["errors"]))
    policy = strip_signature(policy)

    allowed = {"profile", "mode", "rules", "rule_file", "strict"}
    for key in policy:
        if key not in allowed:
            raise ValueError(f"unsupported policy field: {key}")
    rules_value = policy.get("rules")
    rules_path = policy.get("rule_file")
    rules_definition = None
    if rules_value is not None:
        if isinstance(rules_value, str):
            rules_path = _resolve_relative_policy_path(path, rules_value)
        elif isinstance(rules_value, dict):
            rules_definition = rules_value
        else:
            raise ValueError("policy.rules must be a rule-file path string or inline rule definition object")
    if rules_path is not None and not isinstance(rules_path, str):
        raise ValueError("policy.rule_file must be a string")
    return {
        "path": path,
        "profile": policy.get("profile"),
        "mode": policy.get("mode"),
        "rules": rules_path if rules_path is not None else rules_definition,
        "rules_path": rules_path,
        "rules_definition": rules_definition,
        "strict": bool(policy.get("strict", False)),
        "signature": signature_result["signature"],
    }


def _resolve_relative_policy_path(policy_path: str, rules_path: str) -> str:
    if policy_path.startswith(("https://", "http://")):
        return rules_path
    candidate = Path(rules_path)
    if candidate.is_absolute():
        return str(candidate)
    return str((Path(policy_path).parent / candidate).resolve())
