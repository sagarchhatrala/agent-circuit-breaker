"""Central policy loading and precedence helpers."""

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.request import urlopen

from agent_circuit_breaker.limits import MAX_POLICY_FILE_BYTES, ensure_file_within_limit
from agent_circuit_breaker.rules.loader import RuleFileLoader
from agent_circuit_breaker.signing import strip_signature, verify_signed_document


POLICY_FILENAMES = (
    ".agent-circuit-breaker/policy.json",
    "agent-circuit-breaker-policy.json",
)
SOURCE_DEFAULTS = "defaults"
SOURCE_EXPLICIT = "explicit"
SOURCE_ENVIRONMENT = "environment"
SOURCE_REPOSITORY = "repository"
SOURCE_REMOTE = "remote"
TRUST_CALLER_SELECTED = "caller_selected"
TRUST_REPOSITORY = "repository"
TRUST_DEFAULTS = "defaults"


def load_policy(
    path: Optional[str] = None,
    *,
    start_dir: Optional[str] = None,
    require_signature: bool = False,
    trust_repository_policy: bool = False,
    allow_insecure_remote_policy: bool = False,
) -> Dict[str, Any]:
    """Load a policy from explicit path, environment, or repository defaults."""
    if path and path.startswith(("https://", "http://")):
        if path.startswith("http://") and not allow_insecure_remote_policy:
            raise ValueError(
                "insecure remote policy transport is disabled by default; "
                "use HTTPS or explicitly allow insecure remote policy loading"
            )
        with urlopen(path, timeout=10) as response:  # nosec: caller-selected policy source
            raw_bytes = response.read(MAX_POLICY_FILE_BYTES + 1)
        if len(raw_bytes) > MAX_POLICY_FILE_BYTES:
            raise ValueError(f"remote policy exceeds {MAX_POLICY_FILE_BYTES} bytes")
        raw = raw_bytes.decode("utf-8")
        return _validate_policy(
            json.loads(raw),
            path,
            source_type=SOURCE_REMOTE,
            require_signature=require_signature,
            trust_repository_policy=trust_repository_policy,
        )

    candidates = _policy_candidates(path, start_dir)
    for candidate, source_type in candidates:
        if candidate.exists() and candidate.is_file():
            ensure_file_within_limit(candidate, MAX_POLICY_FILE_BYTES, "policy file")
            return _validate_policy(
                json.loads(candidate.read_text(encoding="utf-8")),
                str(candidate),
                source_type=source_type,
                require_signature=require_signature,
                trust_repository_policy=trust_repository_policy,
            )
    return {
        "path": None,
        "source_type": SOURCE_DEFAULTS,
        "trust_level": TRUST_DEFAULTS,
        "trusted": True,
        "profile": None,
        "mode": None,
        "rules": None,
        "rules_path": None,
        "rules_definition": None,
        "strict": False,
        "signature": None,
        "trust_errors": [],
    }


def _policy_candidates(path: Optional[str], start_dir: Optional[str]) -> Iterable[tuple[Path, str]]:
    if path:
        yield Path(path), SOURCE_EXPLICIT
        return

    env_path = os.environ.get("ACB_POLICY")
    if env_path:
        yield Path(env_path), SOURCE_ENVIRONMENT

    root = Path(start_dir or ".").resolve()
    for parent in (root, *root.parents):
        for filename in POLICY_FILENAMES:
            yield parent / filename, SOURCE_REPOSITORY


def _validate_policy(
    policy: Dict[str, Any],
    path: str,
    *,
    source_type: str,
    require_signature: bool = False,
    trust_repository_policy: bool = False,
) -> Dict[str, Any]:
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
    trust_level = _trust_level(source_type, trust_repository_policy)
    trusted = trust_level != TRUST_REPOSITORY or trust_repository_policy
    trust_errors = _repository_policy_trust_errors(
        policy,
        path,
        rules_path,
        rules_definition,
        require_signature=require_signature,
    )
    if source_type == SOURCE_REPOSITORY and not trust_repository_policy and trust_errors:
        raise ValueError("; ".join(trust_errors))
    return {
        "path": path,
        "source_type": source_type,
        "trust_level": trust_level,
        "trusted": trusted,
        "profile": policy.get("profile"),
        "mode": policy.get("mode"),
        "rules": rules_path if rules_path is not None else rules_definition,
        "rules_path": rules_path,
        "rules_definition": rules_definition,
        "strict": bool(policy.get("strict", False)),
        "signature": signature_result["signature"],
        "trust_errors": [],
    }


def _resolve_relative_policy_path(policy_path: str, rules_path: str) -> str:
    if policy_path.startswith(("https://", "http://")):
        return rules_path
    candidate = Path(rules_path)
    if candidate.is_absolute():
        return str(candidate)
    return str((Path(policy_path).parent / candidate).resolve())


def _trust_level(source_type: str, trust_repository_policy: bool) -> str:
    if source_type == SOURCE_REPOSITORY:
        return TRUST_CALLER_SELECTED if trust_repository_policy else TRUST_REPOSITORY
    if source_type == SOURCE_DEFAULTS:
        return TRUST_DEFAULTS
    return TRUST_CALLER_SELECTED


def _repository_policy_trust_errors(
    policy: Dict[str, Any],
    policy_path: str,
    rules_path: Optional[str],
    rules_definition: Optional[Dict[str, Any]],
    *,
    require_signature: bool,
) -> list[str]:
    """Return weakening-policy errors for auto-discovered repository policy."""
    errors: list[str] = []

    if policy.get("profile") == "solo":
        errors.append("untrusted repository policy cannot select solo profile")

    if policy.get("mode") == "advisory":
        errors.append("untrusted repository policy cannot select advisory mode")

    if "strict" in policy and policy.get("strict") is not True:
        errors.append("untrusted repository policy cannot disable strict mode")

    definition = rules_definition
    if definition is None and rules_path:
        loaded = RuleFileLoader.load(rules_path, require_signature=require_signature)
        if loaded["is_valid"]:
            definition = loaded["definition"]

    if definition and _rule_definition_has_allow_rules(definition):
        errors.append("untrusted repository policy cannot add allow rules")

    return errors


def _rule_definition_has_allow_rules(definition: Dict[str, Any]) -> bool:
    rules = definition.get("rules")
    if not isinstance(rules, list):
        return False
    return any(isinstance(rule, dict) and rule.get("response") == "allow" for rule in rules)
