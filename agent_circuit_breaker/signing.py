"""Deterministic policy and rule-pack signature helpers."""

import copy
import hashlib
import hmac
import json
import os
from typing import Any, Dict, List


SIGNATURE_FIELD = "signature"
SUPPORTED_ALGORITHMS = ("sha256", "hmac-sha256")


def verify_signed_document(document: Any, *, require_signature: bool = False) -> Dict[str, Any]:
    """Verify an optional detached signature embedded in a JSON document."""
    result: Dict[str, Any] = {
        "is_valid": True,
        "errors": [],
        "signature": None,
    }
    if not isinstance(document, dict):
        result["is_valid"] = False
        result["errors"] = ["signed document must be an object"]
        return result

    signature = document.get(SIGNATURE_FIELD)
    result["signature"] = signature
    if signature is None:
        if require_signature:
            result["is_valid"] = False
            result["errors"] = ["signature is required"]
        return result

    if not isinstance(signature, dict):
        result["is_valid"] = False
        result["errors"] = ["signature must be an object"]
        return result

    algorithm = signature.get("algorithm")
    if algorithm not in SUPPORTED_ALGORITHMS:
        result["is_valid"] = False
        result["errors"] = [f"signature.algorithm must be one of: {', '.join(SUPPORTED_ALGORITHMS)}"]
        return result

    expected = signature.get("digest")
    if not isinstance(expected, str) or not expected.strip():
        result["is_valid"] = False
        result["errors"] = ["signature.digest must be a non-empty string"]
        return result

    errors: List[str] = []
    actual = _digest(document, algorithm, signature, errors)
    if errors:
        result["is_valid"] = False
        result["errors"] = errors
        return result

    if not hmac.compare_digest(expected.lower(), actual.lower()):
        result["is_valid"] = False
        result["errors"] = ["signature verification failed"]

    return result


def sign_document(document: Dict[str, Any], *, algorithm: str = "sha256", key: str = "") -> Dict[str, Any]:
    """Return a copy of a JSON document with a deterministic signature field."""
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"algorithm must be one of: {', '.join(SUPPORTED_ALGORITHMS)}")
    signed = copy.deepcopy(document)
    signature: Dict[str, Any] = {"algorithm": algorithm, "digest": ""}
    if algorithm == "hmac-sha256":
        if not key:
            raise ValueError("hmac-sha256 signing requires a key")
        signature["key_env"] = "ACB_POLICY_HMAC_KEY"
    signed[SIGNATURE_FIELD] = signature
    signature["digest"] = _digest(signed, algorithm, signature, [], key_override=key)
    return signed


def canonical_payload(document: Dict[str, Any]) -> bytes:
    """Canonical JSON bytes excluding the embedded signature field."""
    payload = copy.deepcopy(document)
    payload.pop(SIGNATURE_FIELD, None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def strip_signature(document: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow copy without the signature field."""
    payload = dict(document)
    payload.pop(SIGNATURE_FIELD, None)
    return payload


def _digest(
    document: Dict[str, Any],
    algorithm: str,
    signature: Dict[str, Any],
    errors: List[str],
    *,
    key_override: str = "",
) -> str:
    payload = canonical_payload(document)
    if algorithm == "sha256":
        return hashlib.sha256(payload).hexdigest()

    key = key_override
    if not key:
        key_env = signature.get("key_env")
        if not isinstance(key_env, str) or not key_env.strip():
            errors.append("signature.key_env must be a non-empty string for hmac-sha256")
            return ""
        key = os.environ.get(key_env, "")
        if not key:
            errors.append(f"signature key environment variable is not set: {key_env}")
            return ""
    return hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
