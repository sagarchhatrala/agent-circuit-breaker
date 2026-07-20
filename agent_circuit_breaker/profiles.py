"""Safety profiles and policy modes for Agent Circuit Breaker."""

from dataclasses import dataclass
from typing import Any, Dict, Optional


PROFILE_NAMES = ("solo", "repo", "team", "prod")
MODE_NAMES = ("strict", "advisory", "approval")


@dataclass(frozen=True)
class SafetyProfile:
    """Named policy posture for common agent workflows."""

    name: str
    mode: str
    approval_threshold: int
    block_threshold: int
    description: str


PROFILES: Dict[str, SafetyProfile] = {
    "solo": SafetyProfile(
        name="solo",
        mode="advisory",
        approval_threshold=100,
        block_threshold=100,
        description="Low-friction personal mode. Report risk without changing existing decisions.",
    ),
    "repo": SafetyProfile(
        name="repo",
        mode="strict",
        approval_threshold=90,
        block_threshold=90,
        description="Protect source trees, git history, and local filesystem state.",
    ),
    "team": SafetyProfile(
        name="team",
        mode="approval",
        approval_threshold=80,
        block_threshold=100,
        description="Require human approval for high-risk agent actions.",
    ),
    "prod": SafetyProfile(
        name="prod",
        mode="approval",
        approval_threshold=60,
        block_threshold=100,
        description="Production posture. Route medium and high risk actions to approval.",
    ),
}


def get_profile(name: Optional[str]) -> Optional[SafetyProfile]:
    """Return a profile by name, or None when no profile was requested."""
    if name is None:
        return None
    normalized = name.strip().lower()
    if normalized not in PROFILES:
        raise ValueError(f"profile must be one of: {', '.join(PROFILE_NAMES)}")
    return PROFILES[normalized]


def apply_policy_mode(
    result: Dict[str, Any],
    *,
    mode: Optional[str] = None,
    profile: Optional[SafetyProfile] = None,
) -> Dict[str, Any]:
    """
    Apply an optional v1.3 policy mode to an evaluation result.

    Default behavior remains unchanged when neither mode nor profile is supplied.
    """
    if mode is not None:
        selected_mode = mode.strip().lower()
        if selected_mode not in MODE_NAMES:
            raise ValueError(f"mode must be one of: {', '.join(MODE_NAMES)}")
    elif profile is not None:
        selected_mode = profile.mode
    else:
        return result

    policy = {
        "mode": selected_mode,
        "profile": profile.name if profile else None,
        "approval_threshold": profile.approval_threshold if profile else 80,
        "block_threshold": profile.block_threshold if profile else 100,
    }
    result["policy"] = policy

    risk_score = int(result.get("risk_score") or 0)
    original_decision = result.get("decision")
    original_verdict = result.get("verdict")

    if selected_mode == "advisory":
        result["policy"]["original_decision"] = original_decision
        result["policy"]["original_verdict"] = original_verdict
        return result

    if selected_mode == "approval":
        threshold = int(policy["approval_threshold"])
        if original_verdict == "block" and risk_score >= threshold:
            result["decision"] = "PENDING_APPROVAL"
            result["verdict"] = "pending_approval"
            result["policy"]["original_decision"] = original_decision
            result["policy"]["original_verdict"] = original_verdict

    return result


def profile_metadata() -> Dict[str, Any]:
    """Return deterministic profile metadata for docs and integrations."""
    return {
        "profiles": {
            name: {
                "mode": profile.mode,
                "approval_threshold": profile.approval_threshold,
                "block_threshold": profile.block_threshold,
                "description": profile.description,
            }
            for name, profile in sorted(PROFILES.items())
        },
        "modes": list(MODE_NAMES),
    }
