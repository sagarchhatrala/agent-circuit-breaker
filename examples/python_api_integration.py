"""Example Python API integration."""

from agent_circuit_breaker import evaluate_action


def should_execute(action: str) -> bool:
    """Return true only when Agent Circuit Breaker explicitly allows the action."""
    result = evaluate_action(action)
    print(f"{action!r}: {result['verdict']}")
    return result["verdict"] == "allow"


if __name__ == "__main__":
    assert should_execute("mkdir /tmp/example") is True
    assert should_execute("rm -rf /") is False
    assert should_execute("git status") is False
