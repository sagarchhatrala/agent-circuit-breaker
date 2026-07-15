"""Demonstrate a local allowlist rule file."""

from pathlib import Path

from agent_circuit_breaker import evaluate_action


RULE_FILE = Path(__file__).with_name("allowlist_rules.json")


def main() -> int:
    """Run the allowlist example."""
    allowed = evaluate_action("git status --short", rule_file_path=str(RULE_FILE))
    blocked = evaluate_action("rm -rf /", rule_file_path=str(RULE_FILE))

    print(f"allowlist_verdict={allowed['verdict']}")
    print(f"allowlist_rule={allowed['matched_rule']}")
    print(f"builtin_block_verdict={blocked['verdict']}")
    print(f"builtin_block_rule={blocked['matched_rule']}")

    return 0 if allowed["verdict"] == "allow" and blocked["verdict"] == "block" else 1


if __name__ == "__main__":
    raise SystemExit(main())
