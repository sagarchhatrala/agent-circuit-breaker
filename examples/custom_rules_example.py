"""Example custom rule integration."""

from pathlib import Path

from agent_circuit_breaker import evaluate_action, validate_rule_file


RULE_FILE = Path(__file__).with_name("custom_rules.json")


if __name__ == "__main__":
    validation = validate_rule_file(str(RULE_FILE))
    assert validation["is_valid"] is True

    result = evaluate_action("deploy production", rule_file_path=str(RULE_FILE))
    print(f"custom_rule_verdict={result['verdict']}")
    print(f"matched_rule={result['matched_rule']}")
    assert result["verdict"] == "block"
