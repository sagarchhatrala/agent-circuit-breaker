"""
Tests for Agent Circuit Breaker engine.

Tests validate:
- Rule structure and validation
- Engine decision logic
- Error handling and edge cases
- Deterministic behavior
"""

import unittest
from agent_circuit_breaker.engine import Engine, Rule, Decision


class TestDecisionEnum(unittest.TestCase):
    """Test Decision enum."""
    
    def test_decision_values(self):
        """All decision types should be defined."""
        self.assertEqual(Decision.ALLOW.value, "allow")
        self.assertEqual(Decision.BLOCK.value, "block")
        self.assertEqual(Decision.ERROR.value, "error")
        self.assertEqual(Decision.UNKNOWN.value, "unknown")
    
    def test_decision_count(self):
        """Should have exactly 4 decision types."""
        self.assertEqual(len(Decision), 4)


class TestRuleValidation(unittest.TestCase):
    """Test Rule dataclass validation."""
    
    def test_valid_rule_creation(self):
        """Valid rules should be created successfully."""
        rule = Rule(
            id="test_rule",
            title="Test Rule",
            severity="CRITICAL",
            response="block",
            matcher=lambda x: False,
        )
        self.assertEqual(rule.id, "test_rule")
        self.assertEqual(rule.title, "Test Rule")
        self.assertEqual(rule.severity, "CRITICAL")
        self.assertEqual(rule.response, "block")
    
    def test_invalid_id_empty(self):
        """Rule with empty id should raise ValueError."""
        with self.assertRaises(ValueError):
            Rule(
                id="",
                title="Test",
                severity="CRITICAL",
                response="block",
                matcher=lambda x: False,
            )
    
    def test_invalid_title_empty(self):
        """Rule with empty title should raise ValueError."""
        with self.assertRaises(ValueError):
            Rule(
                id="test",
                title="",
                severity="CRITICAL",
                response="block",
                matcher=lambda x: False,
            )
    
    def test_invalid_severity(self):
        """Rule with invalid severity should raise ValueError."""
        with self.assertRaises(ValueError):
            Rule(
                id="test",
                title="Test",
                severity="INVALID",
                response="block",
                matcher=lambda x: False,
            )
    
    def test_valid_severity_values(self):
        """All valid severity levels should be accepted."""
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            rule = Rule(
                id="test",
                title="Test",
                severity=severity,
                response="block",
                matcher=lambda x: False,
            )
            self.assertEqual(rule.severity, severity)
    
    def test_invalid_response(self):
        """Rule with invalid response should raise ValueError."""
        with self.assertRaises(ValueError):
            Rule(
                id="test",
                title="Test",
                severity="CRITICAL",
                response="invalid",
                matcher=lambda x: False,
            )
    
    def test_valid_response_values(self):
        """Valid responses should be accepted."""
        for response in ("allow", "block"):
            rule = Rule(
                id="test",
                title="Test",
                severity="CRITICAL",
                response=response,
                matcher=lambda x: False,
            )
            self.assertEqual(rule.response, response)
    
    def test_matcher_not_callable(self):
        """Rule with non-callable matcher should raise ValueError."""
        with self.assertRaises(ValueError):
            Rule(
                id="test",
                title="Test",
                severity="CRITICAL",
                response="block",
                matcher="not_callable",
            )
    
    def test_metadata_optional(self):
        """Metadata should be optional."""
        rule1 = Rule(
            id="test",
            title="Test",
            severity="CRITICAL",
            response="block",
            matcher=lambda x: False,
        )
        self.assertIsNone(rule1.metadata)
        
        rule2 = Rule(
            id="test",
            title="Test",
            severity="CRITICAL",
            response="block",
            matcher=lambda x: False,
            metadata={"key": "value"},
        )
        self.assertEqual(rule2.metadata["key"], "value")


class TestEngineBasic(unittest.TestCase):
    """Test basic engine functionality."""
    
    def setUp(self):
        """Set up test engine and rules."""
        self.engine = Engine()
        
        self.allow_rule = Rule(
            id="allow_rule",
            title="Allow Rule",
            severity="MEDIUM",
            response="allow",
            matcher=lambda x: "safe" in x,
        )
        
        self.block_rule = Rule(
            id="block_rule",
            title="Block Rule",
            severity="CRITICAL",
            response="block",
            matcher=lambda x: "dangerous" in x,
        )
    
    def test_engine_creation(self):
        """Engine should be created successfully."""
        self.assertIsNotNone(self.engine)
    
    def test_evaluate_with_no_rules(self):
        """Evaluating with no rules should return UNKNOWN."""
        decision, rule = self.engine.evaluate("any action", [])
        self.assertEqual(decision, Decision.UNKNOWN)
        self.assertIsNone(rule)
    
    def test_evaluate_allow_match(self):
        """Matching allow rule should return ALLOW."""
        decision, rule = self.engine.evaluate("this is safe", [self.allow_rule])
        self.assertEqual(decision, Decision.ALLOW)
        self.assertEqual(rule.id, "allow_rule")
    
    def test_evaluate_block_match(self):
        """Matching block rule should return BLOCK."""
        decision, rule = self.engine.evaluate("this is dangerous", [self.block_rule])
        self.assertEqual(decision, Decision.BLOCK)
        self.assertEqual(rule.id, "block_rule")
    
    def test_evaluate_no_match(self):
        """No matching rule should return UNKNOWN."""
        decision, rule = self.engine.evaluate("neutral action", [self.allow_rule, self.block_rule])
        self.assertEqual(decision, Decision.UNKNOWN)
        self.assertIsNone(rule)
    
    def test_evaluate_multiple_rules_first_wins(self):
        """First matching rule should determine decision."""
        decision, rule = self.engine.evaluate(
            "this is dangerous and safe",
            [self.block_rule, self.allow_rule]
        )
        self.assertEqual(decision, Decision.BLOCK)
        self.assertEqual(rule.id, "block_rule")
    
    def test_evaluate_invalid_action_type(self):
        """Non-string action should return ERROR."""
        decision, rule = self.engine.evaluate(123, [self.allow_rule])
        self.assertEqual(decision, Decision.ERROR)
        self.assertIsNone(rule)
    
    def test_evaluate_invalid_rules_type(self):
        """Non-list rules should return ERROR."""
        decision, rule = self.engine.evaluate("action", "not_a_list")
        self.assertEqual(decision, Decision.ERROR)
        self.assertIsNone(rule)
    
    def test_evaluate_invalid_rule_in_list(self):
        """Malformed rule in list should return ERROR."""
        decision, rule = self.engine.evaluate("action", [self.allow_rule, "not_a_rule"])
        self.assertEqual(decision, Decision.ERROR)
        self.assertIsNone(rule)
    
    def test_evaluate_matcher_exception(self):
        """Matcher that raises exception should return ERROR."""
        bad_rule = Rule(
            id="bad_rule",
            title="Bad Rule",
            severity="CRITICAL",
            response="block",
            matcher=lambda x: 1 / 0,  # Division by zero
        )
        decision, rule = self.engine.evaluate("action", [bad_rule])
        self.assertEqual(decision, Decision.ERROR)
        self.assertIsNone(rule)


class TestEngineSafe(unittest.TestCase):
    """Test the safe evaluate method."""
    
    def setUp(self):
        """Set up test engine and rules."""
        self.engine = Engine()
        self.block_rule = Rule(
            id="block_rule",
            title="Block Rule",
            severity="CRITICAL",
            response="block",
            matcher=lambda x: "dangerous" in x,
        )
    
    def test_evaluate_safe_returns_decision(self):
        """Safe evaluate should return just the decision."""
        decision = self.engine.evaluate_safe("this is dangerous", [self.block_rule])
        self.assertEqual(decision, Decision.BLOCK)
        self.assertIsInstance(decision, Decision)
    
    def test_evaluate_safe_no_rule_object(self):
        """Safe evaluate should not return rule object."""
        result = self.engine.evaluate_safe("action", [self.block_rule])
        self.assertIsInstance(result, Decision)


class TestDeterminism(unittest.TestCase):
    """Test that engine decisions are deterministic."""
    
    def setUp(self):
        """Set up test engine and rules."""
        self.engine = Engine()
        self.rule = Rule(
            id="test",
            title="Test",
            severity="CRITICAL",
            response="block",
            matcher=lambda x: "block" in x,
        )
    
    def test_same_action_same_rules_same_decision(self):
        """Same action + rules should produce same decision every time."""
        action = "this should block"
        
        decision1, _ = self.engine.evaluate(action, [self.rule])
        decision2, _ = self.engine.evaluate(action, [self.rule])
        decision3, _ = self.engine.evaluate(action, [self.rule])
        
        self.assertEqual(decision1, decision2)
        self.assertEqual(decision2, decision3)
        self.assertEqual(decision1, Decision.BLOCK)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""
    
    def setUp(self):
        """Set up test engine."""
        self.engine = Engine()
    
    def test_empty_action_string(self):
        """Empty action string should be valid."""
        rule = Rule(
            id="empty_test",
            title="Empty Test",
            severity="MEDIUM",
            response="block",
            matcher=lambda x: x == "",
        )
        decision, rule_match = self.engine.evaluate("", [rule])
        self.assertEqual(decision, Decision.BLOCK)
    
    def test_very_long_action(self):
        """Very long action string should be handled."""
        long_action = "x" * 10000
        rule = Rule(
            id="long_test",
            title="Long Test",
            severity="MEDIUM",
            response="block",
            matcher=lambda x: len(x) > 5000,
        )
        decision, rule_match = self.engine.evaluate(long_action, [rule])
        self.assertEqual(decision, Decision.BLOCK)
    
    def test_special_characters_in_action(self):
        """Action with special characters should be handled."""
        special_action = "rm -rf /home/\x00\x01\x02"
        rule = Rule(
            id="special_test",
            title="Special Test",
            severity="MEDIUM",
            response="block",
            matcher=lambda x: "rm -rf" in x,
        )
        decision, _ = self.engine.evaluate(special_action, [rule])
        self.assertEqual(decision, Decision.BLOCK)


if __name__ == "__main__":
    unittest.main()
