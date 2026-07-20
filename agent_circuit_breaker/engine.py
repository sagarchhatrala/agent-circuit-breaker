"""
Engine - Core decision logic for Agent Circuit Breaker.

The engine receives an action and a rule set, then returns a deterministic decision.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Any, Optional

from agent_circuit_breaker.normalization import normalize_for_matching


class Decision(Enum):
    """Possible engine decisions."""
    ALLOW = "allow"
    BLOCK = "block"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class Rule:
    """
    Declarative safety rule.
    
    A rule describes when an action should be blocked or allowed.
    """
    
    id: str
    """Unique rule identifier (e.g., 'fs_recursive_delete')"""
    
    title: str
    """Human-readable title (e.g., 'Recursive filesystem deletion detected')"""
    
    severity: str
    """Severity level (CRITICAL, HIGH, MEDIUM, LOW)"""
    
    response: str
    """Response action (allow or block)"""
    
    matcher: Callable[[str], bool]
    """
    Matcher function that evaluates the action.
    Returns True if the rule matches the action.
    """
    
    metadata: Optional[dict] = None
    """Optional metadata (e.g., created_date, maintainer, references)"""
    
    def __post_init__(self) -> None:
        """Validate rule structure."""
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValueError("Rule id must be a non-empty string")
        
        if not isinstance(self.title, str) or not self.title.strip():
            raise ValueError("Rule title must be a non-empty string")
        
        if self.severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            raise ValueError(f"Rule severity must be one of (CRITICAL, HIGH, MEDIUM, LOW), got: {self.severity}")
        
        if self.response not in ("allow", "block"):
            raise ValueError(f"Rule response must be 'allow' or 'block', got: {self.response}")
        
        if not callable(self.matcher):
            raise ValueError("Rule matcher must be callable")


class Engine:
    """
    Decision engine.
    
    Evaluates an action against a rule set and returns a deterministic decision.
    """
    
    def evaluate(self, action: str, rules: List[Rule]) -> tuple[Decision, Optional[Rule]]:
        """
        Evaluate an action against a rule set.
        
        Returns:
            (decision, matching_rule): Tuple of (Decision, Rule that matched or None)
        
        Rules are evaluated in order. First matching rule determines the decision.
        If no rules match, returns UNKNOWN.
        
        Raises:
            ValueError: If action is not a string or rules list is invalid
            TypeError: If a rule matcher raises an unexpected exception
        """
        
        # Validate inputs
        if not isinstance(action, str):
            return Decision.ERROR, None
        
        if not isinstance(rules, list):
            return Decision.ERROR, None
        
        if not rules:
            # No rules provided - nothing to evaluate against
            return Decision.UNKNOWN, None

        try:
            normalized_action = normalize_for_matching(action)
        except ValueError:
            return Decision.ERROR, None
        
        # Evaluate each rule in order
        for rule in rules:
            if not isinstance(rule, Rule):
                # Malformed rule in list
                return Decision.ERROR, None
            
            try:
                # Call the matcher function
                if rule.matcher(normalized_action):
                    # Rule matched - return the decision based on rule response
                    if rule.response == "block":
                        return Decision.BLOCK, rule
                    elif rule.response == "allow":
                        return Decision.ALLOW, rule
            
            except Exception as e:
                # Matcher raised an exception - treat as error
                # This prevents silent failures
                return Decision.ERROR, None
        
        # No rules matched
        return Decision.UNKNOWN, None
    
    def evaluate_safe(self, action: str, rules: List[Rule]) -> Decision:
        """
        Simplified evaluate that returns just the decision.
        
        Useful for simple scenarios where you don't need the matching rule details.
        """
        decision, _ = self.evaluate(action, rules)
        return decision
