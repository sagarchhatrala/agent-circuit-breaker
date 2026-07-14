"""Agent Circuit Breaker — Deterministic safety layer for AI agents."""

__version__ = "0.1.0"
__author__ = "Sagar Chhatrala"

from .engine import Engine, Decision, Rule

__all__ = ["Engine", "Decision", "Rule"]
