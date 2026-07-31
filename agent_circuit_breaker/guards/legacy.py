"""Bridge existing deterministic evaluator into the async pipeline."""

from __future__ import annotations

from agent_circuit_breaker.core.context import AgentContext
from agent_circuit_breaker.core.results import GuardResult


class LegacyActionGuard:
    """Run the current battle-tested evaluator as one pipeline guard."""

    guard_id = "legacy_action_guard"

    async def evaluate(self, context: AgentContext) -> GuardResult:
        from agent_circuit_breaker.api import evaluate_action

        action = context.action_text()
        if not action:
            return GuardResult.unknown(self.guard_id, "no action text")

        result = evaluate_action(action)
        verdict = result.get("verdict")
        if verdict in {"block", "error", "pending_approval"}:
            return GuardResult.deny(
                self.guard_id,
                result.get("matched_rule") or result.get("error") or f"legacy verdict {verdict}",
                severity="CRITICAL" if verdict in {"block", "error"} else "HIGH",
                metadata={"legacy_result": result},
            )
        if verdict == "allow":
            return GuardResult.allow(self.guard_id, "legacy evaluator allowed action", {"legacy_result": result})
        return GuardResult.unknown(self.guard_id, "legacy evaluator returned unknown", {"legacy_result": result})
