"""Shell command gatekeeper guard."""

from __future__ import annotations

from typing import Iterable, Set

from agent_circuit_breaker.core.context import AgentContext
from agent_circuit_breaker.core.results import GuardResult
from agent_circuit_breaker.inspectors.command import CommandInspector


class ShellGuard:
    """Deterministic shell command guard using the local command lexer."""

    guard_id = "shell_guard"

    def __init__(
        self,
        *,
        allowed_binaries: Iterable[str] | None = None,
        denied_binaries: Iterable[str] | None = None,
        allowed_operators: Iterable[str] = (),
    ) -> None:
        self.allowed_binaries = {item.lower() for item in allowed_binaries or ()}
        self.denied_binaries = {item.lower() for item in denied_binaries or {"sh", "bash", "pwsh", "powershell", "cmd"}}
        self.allowed_operators = set(allowed_operators)

    async def evaluate(self, context: AgentContext) -> GuardResult:
        command = _command_text(context)
        if not command:
            return GuardResult.unknown(self.guard_id, "no shell command")

        analysis = CommandInspector.analyze_command(command)
        if not analysis.get("is_valid"):
            return GuardResult.deny(self.guard_id, analysis.get("error") or "invalid shell command", "HIGH")

        blocked_operator = next((op for op in analysis.get("operators", []) if op not in self.allowed_operators), None)
        if blocked_operator:
            return GuardResult.deny(
                self.guard_id,
                f"shell operator {blocked_operator!r} is not allowed",
                "HIGH",
                {"operator": blocked_operator},
            )

        for segment in analysis.get("segments", []):
            binary = (segment.get("command") or "").lower()
            args = [str(arg).lower() for arg in segment.get("args", [])]
            if self.allowed_binaries and binary not in self.allowed_binaries:
                return GuardResult.deny(self.guard_id, f"binary {binary!r} is not allowlisted", "HIGH")
            if binary in self.denied_binaries:
                return GuardResult.deny(self.guard_id, f"binary {binary!r} is denied", "HIGH")
            if binary == "rm" and _has_rm_recursive_force(args):
                return GuardResult.deny(self.guard_id, "recursive forced rm is denied", "CRITICAL")
            if binary == "git" and "push" in args and any(arg in {"--force", "-f", "--force-with-lease"} for arg in args):
                return GuardResult.deny(self.guard_id, "forced git push is denied", "HIGH")

        return GuardResult.allow(self.guard_id, "shell command passed shell guard")


def _command_text(context: AgentContext) -> str:
    if context.tool_name.lower() in {"shell", "bash", "command", "cmd", "powershell"}:
        return context.action_text()
    value = context.tool_args.get("command")
    return value if isinstance(value, str) else ""


def _has_rm_recursive_force(args: list[str]) -> bool:
    recursive = any(arg in {"-r", "-R", "--recursive"} or (arg.startswith("-") and "r" in arg.lower()) for arg in args)
    force = any(arg in {"-f", "--force"} or (arg.startswith("-") and "f" in arg.lower()) for arg in args)
    return recursive and force
