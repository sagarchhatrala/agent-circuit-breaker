"""Package installation guard."""

from __future__ import annotations

from typing import Iterable

from agent_circuit_breaker.core.context import AgentContext
from agent_circuit_breaker.core.results import GuardResult
from agent_circuit_breaker.inspectors.command import CommandInspector


class PackageInstallGuard:
    """Enforce package index and package allowlist rules."""

    guard_id = "package_install_guard"

    def __init__(
        self,
        *,
        required_index_url: str | None = None,
        allowed_packages: Iterable[str] | None = None,
    ) -> None:
        self.required_index_url = required_index_url
        self.allowed_packages = {package.lower() for package in allowed_packages or ()}

    async def evaluate(self, context: AgentContext) -> GuardResult:
        command = context.action_text()
        if not command:
            return GuardResult.unknown(self.guard_id, "no package command")

        analysis = CommandInspector.analyze_command(command)
        if not analysis.get("segments"):
            return GuardResult.unknown(self.guard_id, "no package command")

        segment = analysis["segments"][0]
        binary = (segment.get("command") or "").lower()
        args = [str(arg) for arg in segment.get("args", [])]
        if binary == "pip" and "install" in [arg.lower() for arg in args]:
            return self._evaluate_pip(args)
        if binary == "npm" and any(arg.lower() in {"install", "i", "add"} for arg in args):
            return self._evaluate_npm(args)
        return GuardResult.unknown(self.guard_id, "not a package install")

    def _evaluate_pip(self, args: list[str]) -> GuardResult:
        if self.required_index_url:
            index_url = _option_value(args, "--index-url") or _option_value(args, "-i")
            if index_url != self.required_index_url:
                return GuardResult.deny(self.guard_id, "pip install missing required index-url", "HIGH")
        packages = _package_names(args, {"install", "--index-url", "-i", "--extra-index-url", "-r", "--requirement"})
        return self._check_packages(packages)

    def _evaluate_npm(self, args: list[str]) -> GuardResult:
        packages = _package_names(args, {"install", "i", "add", "--registry"})
        return self._check_packages(packages)

    def _check_packages(self, packages: list[str]) -> GuardResult:
        if self.allowed_packages:
            blocked = [package for package in packages if package.lower() not in self.allowed_packages]
            if blocked:
                return GuardResult.deny(
                    self.guard_id,
                    "package is not allowlisted",
                    "HIGH",
                    {"packages": blocked},
                )
        return GuardResult.allow(self.guard_id, "package install passed policy")


def _option_value(args: list[str], option: str) -> str | None:
    for index, arg in enumerate(args):
        if arg == option and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith(f"{option}="):
            return arg.split("=", 1)[1]
    return None


def _package_names(args: list[str], reserved: set[str]) -> list[str]:
    packages: list[str] = []
    skip_next = False
    options_with_values = {"--index-url", "-i", "--extra-index-url", "-r", "--requirement", "--registry"}
    for arg in args:
        lower = arg.lower()
        if skip_next:
            skip_next = False
            continue
        if lower in options_with_values:
            skip_next = True
            continue
        if lower in reserved or lower.startswith("-"):
            continue
        packages.append(arg.split("==", 1)[0].split("@", 1)[0])
    return packages
