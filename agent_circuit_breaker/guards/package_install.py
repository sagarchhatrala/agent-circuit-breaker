"""Package installation guard."""

from __future__ import annotations

import json
from pathlib import Path
from collections.abc import Iterable as IterableABC
from typing import Any
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
        allowed_transitive_packages: Iterable[str] | None = None,
        lockfile_path: str | None = None,
    ) -> None:
        self.required_index_url = required_index_url
        self.allowed_packages = {package.lower() for package in allowed_packages or ()}
        self.allowed_transitive_packages = {package.lower() for package in allowed_transitive_packages or ()}
        self.lockfile_path = lockfile_path

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
            result = self._evaluate_pip(args)
            if result.verdict == "deny":
                return result
            return self._evaluate_resolved_dependencies(context)
        if binary == "npm" and any(arg.lower() in {"install", "i", "add"} for arg in args):
            result = self._evaluate_npm(args)
            if result.verdict == "deny":
                return result
            return self._evaluate_resolved_dependencies(context)
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

    def _evaluate_resolved_dependencies(self, context: AgentContext) -> GuardResult:
        if not self.allowed_transitive_packages:
            return GuardResult.allow(self.guard_id, "package install passed policy")

        dependencies = _dependency_names(context.tool_args.get("resolved_dependencies"))
        dependencies.extend(_dependency_names(context.tool_args.get("dependencies")))
        if self.lockfile_path:
            dependencies.extend(_dependencies_from_lockfile(self.lockfile_path))
        dependencies = sorted({dependency.lower() for dependency in dependencies if dependency})

        if not dependencies:
            return GuardResult.deny(
                self.guard_id,
                "transitive dependency metadata required",
                "HIGH",
            )

        blocked = [dependency for dependency in dependencies if dependency not in self.allowed_transitive_packages]
        if blocked:
            return GuardResult.deny(
                self.guard_id,
                "transitive dependency is not allowlisted",
                "HIGH",
                {"packages": blocked},
            )
        return GuardResult.allow(self.guard_id, "package install passed transitive dependency policy")


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


def _dependency_names(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [_normalize_package_name(value)]
    if isinstance(value, dict):
        if "name" in value:
            return [_normalize_package_name(str(value["name"]))]
        return [_normalize_package_name(str(name)) for name in value.keys()]
    if isinstance(value, IterableABC):
        names: list[str] = []
        for item in value:
            names.extend(_dependency_names(item))
        return names
    return []


def _dependencies_from_lockfile(path: str) -> list[str]:
    lockfile = Path(path)
    if not lockfile.exists():
        return []
    if lockfile.suffix == ".json" or lockfile.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return _dependencies_from_json_lock(lockfile)
    return _dependencies_from_text_lock(lockfile)


def _dependencies_from_json_lock(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, package_data in packages.items():
            if package_path == "":
                continue
            name = package_data.get("name") if isinstance(package_data, dict) else None
            names.add(_normalize_package_name(str(name or Path(package_path).name)))
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        names.update(_normalize_package_name(str(name)) for name in dependencies.keys())
    return sorted(name for name in names if name)


def _dependencies_from_text_lock(path: Path) -> list[str]:
    names: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        names.add(_normalize_package_name(line))
    return sorted(name for name in names if name)


def _normalize_package_name(value: str) -> str:
    value = value.strip().strip('"').strip("'")
    for separator in ("==", ">=", "<=", "~=", "!=", ">", "<", "@"):
        if separator == "@" and value.startswith("@"):
            continue
        value = value.split(separator, 1)[0]
    if "/" in value and value.startswith("node_modules/"):
        value = value.rsplit("/", 1)[-1]
    return value.lower()
