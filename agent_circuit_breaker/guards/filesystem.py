"""Filesystem path canonicalization guard."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Mapping

from agent_circuit_breaker.core.context import AgentContext
from agent_circuit_breaker.core.results import GuardResult
from agent_circuit_breaker.inspectors.filesystem import FilesystemInspector


class FilesystemGuard:
    """Enforce directory permissions and file extension quarantine."""

    guard_id = "filesystem_guard"

    def __init__(
        self,
        permissions: Mapping[str, Iterable[str]] | None = None,
        *,
        allowed_extensions: Iterable[str] | None = None,
        blocked_extensions: Iterable[str] | None = None,
    ) -> None:
        self.permissions = {
            os.path.realpath(path): {perm.lower() for perm in perms}
            for path, perms in (permissions or {}).items()
        }
        self.allowed_extensions = _normalize_extensions(allowed_extensions)
        self.blocked_extensions = _normalize_extensions(blocked_extensions or {".sh", ".ps1", ".bat", ".cmd"})

    async def evaluate(self, context: AgentContext) -> GuardResult:
        paths = _paths_from_context(context)
        if not paths:
            return GuardResult.unknown(self.guard_id, "no filesystem path")

        operation = _operation_from_context(context)
        for path in paths:
            canonical = os.path.realpath(path)
            extension = Path(canonical).suffix.lower()
            if extension in self.blocked_extensions:
                return GuardResult.deny(self.guard_id, f"file extension {extension} is quarantined", "HIGH")
            if self.allowed_extensions and extension and extension not in self.allowed_extensions:
                return GuardResult.deny(self.guard_id, f"file extension {extension} is not allowlisted", "MEDIUM")
            if self.permissions and not self._is_permitted(canonical, operation):
                return GuardResult.deny(
                    self.guard_id,
                    f"{operation} is not permitted for {canonical}",
                    "HIGH",
                    {"path": canonical, "operation": operation},
                )

        return GuardResult.allow(self.guard_id, "filesystem paths passed policy")

    def _is_permitted(self, canonical: str, operation: str) -> bool:
        for root, perms in self.permissions.items():
            if canonical == root or canonical.startswith(root + os.sep):
                return operation in perms
        return False


def _paths_from_context(context: AgentContext) -> list[str]:
    raw_paths = context.tool_args.get("paths")
    if isinstance(raw_paths, list):
        return [str(path) for path in raw_paths]
    raw_path = context.tool_args.get("path")
    if isinstance(raw_path, str):
        return [raw_path]

    command = context.action_text()
    if not command:
        return []
    operation = FilesystemInspector.analyze_operation(command)
    return [str(path) for path in operation.get("targets", [])]


def _operation_from_context(context: AgentContext) -> str:
    value = context.tool_args.get("operation")
    if isinstance(value, str):
        return value.lower()
    command = context.action_text()
    if command:
        operation = FilesystemInspector.analyze_operation(command).get("operation")
        if operation in {"create_file", "create_dir", "copy", "move", "chmod", "delete"}:
            return "write" if operation != "delete" else "write"
    return "read"


def _normalize_extensions(values: Iterable[str] | None) -> set[str]:
    return {value.lower() if value.startswith(".") else f".{value.lower()}" for value in values or ()}
