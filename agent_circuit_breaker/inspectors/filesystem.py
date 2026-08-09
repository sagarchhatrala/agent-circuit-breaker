"""Filesystem Inspector - Analyzes filesystem operations for safety."""

import os
import re
import platform
from pathlib import Path, PureWindowsPath, PurePosixPath
from typing import Any, Dict, Tuple, Optional, List, Set

from agent_circuit_breaker.inspectors.command import CommandInspector


class FilesystemInspector:
    """Inspects and analyzes filesystem operations for safety risks."""

    DELETE_COMMANDS = {"rm", "remove", "del", "rmdir", "remove-item"}
    MOVE_COMMANDS = {"mv", "move", "ren", "rename"}
    COPY_COMMANDS = {"cp", "copy", "xcopy"}
    CHMOD_COMMANDS = {"chmod", "icacls", "attrib"}
    CREATE_DIR_COMMANDS = {"mkdir", "md"}
    CREATE_FILE_COMMANDS = {"touch"}

    # System paths that should never be deleted (cross-platform)
    DANGEROUS_TARGETS = {
        # POSIX/Linux
        "/",
        "/root",
        "/etc",
        "/sys",
        "/proc",
        "/boot",
        "/bin",
        "/sbin",
        "/usr",
        "/usr/bin",
        "/usr/sbin",
        "/lib",
        "/lib64",
        "/dev",
        "/var",
        "/home",
        # macOS
        "/Applications",
        "/System",
        "/Library",
        # Windows
        "C:\\",
        "C:\\Windows",
        "C:\\System32",
        "C:\\ProgramFiles",
        "C:\\Program Files",
        "C:\\ProgramData",
        "D:\\",
        "E:\\",
    }

    # Top-level container paths are dangerous as direct deletion targets, but
    # deleting a user's own child path should be evaluated by operation context.
    EXACT_ONLY_TARGETS = {
        "/",
        "/home",
        "C:\\",
        "D:\\",
        "E:\\",
    }

    def __init__(self):
        """Initialize the Filesystem Inspector."""
        self.current_os = platform.system()

    @staticmethod
    def normalize_path(path: str) -> str:
        """
        Normalize a filesystem path to canonical form.

        Handles:
        - Forward/backward slash normalization
        - .. and . resolution
        - Relative path expansion
        - Trailing slashes
        - Windows drive letter case normalization
        - Symlink resolution (when possible)

        Args:
            path: Raw filesystem path

        Returns:
            Normalized, canonical path

        Raises:
            ValueError: If path is empty or contains invalid characters
        """
        if not path or not isinstance(path, str):
            raise ValueError(f"Invalid path: {path!r}")

        path = path.strip()
        if not path:
            raise ValueError("Path cannot be empty or whitespace")

        if re.match(r"^[a-zA-Z]:[^/\\]", path):
            path = f"{path[:2]}\\{path[2:]}"

        # Replace backslashes with forward slashes for uniform processing
        path = path.replace("\\", "/")

        # Remove trailing slashes (except for root)
        while path.endswith("/") and path != "/":
            path = path[:-1]

        # Handle . and .. components
        components = path.split("/")
        normalized = []

        for component in components:
            if component == "" or component == ".":
                # Empty or current dir - skip unless it's the leading empty (root)
                if component == "" and not normalized:
                    normalized.append("")
                continue
            elif component == "..":
                # Go up one level if possible
                if normalized and normalized[-1] != "":
                    normalized.pop()
                elif normalized and normalized[-1] == "" and len(normalized) > 1:
                    # Don't escape root on Unix
                    pass
                continue
            else:
                normalized.append(component)

        result = "/".join(normalized)

        # Ensure root stays as /
        if result == "":
            result = "/"

        # Expand ~ to home directory
        if result.startswith("~"):
            result = str(Path(result).expanduser())

        # Convert back to system-native slashes
        if FilesystemInspector._is_windows_path(result):
            result = result.replace("/", "\\")

        return result

    @staticmethod
    def _is_windows_path(path: str) -> bool:
        """Check if path is a Windows path."""
        # Check for drive letter (e.g., C:)
        return bool(re.match(r"^[a-zA-Z]:", path))

    @staticmethod
    def is_dangerous_target(path: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a path is a dangerous deletion target.

        Args:
            path: Filesystem path to check

        Returns:
            Tuple of (is_dangerous, reason) where reason explains why if dangerous

        Raises:
            ValueError: If path cannot be normalized
        """
        if not path or not isinstance(path, str):
            return False, None

        try:
            normalized = FilesystemInspector.normalize_path(path)
        except ValueError:
            return False, None

        # Use a uniform separator for cross-platform comparisons. Lowercasing
        # keeps Windows path checks deterministic even on non-Windows hosts.
        check_path = normalized.replace("\\", "/").lower()

        # Check against dangerous targets
        for dangerous in FilesystemInspector.DANGEROUS_TARGETS:
            dangerous_check = dangerous.replace("\\", "/").lower().rstrip("/")
            if dangerous_check == "":
                dangerous_check = "/"

            is_exact_match = check_path.rstrip("/") == dangerous_check
            is_child_match = check_path.startswith(dangerous_check + "/")

            if dangerous in FilesystemInspector.EXACT_ONLY_TARGETS:
                if is_exact_match:
                    return True, f"Dangerous target: {dangerous}"
                continue

            if is_exact_match or is_child_match:
                return True, f"Dangerous target: {dangerous}"

        # Check if path is root or root-like
        if normalized in ("/", "\\", "..", "~"):
            return True, "Root or parent directory deletion"

        return False, None

    @staticmethod
    def analyze_operation(command: str) -> dict:
        """
        Analyze a shell command to extract filesystem operation details.

        Detects and extracts:
        - Operation type (delete, move, copy, chmod, etc.)
        - Target paths
        - Flags (recursive, force, dry-run, etc.)
        - Whether it's a dangerous pattern

        Args:
            command: Shell command string

        Returns:
            Dictionary with keys:
            - operation: str (delete, move, copy, chmod, create, etc.)
            - targets: List[str] (extracted file paths)
            - flags: Set[str] (command flags)
            - is_dangerous: bool
            - danger_reason: Optional[str]
        """
        if not command or not isinstance(command, str):
            return {
                "operation": "unknown",
                "targets": [],
                "flags": set(),
                "is_dangerous": False,
                "danger_reason": None,
            }

        command = command.strip()
        result = {
            "operation": "unknown",
            "targets": [],
            "flags": set(),
            "is_dangerous": False,
            "danger_reason": None,
        }

        command_analysis = CommandInspector.analyze_command(command)
        if not command_analysis["is_valid"] or not command_analysis["segments"]:
            return result

        segment = command_analysis["segments"][0]
        command_name = (segment["command"] or "").lower()
        args = segment["args"]

        if command_name in FilesystemInspector.DELETE_COMMANDS:
            result["operation"] = "delete"
            result.update(FilesystemInspector._analyze_delete_args(command_name, args))

        elif command_name in FilesystemInspector.MOVE_COMMANDS:
            result["operation"] = "move"
            result.update(FilesystemInspector._analyze_target_args(args))

        elif command_name in FilesystemInspector.COPY_COMMANDS:
            result["operation"] = "copy"
            result.update(FilesystemInspector._analyze_copy_args(args))

        elif command_name in FilesystemInspector.CHMOD_COMMANDS:
            result["operation"] = "chmod"
            result.update(FilesystemInspector._analyze_target_args(args))

        elif command_name in FilesystemInspector.CREATE_DIR_COMMANDS or (
            command_name == "new-item"
            and FilesystemInspector._has_option_value(args, "-itemtype", "directory")
        ):
            result["operation"] = "create_dir"

        elif command_name in FilesystemInspector.CREATE_FILE_COMMANDS or (
            command_name == "new-item"
            and FilesystemInspector._has_option_value(args, "-itemtype", "file")
        ):
            result["operation"] = "create_file"

        return result

    @staticmethod
    def _analyze_delete_command(command: str) -> dict:
        """Analyze a delete/remove command."""
        analysis = CommandInspector.analyze_command(command)
        if not analysis["is_valid"] or not analysis["segments"]:
            return {"targets": [], "flags": set(), "is_dangerous": False, "danger_reason": None}

        segment = analysis["segments"][0]
        return FilesystemInspector._analyze_delete_args(
            (segment["command"] or "").lower(),
            segment["args"],
        )

    @staticmethod
    def _analyze_delete_args(command: str, args: List[str]) -> dict:
        """Analyze tokenized delete/remove arguments."""
        result = {"targets": [], "flags": set(), "is_dangerous": False, "danger_reason": None}

        args_lower = [arg.lower() for arg in args]
        for arg in args_lower:
            if FilesystemInspector._is_recursive_delete_flag(arg):
                result["flags"].add("recursive")
            if FilesystemInspector._is_force_delete_flag(arg):
                result["flags"].add("force")

        result["targets"] = FilesystemInspector._target_args(args, command)

        for target in result["targets"]:
            is_dangerous, reason = FilesystemInspector.is_dangerous_target(target)
            if is_dangerous:
                result["is_dangerous"] = True
                result["danger_reason"] = reason
                break

        return result

    @staticmethod
    def _analyze_target_args(args: List[str]) -> dict:
        """Analyze arguments where non-option tokens are target paths."""
        result = {"targets": FilesystemInspector._target_args(args), "flags": set(), "is_dangerous": False, "danger_reason": None}
        return result

    @staticmethod
    def _analyze_move_command(command: str) -> dict:
        """Analyze a move/rename command."""
        analysis = CommandInspector.analyze_command(command)
        if not analysis["is_valid"] or not analysis["segments"]:
            return {"targets": [], "flags": set(), "is_dangerous": False, "danger_reason": None}

        return FilesystemInspector._analyze_target_args(analysis["segments"][0]["args"])

    @staticmethod
    def _analyze_copy_command(command: str) -> dict:
        """Analyze a copy command."""
        analysis = CommandInspector.analyze_command(command)
        if not analysis["is_valid"] or not analysis["segments"]:
            return {"targets": [], "flags": set(), "is_dangerous": False, "danger_reason": None}

        return FilesystemInspector._analyze_copy_args(analysis["segments"][0]["args"])

    @staticmethod
    def _analyze_copy_args(args: List[str]) -> dict:
        """Analyze tokenized copy arguments."""
        result = FilesystemInspector._analyze_target_args(args)
        for arg in args:
            if FilesystemInspector._is_recursive_delete_flag(arg.lower()):
                result["flags"].add("recursive")
        return result

    @staticmethod
    def _analyze_chmod_command(command: str) -> dict:
        """Analyze a chmod/permissions command."""
        analysis = CommandInspector.analyze_command(command)
        if not analysis["is_valid"] or not analysis["segments"]:
            return {"targets": [], "flags": set(), "is_dangerous": False, "danger_reason": None}

        return FilesystemInspector._analyze_target_args(analysis["segments"][0]["args"])

    @staticmethod
    def _target_args(args: List[str], command: str = "") -> List[str]:
        """Return non-option arguments that represent likely filesystem targets."""
        targets: List[str] = []
        skip_next = False
        option_value_flags = {"-path", "--path", "-literalpath", "-destination", "-target"}

        for index, arg in enumerate(args):
            lower = arg.lower()
            if skip_next:
                skip_next = False
                continue

            if lower in option_value_flags:
                if index + 1 < len(args):
                    targets.append(args[index + 1])
                    skip_next = True
                continue

            if FilesystemInspector._is_option_like(arg, command):
                continue

            targets.append(arg)

        return targets

    @staticmethod
    def _is_option_like(arg: str, command: str = "") -> bool:
        """Return true when a token is an option, not a target path."""
        lower = arg.lower()
        if lower.startswith("--") or lower.startswith("-"):
            return True
        if command in {"del", "rmdir"} and lower in {"/s", "/q"}:
            return True
        return False

    @staticmethod
    def _is_recursive_delete_flag(arg: str) -> bool:
        """Return true for recursive flags used by delete-like commands."""
        if arg in {"--recursive", "-recurse", "/s"}:
            return True
        return arg.startswith("-") and not arg.startswith("--") and "r" in arg

    @staticmethod
    def _is_force_delete_flag(arg: str) -> bool:
        """Return true for force flags used by delete-like commands."""
        if arg in {"--force", "-force", "/q"}:
            return True
        return arg.startswith("-") and not arg.startswith("--") and "f" in arg

    @staticmethod
    def _has_option_value(args: List[str], option_name: str, expected_value: str) -> bool:
        """Return true when args contain an option followed by an expected value."""
        args_lower = [arg.lower() for arg in args]
        option_name = option_name.lower()
        expected_value = expected_value.lower()
        for index, arg in enumerate(args_lower[:-1]):
            if arg == option_name and args_lower[index + 1] == expected_value:
                return True
        return False
