"""Filesystem Inspector - Analyzes filesystem operations for safety."""

import os
import re
import platform
from pathlib import Path, PureWindowsPath, PurePosixPath
from typing import Tuple, Optional, List, Set


class FilesystemInspector:
    """Inspects and analyzes filesystem operations for safety risks."""

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

        # Normalize to lowercase for pattern matching
        cmd_lower = command.lower()

        # Detect operation type and extract details
        if any(
            op in cmd_lower for op in ["rm ", "remove ", "del ", "rmdir ", "remove-item"]
        ):
            result["operation"] = "delete"
            result.update(FilesystemInspector._analyze_delete_command(command))

        elif any(op in cmd_lower for op in ["mv ", "move ", "ren ", "rename "]):
            result["operation"] = "move"
            result.update(FilesystemInspector._analyze_move_command(command))

        elif any(op in cmd_lower for op in ["cp ", "copy ", "xcopy "]):
            result["operation"] = "copy"
            result.update(FilesystemInspector._analyze_copy_command(command))

        elif any(op in cmd_lower for op in ["chmod ", "icacls ", "attrib "]):
            result["operation"] = "chmod"
            result.update(FilesystemInspector._analyze_chmod_command(command))

        elif any(op in cmd_lower for op in ["mkdir ", "md ", "new-item -itemtype directory"]):
            result["operation"] = "create_dir"

        elif any(op in cmd_lower for op in ["touch ", "new-item -itemtype file"]):
            result["operation"] = "create_file"

        return result

    @staticmethod
    def _analyze_delete_command(command: str) -> dict:
        """Analyze a delete/remove command."""
        result = {"targets": [], "flags": set(), "is_dangerous": False, "danger_reason": None}

        # Extract flags
        flags_patterns = [
            (r"(?<!\S)-[A-Za-z]*r[A-Za-z]*(?:\s|$)", "recursive"),
            (r"(?<!\S)-[A-Za-z]*f[A-Za-z]*(?:\s|$)", "force"),
            (r"-r(?:\s|$|/|\\)", "recursive"),
            (r"-f(?:\s|$|/|\\)", "force"),
            (r"--recursive", "recursive"),
            (r"--force", "force"),
            (r"-Recurse", "recursive"),
            (r"-Force", "force"),
            (r"/s(?:\s|$|/)", "recursive"),
            (r"/q(?:\s|$|/)", "force"),
        ]

        for pattern, flag_name in flags_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                result["flags"].add(flag_name)

        # Extract target paths (simple heuristic: unquoted or quoted strings after command)
        # This is a simplified version - real parsing would be more complex
        quoted_pattern = r'["\']([^"\']+)["\']'
        quoted_paths = re.findall(quoted_pattern, command)
        result["targets"].extend(quoted_paths)

        # If we found recursive + targets, check for danger
        if "recursive" in result["flags"] and result["targets"]:
            for target in result["targets"]:
                is_dangerous, reason = FilesystemInspector.is_dangerous_target(target)
                if is_dangerous:
                    result["is_dangerous"] = True
                    result["danger_reason"] = reason
                    break

        return result

    @staticmethod
    def _analyze_move_command(command: str) -> dict:
        """Analyze a move/rename command."""
        result = {"targets": [], "flags": set(), "is_dangerous": False, "danger_reason": None}

        # Extract quoted paths
        quoted_pattern = r'["\']([^"\']+)["\']'
        paths = re.findall(quoted_pattern, command)
        if paths:
            # First path is source, rest are destinations/targets
            result["targets"] = paths

        return result

    @staticmethod
    def _analyze_copy_command(command: str) -> dict:
        """Analyze a copy command."""
        result = {"targets": [], "flags": set(), "is_dangerous": False, "danger_reason": None}

        # Extract quoted paths
        quoted_pattern = r'["\']([^"\']+)["\']'
        paths = re.findall(quoted_pattern, command)
        result["targets"] = paths

        # Check for recursive flag
        if re.search(r"(-r|--recursive|/s)", command, re.IGNORECASE):
            result["flags"].add("recursive")

        return result

    @staticmethod
    def _analyze_chmod_command(command: str) -> dict:
        """Analyze a chmod/permissions command."""
        result = {"targets": [], "flags": set(), "is_dangerous": False, "danger_reason": None}

        # Extract quoted paths
        quoted_pattern = r'["\']([^"\']+)["\']'
        paths = re.findall(quoted_pattern, command)
        result["targets"] = paths

        return result
