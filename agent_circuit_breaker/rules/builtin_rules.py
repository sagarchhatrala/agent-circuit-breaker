"""
Built-in rules - Default filesystem safety policy.

These rules describe dangerous filesystem operations that should be blocked.
"""

from ..engine import Rule
from ..inspectors.filesystem import FilesystemInspector
from ..inspectors.command import CommandInspector


def _is_recursive_delete(action: str) -> bool:
    """Detect recursive filesystem deletion patterns."""
    action_lower = action.lower().strip()
    
    # Unix/Linux patterns
    if "rm" in action_lower:
        if "-rf" in action_lower or "-fr" in action_lower:
            return True
        if "rmdir" in action_lower and "/s" in action_lower:
            return True
    
    # Windows PowerShell patterns
    if "remove-item" in action_lower:
        if "-recurse" in action_lower or "-r " in action_lower:
            return True
    
    # Windows cmd patterns
    if "rmdir" in action_lower and "/s" in action_lower:
        return True
    
    return False


def _is_system_path(action: str) -> bool:
    """Detect attempts to delete system directories."""
    analysis = FilesystemInspector.analyze_operation(action)
    if analysis["operation"] != "delete":
        return False

    for target in analysis["targets"]:
        is_dangerous, _ = FilesystemInspector.is_dangerous_target(target)
        if is_dangerous:
            return True

    return False


def _is_root_deletion(action: str) -> bool:
    """Detect deletion targeting root or home directory without qualification."""
    action_lower = action.lower()
    
    # Pattern: rm -rf / or rm -rf ~
    if "rm -rf /" in action_lower or "rmdir /s /:" in action_lower:
        return True
    
    if "rm -rf ~" in action_lower:
        return True
    
    return False


def _is_unqualified_glob_delete(action: str) -> bool:
    """Detect bulk delete operations without proper qualification."""
    action_lower = action.lower()
    
    # Pattern: rm -rf /* or rm -rf *
    if "rm -rf /*" in action_lower or "rm -rf *" in action_lower:
        return True
    
    if "remove-item -path" in action_lower and ("*" in action_lower or "/*" in action_lower):
        if "-recurse" in action_lower:
            return True
    
    return False


def _has_command_risk(action: str, risk_flag: str) -> bool:
    """Return true when command analysis reports a specific risk flag."""
    analysis = CommandInspector.analyze_command(action)
    if not analysis["is_valid"]:
        return False

    return risk_flag in analysis["risk_flags"]


def _is_git_force_push(action: str) -> bool:
    """Detect git force push operations."""
    return _has_command_risk(action, "cmd_git_force_push")


def _is_recursive_world_writable(action: str) -> bool:
    """Detect recursive chmod 777 operations."""
    return _has_command_risk(action, "cmd_recursive_world_writable")


def _is_remote_script_to_shell(action: str) -> bool:
    """Detect remote script download piped directly to a shell."""
    return _has_command_risk(action, "cmd_remote_script_to_shell")


# Built-in filesystem safety rules
BUILTIN_RULES = [
    Rule(
        id="fs_recursive_delete",
        title="Recursive filesystem deletion detected",
        severity="CRITICAL",
        response="block",
        matcher=_is_recursive_delete,
        metadata={
            "description": "Blocks recursive delete operations (rm -rf, rmdir /s, Remove-Item -Recurse)",
            "category": "filesystem",
            "cve_references": [],
        }
    ),
    
    Rule(
        id="fs_system_path",
        title="Attempt to delete system directory",
        severity="CRITICAL",
        response="block",
        matcher=_is_system_path,
        metadata={
            "description": "Blocks operations targeting system directories (/root, /sys, C:\\Windows, etc.)",
            "category": "filesystem",
            "platforms": ["linux", "macos", "windows"],
        }
    ),
    
    Rule(
        id="fs_root_deletion",
        title="Deletion of root or home directory",
        severity="CRITICAL",
        response="block",
        matcher=_is_root_deletion,
        metadata={
            "description": "Blocks attempts to delete root (/) or home (~) directories",
            "category": "filesystem",
        }
    ),
    
    Rule(
        id="fs_unqualified_glob_delete",
        title="Unqualified bulk delete with recursive flag",
        severity="CRITICAL",
        response="block",
        matcher=_is_unqualified_glob_delete,
        metadata={
            "description": "Blocks bulk recursive deletes using wildcards (rm -rf /*, etc.)",
            "category": "filesystem",
        }
    ),

    Rule(
        id="cmd_git_force_push",
        title="Git force push detected",
        severity="HIGH",
        response="block",
        matcher=_is_git_force_push,
        metadata={
            "description": "Blocks git push operations using --force, -f, or --force-with-lease",
            "category": "command",
        }
    ),

    Rule(
        id="cmd_recursive_world_writable",
        title="Recursive world-writable chmod detected",
        severity="HIGH",
        response="block",
        matcher=_is_recursive_world_writable,
        metadata={
            "description": "Blocks recursive chmod 777 operations",
            "category": "command",
        }
    ),

    Rule(
        id="cmd_remote_script_to_shell",
        title="Remote script piped to shell detected",
        severity="CRITICAL",
        response="block",
        matcher=_is_remote_script_to_shell,
        metadata={
            "description": "Blocks curl/wget output piped directly to sh or bash",
            "category": "command",
        }
    ),
]
