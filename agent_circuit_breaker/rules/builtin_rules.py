"""
Built-in rules - Default filesystem safety policy.

These rules describe dangerous filesystem operations that should be blocked.
"""

from functools import lru_cache

from ..engine import Rule
from ..inspectors.filesystem import FilesystemInspector
from ..inspectors.command import CommandInspector
from ..inspectors.sql import SQLInspector


def _filesystem_analyses(action: str) -> list[dict]:
    """Return filesystem analyses for each parsed command segment."""
    command_analysis = _command_analysis(action)
    if not command_analysis["is_valid"]:
        return []

    return [
        FilesystemInspector.analyze_operation(segment["raw"])
        for segment in command_analysis["segments"]
    ]


@lru_cache(maxsize=128)
def _command_analysis(action: str) -> dict:
    """Return cached command analysis for a single evaluation input."""
    return CommandInspector.analyze_command(action)


@lru_cache(maxsize=128)
def _sql_analysis(action: str) -> dict:
    """Return cached SQL analysis for a single evaluation input."""
    return SQLInspector.analyze_sql(action)


def _is_recursive_delete(action: str) -> bool:
    """Detect recursive filesystem deletion patterns."""
    return any(
        analysis["operation"] == "delete" and "recursive" in analysis["flags"]
        for analysis in _filesystem_analyses(action)
    )


def _is_system_path(action: str) -> bool:
    """Detect attempts to delete system directories."""
    for analysis in _filesystem_analyses(action):
        if analysis["operation"] != "delete":
            continue

        for target in analysis["targets"]:
            is_dangerous, _ = FilesystemInspector.is_dangerous_target(target)
            if is_dangerous:
                return True

    return False


def _is_root_deletion(action: str) -> bool:
    """Detect deletion targeting root or home directory without qualification."""
    for analysis in _filesystem_analyses(action):
        if analysis["operation"] != "delete":
            continue

        for target in analysis["targets"]:
            if target in {"/", "\\", "~"}:
                return True

    return False


def _is_unqualified_glob_delete(action: str) -> bool:
    """Detect bulk delete operations without proper qualification."""
    for analysis in _filesystem_analyses(action):
        if analysis["operation"] != "delete":
            continue

        if "recursive" not in analysis["flags"]:
            continue

        if any(target in {"*", "/*", "\\*"} for target in analysis["targets"]):
            return True

    return False


def _has_command_risk(action: str, risk_flag: str) -> bool:
    """Return true when command analysis reports a specific risk flag."""
    analysis = _command_analysis(action)
    if not analysis["is_valid"]:
        return False

    return risk_flag in analysis["risk_flags"]


def _has_sql_risk(action: str, risk_flag: str) -> bool:
    """Return true when SQL analysis reports a specific risk flag."""
    analysis = _sql_analysis(action)
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


def _is_nested_dangerous_execution(action: str) -> bool:
    """Detect dangerous commands hidden inside shell/interpreter wrappers."""
    return _has_command_risk(action, "cmd_nested_dangerous_execution")


def _is_package_publish_without_context(action: str) -> bool:
    """Detect package publish commands without explicit release context."""
    return _has_command_risk(action, "cmd_package_publish_without_context")


def _is_destructive_docker(action: str) -> bool:
    """Detect destructive Docker command shapes."""
    return _has_command_risk(action, "cmd_destructive_docker")


def _is_cloud_resource_deletion(action: str) -> bool:
    """Detect cloud resource deletion command shapes."""
    return _has_command_risk(action, "cmd_cloud_resource_deletion")


def _is_forceful_kubernetes_delete(action: str) -> bool:
    """Detect forceful Kubernetes deletion command shapes."""
    return _has_command_risk(action, "cmd_forceful_kubernetes_delete")


def _is_disk_overwrite_or_format(action: str) -> bool:
    """Detect disk overwrite or format command shapes."""
    return _has_command_risk(action, "cmd_disk_overwrite_or_format")


def _is_find_root_delete(action: str) -> bool:
    """Detect root-level find delete command shapes."""
    return _has_command_risk(action, "cmd_find_root_delete")


def _is_shell_fork_bomb(action: str) -> bool:
    """Detect shell fork bomb command shapes."""
    return _has_command_risk(action, "cmd_shell_fork_bomb")


def _is_sql_drop_table(action: str) -> bool:
    """Detect SQL DROP TABLE statements."""
    return _has_sql_risk(action, "sql_drop_table")


def _is_sql_drop_database(action: str) -> bool:
    """Detect SQL DROP DATABASE statements."""
    return _has_sql_risk(action, "sql_drop_database")


def _is_sql_truncate(action: str) -> bool:
    """Detect SQL TRUNCATE statements."""
    return _has_sql_risk(action, "sql_truncate")


def _is_sql_unqualified_delete(action: str) -> bool:
    """Detect SQL DELETE statements without WHERE."""
    return _has_sql_risk(action, "sql_unqualified_delete")


def _is_sql_unqualified_update(action: str) -> bool:
    """Detect SQL UPDATE statements without WHERE."""
    return _has_sql_risk(action, "sql_unqualified_update")


def _is_sql_tautological_delete(action: str) -> bool:
    """Detect SQL DELETE statements with tautological WHERE predicates."""
    return _has_sql_risk(action, "sql_tautological_delete")


def _is_sql_tautological_update(action: str) -> bool:
    """Detect SQL UPDATE statements with tautological WHERE predicates."""
    return _has_sql_risk(action, "sql_tautological_update")


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
            "description": "Blocks recursive chmod operations that make targets world-writable",
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

    Rule(
        id="cmd_nested_dangerous_execution",
        title="Dangerous nested command execution detected",
        severity="CRITICAL",
        response="block",
        matcher=_is_nested_dangerous_execution,
        metadata={
            "description": "Blocks dangerous commands passed through shell or interpreter execution flags",
            "category": "command",
        }
    ),

    Rule(
        id="cmd_package_publish_without_context",
        title="Package publish without explicit release context detected",
        severity="HIGH",
        response="block",
        matcher=_is_package_publish_without_context,
        metadata={
            "description": "Blocks common package publish commands unless an explicit repository, registry, tag, or dry-run context is present",
            "category": "command",
        }
    ),

    Rule(
        id="cmd_destructive_docker",
        title="Destructive Docker command detected",
        severity="HIGH",
        response="block",
        matcher=_is_destructive_docker,
        metadata={
            "description": "Blocks destructive Docker prune, remove, volume, network, and compose-down command shapes",
            "category": "command",
        }
    ),

    Rule(
        id="cmd_cloud_resource_deletion",
        title="Cloud resource deletion command detected",
        severity="HIGH",
        response="block",
        matcher=_is_cloud_resource_deletion,
        metadata={
            "description": "Blocks common AWS, Azure CLI, and gcloud deletion command shapes",
            "category": "command",
        }
    ),

    Rule(
        id="cmd_forceful_kubernetes_delete",
        title="Forceful Kubernetes deletion detected",
        severity="HIGH",
        response="block",
        matcher=_is_forceful_kubernetes_delete,
        metadata={
            "description": "Blocks kubectl/oc delete commands that use --force, --now, or --grace-period=0",
            "category": "command",
        }
    ),

    Rule(
        id="cmd_disk_overwrite_or_format",
        title="Disk overwrite or format command detected",
        severity="CRITICAL",
        response="block",
        matcher=_is_disk_overwrite_or_format,
        metadata={
            "description": "Blocks dd writes to /dev devices and mkfs formatting of /dev devices",
            "category": "command",
        }
    ),

    Rule(
        id="cmd_find_root_delete",
        title="Root-level find delete command detected",
        severity="CRITICAL",
        response="block",
        matcher=_is_find_root_delete,
        metadata={
            "description": "Blocks find -delete command shapes rooted at system-level paths",
            "category": "command",
        }
    ),

    Rule(
        id="cmd_shell_fork_bomb",
        title="Shell fork bomb detected",
        severity="CRITICAL",
        response="block",
        matcher=_is_shell_fork_bomb,
        metadata={
            "description": "Blocks classic shell fork bomb command text",
            "category": "command",
        }
    ),

    Rule(
        id="sql_drop_table",
        title="SQL DROP TABLE detected",
        severity="CRITICAL",
        response="block",
        matcher=_is_sql_drop_table,
        metadata={
            "description": "Blocks SQL DROP TABLE statements",
            "category": "sql",
        }
    ),

    Rule(
        id="sql_drop_database",
        title="SQL DROP DATABASE detected",
        severity="CRITICAL",
        response="block",
        matcher=_is_sql_drop_database,
        metadata={
            "description": "Blocks SQL DROP DATABASE statements",
            "category": "sql",
        }
    ),

    Rule(
        id="sql_truncate",
        title="SQL TRUNCATE detected",
        severity="CRITICAL",
        response="block",
        matcher=_is_sql_truncate,
        metadata={
            "description": "Blocks SQL TRUNCATE statements",
            "category": "sql",
        }
    ),

    Rule(
        id="sql_unqualified_delete",
        title="SQL DELETE without WHERE detected",
        severity="HIGH",
        response="block",
        matcher=_is_sql_unqualified_delete,
        metadata={
            "description": "Blocks SQL DELETE statements that do not include a WHERE clause",
            "category": "sql",
        }
    ),

    Rule(
        id="sql_unqualified_update",
        title="SQL UPDATE without WHERE detected",
        severity="HIGH",
        response="block",
        matcher=_is_sql_unqualified_update,
        metadata={
            "description": "Blocks SQL UPDATE statements that do not include a WHERE clause",
            "category": "sql",
        }
    ),

    Rule(
        id="sql_tautological_delete",
        title="SQL DELETE with tautological WHERE detected",
        severity="HIGH",
        response="block",
        matcher=_is_sql_tautological_delete,
        metadata={
            "description": "Blocks SQL DELETE statements with simple always-true WHERE predicates",
            "category": "sql",
        }
    ),

    Rule(
        id="sql_tautological_update",
        title="SQL UPDATE with tautological WHERE detected",
        severity="HIGH",
        response="block",
        matcher=_is_sql_tautological_update,
        metadata={
            "description": "Blocks SQL UPDATE statements with simple always-true WHERE predicates",
            "category": "sql",
        }
    ),
]
