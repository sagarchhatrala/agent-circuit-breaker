"""Human-oriented explanations and safer alternatives."""

from typing import Any, Dict, List


SUGGESTIONS = {
    "fs_recursive_delete": [
        "Create a backup or checkpoint before deleting recursively.",
        "Narrow the target path and avoid system or repository roots.",
        "Run a dry-run listing first, for example with find or ls.",
    ],
    "fs_system_path": [
        "Do not modify system paths from an agent session.",
        "Use a sandbox, container, or disposable VM for system-level experiments.",
    ],
    "cmd_git_force_push": [
        "Use a pull request instead of rewriting remote history.",
        "If history rewrite is intentional, require a human approval step.",
    ],
    "cmd_recursive_world_writable": [
        "Grant the narrowest required permission instead of recursive world-writable access.",
        "Prefer owner or group scoped permissions.",
    ],
    "cmd_remote_script_pipe_shell": [
        "Download the script, inspect it, pin its checksum, then execute only after review.",
    ],
    "cmd_package_publish": [
        "Publish only from a tagged release workflow after tests pass.",
        "Use TestPyPI or a dry-run build before real package publishing.",
    ],
    "cmd_cloud_delete": [
        "Confirm account, region, project, and environment before destructive cloud changes.",
        "Use read-only describe/list commands first.",
    ],
    "cmd_kubectl_force_delete": [
        "Inspect the resource with kubectl get/describe before deletion.",
        "Avoid force deletion unless an operator has approved the blast radius.",
    ],
    "cmd_disk_overwrite_or_format": [
        "Never format or overwrite block devices from an agent session.",
        "Use a disposable test image if disk operations are required.",
    ],
    "cmd_find_root_delete": [
        "Scope find -delete to a disposable directory and print matches before deleting.",
    ],
    "cmd_shell_fork_bomb": [
        "Do not run self-replicating shell functions.",
    ],
    "sql_drop_table": [
        "Run against staging first and require a reviewed migration.",
        "Take a verified backup before destructive schema changes.",
    ],
    "sql_drop_database": [
        "Require explicit production approval and a tested restore point.",
    ],
    "sql_truncate": [
        "Use a transaction and confirm row counts before truncating data.",
    ],
    "sql_unqualified_delete": [
        "Add a selective WHERE clause and preview affected rows first.",
    ],
    "sql_unqualified_update": [
        "Add a selective WHERE clause and preview affected rows first.",
    ],
    "sql_tautological_delete": [
        "Replace tautological predicates with narrow, reviewed filters.",
    ],
    "sql_tautological_update": [
        "Replace tautological predicates with narrow, reviewed filters.",
    ],
}


def explain_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Build an additive explanation object for an evaluation result."""
    rule_id = result.get("matched_rule")
    command_flags = (result.get("command_analysis") or {}).get("risk_flags") or []
    sql_flags = (result.get("sql_analysis") or {}).get("risk_flags") or []
    keys: List[str] = []

    if rule_id:
        keys.append(rule_id)
    for flag in command_flags + sql_flags:
        if flag not in keys:
            keys.append(flag)

    suggestions: List[str] = []
    for key in keys:
        for suggestion in SUGGESTIONS.get(key, []):
            if suggestion not in suggestions:
                suggestions.append(suggestion)

    if not suggestions and result.get("verdict") == "unknown":
        suggestions.append("Treat UNKNOWN as not vetted, not as safe.")
    if not suggestions and result.get("verdict") == "allow":
        suggestions.append("No built-in high-risk pattern matched this action.")

    return {
        "summary": _summary(result),
        "matched_rule": rule_id,
        "risk_score": int(result.get("risk_score") or 0),
        "suggestions": suggestions,
    }


def format_explanation(result: Dict[str, Any], explanation: Dict[str, Any]) -> str:
    """Format an explanation for CLI output."""
    lines = [
        f"Command: {result.get('command')}",
        f"Verdict: {str(result.get('verdict')).upper()}",
        f"Risk Score: {explanation['risk_score']}",
        f"Summary: {explanation['summary']}",
    ]

    if explanation.get("matched_rule"):
        lines.append(f"Matched Rule: {explanation['matched_rule']}")

    if explanation["suggestions"]:
        lines.append("Safer Alternatives:")
        for suggestion in explanation["suggestions"]:
            lines.append(f"  - {suggestion}")

    return "\n".join(lines)


def _summary(result: Dict[str, Any]) -> str:
    verdict = result.get("verdict")
    if verdict == "block":
        return "This action matched a blocking safety rule."
    if verdict == "pending_approval":
        return "This action requires human approval under the selected policy."
    if verdict == "allow":
        return "This action matched a known safe operation or allow rule."
    if verdict == "error":
        return "This action could not be analyzed safely."
    return "No deterministic allow or block rule matched this action."
