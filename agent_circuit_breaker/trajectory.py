"""Trajectory-level safety analysis for long-running agent runs."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional

from agent_circuit_breaker.decision import from_legacy_result
from agent_circuit_breaker.normalization import normalize_for_matching


Finding = Dict[str, Any]
Evaluation = Dict[str, Any]
Evaluator = Callable[[str], Evaluation]
ActionRecord = Dict[str, Any]


@dataclass(frozen=True)
class TrajectoryPolicy:
    """Optional run contract for trajectory evaluation."""

    goal: Optional[str] = None
    allowed_scopes: tuple[str, ...] = ()
    forbidden_targets: tuple[str, ...] = ()
    allowed_outputs: tuple[str, ...] = ()
    allowed_actors: tuple[str, ...] = ()
    forbidden_actors: tuple[str, ...] = ()
    allowed_delegations: tuple[tuple[str, str], ...] = ()
    require_actor: bool = False
    max_blocked_attempts: int = 1
    max_unknown_actions: Optional[int] = None

    @classmethod
    def from_contract(cls, contract: Optional[Dict[str, Any]]) -> "TrajectoryPolicy":
        """Build a policy from a caller-supplied contract dictionary."""
        if contract is None:
            return cls()
        if not isinstance(contract, dict):
            raise ValueError("trajectory contract must be an object")

        return cls(
            goal=_optional_string(contract.get("goal"), "goal"),
            allowed_scopes=tuple(_string_list(contract.get("allowed_scopes"), "allowed_scopes")),
            forbidden_targets=tuple(_string_list(contract.get("forbidden_targets"), "forbidden_targets")),
            allowed_outputs=tuple(_string_list(contract.get("allowed_outputs"), "allowed_outputs")),
            allowed_actors=tuple(_string_list(contract.get("allowed_actors"), "allowed_actors")),
            forbidden_actors=tuple(_string_list(contract.get("forbidden_actors"), "forbidden_actors")),
            allowed_delegations=tuple(_delegation_pairs(contract.get("allowed_delegations"))),
            require_actor=_optional_bool(contract.get("require_actor"), "require_actor", False),
            max_blocked_attempts=_optional_int(contract.get("max_blocked_attempts"), "max_blocked_attempts", 1) or 1,
            max_unknown_actions=_optional_int(contract.get("max_unknown_actions"), "max_unknown_actions", None),
        )


def evaluate_trajectory(
    actions: Iterable[str],
    evaluator: Evaluator,
    contract: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Evaluate a sequence of agent actions and trajectory-level risk patterns.

    Single-action verdicts still come from the supplied evaluator. This layer
    adds deterministic checks that need run history or an explicit run contract.
    """
    action_records = _validate_actions(actions)
    policy = TrajectoryPolicy.from_contract(contract)
    evaluations = [_evaluate_step(index, record, evaluator) for index, record in enumerate(action_records)]
    findings = _find_trajectory_risks(evaluations, policy)
    verdict = _trajectory_verdict(evaluations, findings)

    return {
        "schema_version": 1,
        "run_id": _run_id(action_records, contract),
        "run_fingerprint": _run_fingerprint(action_records, contract),
        "verdict": verdict,
        "decision": verdict.upper(),
        "summary": _summary(evaluations, findings),
        "contract": {
            "goal": policy.goal,
            "allowed_scopes": list(policy.allowed_scopes),
            "forbidden_targets": list(policy.forbidden_targets),
            "allowed_outputs": list(policy.allowed_outputs),
            "allowed_actors": list(policy.allowed_actors),
            "forbidden_actors": list(policy.forbidden_actors),
            "allowed_delegations": [
                {"from": source, "to": target}
                for source, target in policy.allowed_delegations
            ],
            "require_actor": policy.require_actor,
            "max_blocked_attempts": policy.max_blocked_attempts,
            "max_unknown_actions": policy.max_unknown_actions,
        },
        "actions": evaluations,
        "trajectory_findings": findings,
    }


def _validate_actions(actions: Iterable[Any]) -> List[ActionRecord]:
    if isinstance(actions, (str, bytes)) or not isinstance(actions, Iterable):
        raise ValueError("trajectory actions must be a list of strings or objects")

    action_list = list(actions)
    records: List[ActionRecord] = []
    for index, action in enumerate(action_list):
        records.append(_action_record(index, action))
    return records


def _action_record(index: int, action: Any) -> ActionRecord:
    if isinstance(action, str):
        return {"command": action}
    if not isinstance(action, dict):
        raise ValueError(f"trajectory actions[{index}] must be a string or object")

    command = action.get("command", action.get("action"))
    if not isinstance(command, str):
        raise ValueError(f"trajectory actions[{index}].command must be a string")

    record: ActionRecord = {"command": command}
    for field in ("actor", "delegated_by", "tool_name", "request_id"):
        if field not in action or action[field] is None:
            continue
        if not isinstance(action[field], str):
            raise ValueError(f"trajectory actions[{index}].{field} must be a string")
        record[field] = action[field]

    metadata = action.get("metadata")
    if metadata is not None:
        if not isinstance(metadata, dict):
            raise ValueError(f"trajectory actions[{index}].metadata must be an object")
        record["metadata"] = metadata
    return record


def _evaluate_step(index: int, action: ActionRecord, evaluator: Evaluator) -> Evaluation:
    result = evaluator(action["command"])
    result = dict(result)
    result["trajectory_index"] = index
    for field in ("actor", "delegated_by", "tool_name", "request_id", "metadata"):
        if field in action:
            result[field] = action[field]
    result["canonical_decision"] = from_legacy_result(result).to_summary()
    return result


def _find_trajectory_risks(evaluations: List[Evaluation], policy: TrajectoryPolicy) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_actor_authority_findings(evaluations, policy))
    findings.extend(_blocked_retry_findings(evaluations, policy))
    findings.extend(_unknown_volume_findings(evaluations, policy))
    findings.extend(_forbidden_target_findings(evaluations, policy))
    findings.extend(_allowed_scope_findings(evaluations, policy))
    findings.extend(_output_channel_findings(evaluations, policy))
    findings.extend(_direct_secret_egress_findings(evaluations))
    findings.extend(_secret_egress_findings(evaluations))
    findings.extend(_data_export_egress_findings(evaluations))
    findings.extend(_external_download_execution_findings(evaluations))
    return findings


def _actor_authority_findings(evaluations: List[Evaluation], policy: TrajectoryPolicy) -> List[Finding]:
    findings: List[Finding] = []
    allowed_actors = set(policy.allowed_actors)
    forbidden_actors = set(policy.forbidden_actors)
    allowed_delegations = set(policy.allowed_delegations)

    for item in evaluations:
        actor = item.get("actor")
        delegated_by = item.get("delegated_by")
        index = item["trajectory_index"]

        if policy.require_actor and not actor:
            findings.append(
                {
                    "id": "traj_missing_actor",
                    "title": "Trajectory action is missing required actor identity",
                    "severity": "HIGH",
                    "response": "block",
                    "indices": [index],
                    "reason": "run contract requires every action to identify the actor",
                }
            )
            continue

        if not isinstance(actor, str) or not actor:
            continue

        if actor in forbidden_actors:
            findings.append(
                {
                    "id": "traj_forbidden_actor",
                    "title": "Action actor is forbidden by the run contract",
                    "severity": "CRITICAL",
                    "response": "block",
                    "indices": [index],
                    "actor": actor,
                    "reason": f"actor {actor} is listed in forbidden_actors",
                }
            )
            continue

        if allowed_actors and actor not in allowed_actors:
            findings.append(
                {
                    "id": "traj_unauthorized_actor",
                    "title": "Action actor is outside the authorized run actors",
                    "severity": "HIGH",
                    "response": "block",
                    "indices": [index],
                    "actor": actor,
                    "reason": f"actor {actor} is not listed in allowed_actors",
                }
            )

        if delegated_by is None:
            continue
        if not isinstance(delegated_by, str) or not delegated_by:
            continue

        if (delegated_by, actor) not in allowed_delegations:
            findings.append(
                {
                    "id": "traj_unauthorized_delegation",
                    "title": "Delegated action is not authorized by the run contract",
                    "severity": "HIGH",
                    "response": "block",
                    "indices": [index],
                    "actor": actor,
                    "delegated_by": delegated_by,
                    "reason": f"delegation from {delegated_by} to {actor} is not listed in allowed_delegations",
                }
            )

    return findings


def _blocked_retry_findings(evaluations: List[Evaluation], policy: TrajectoryPolicy) -> List[Finding]:
    blocked = [item for item in evaluations if item.get("verdict") == "block"]
    if len(blocked) <= policy.max_blocked_attempts:
        return []

    return [
        {
            "id": "traj_repeated_blocked_actions",
            "title": "Repeated blocked actions in one trajectory",
            "severity": "HIGH",
            "response": "block",
            "indices": [item["trajectory_index"] for item in blocked],
            "reason": "agent run exceeded max_blocked_attempts",
        }
    ]


def _unknown_volume_findings(evaluations: List[Evaluation], policy: TrajectoryPolicy) -> List[Finding]:
    if policy.max_unknown_actions is None:
        return []

    unknown = [item for item in evaluations if item.get("verdict") == "unknown"]
    if len(unknown) <= policy.max_unknown_actions:
        return []

    return [
        {
            "id": "traj_unknown_action_volume",
            "title": "Too many unknown actions in one trajectory",
            "severity": "MEDIUM",
            "response": "approval",
            "indices": [item["trajectory_index"] for item in unknown],
            "reason": "agent run exceeded max_unknown_actions",
        }
    ]


def _forbidden_target_findings(evaluations: List[Evaluation], policy: TrajectoryPolicy) -> List[Finding]:
    findings: List[Finding] = []
    for item in evaluations:
        normalized = _normalized_command(item)
        for target in policy.forbidden_targets:
            if _matches_forbidden_target(normalized, target):
                findings.append(
                    {
                        "id": "traj_forbidden_target",
                        "title": "Action references a forbidden target",
                        "severity": "HIGH",
                        "response": "block",
                        "indices": [item["trajectory_index"]],
                        "target": target,
                        "reason": f"action references forbidden target: {target}",
                    }
                )
    return findings


def _allowed_scope_findings(evaluations: List[Evaluation], policy: TrajectoryPolicy) -> List[Finding]:
    if not policy.allowed_scopes:
        return []

    findings: List[Finding] = []
    allowed = tuple(_normalize_scope(scope) for scope in policy.allowed_scopes)
    for item in evaluations:
        command = item.get("command")
        if not isinstance(command, str) or not _is_write_like(command):
            continue

        for path in _write_target_tokens(command):
            normalized = _normalize_scope(path)
            if not any(normalized == scope.rstrip("/") or normalized.startswith(scope) for scope in allowed):
                findings.append(
                    {
                        "id": "traj_scope_violation",
                        "title": "Action writes outside allowed scopes",
                        "severity": "HIGH",
                        "response": "block",
                        "indices": [item["trajectory_index"]],
                        "path": path,
                        "reason": "write-like action targets a path outside allowed_scopes",
                    }
                )
    return findings


def _output_channel_findings(evaluations: List[Evaluation], policy: TrajectoryPolicy) -> List[Finding]:
    if not policy.allowed_outputs:
        return []

    allowed = {normalize_for_matching(output) for output in policy.allowed_outputs}
    findings: List[Finding] = []
    for item in evaluations:
        channel = _output_channel(item)
        if channel and channel not in allowed:
            findings.append(
                {
                    "id": "traj_output_channel_drift",
                    "title": "Action uses an output channel outside the run contract",
                    "severity": "HIGH",
                    "response": "block",
                    "indices": [item["trajectory_index"]],
                    "channel": channel,
                    "reason": f"output channel {channel} is not listed in allowed_outputs",
                }
            )
    return findings


def _matches_forbidden_target(normalized_command: str, target: str) -> bool:
    """Match forbidden targets on token/path boundaries, not arbitrary substrings."""
    normalized_target = normalize_for_matching(target).strip()
    if not normalized_target:
        return False

    if re.fullmatch(r"[a-z0-9_-]+", normalized_target):
        pattern = rf"(?<![a-z0-9_-]){re.escape(normalized_target)}(?![a-z0-9_-])"
        return re.search(pattern, normalized_command) is not None

    return normalized_target in normalized_command


def _secret_egress_findings(evaluations: List[Evaluation]) -> List[Finding]:
    secret_reads = [
        item
        for item in evaluations
        if _looks_like_secret_read(item) or _looks_like_sensitive_derivation(item)
    ]
    if not secret_reads:
        return []

    findings: List[Finding] = []
    first_secret = secret_reads[0]
    for item in evaluations:
        if item["trajectory_index"] <= first_secret["trajectory_index"]:
            continue
        if _looks_like_egress(item):
            findings.append(
                {
                    "id": "traj_secret_then_egress",
                    "title": "Secret-like read followed by external egress",
                    "severity": "CRITICAL",
                    "response": "block",
                    "indices": [first_secret["trajectory_index"], item["trajectory_index"]],
                    "reason": "trajectory reads or derives secret-like material before a network, publish, or upload action",
                    "evidence": {
                        "source_action": _secret_source_kind(first_secret),
                    },
                }
            )
            break
    return findings


def _direct_secret_egress_findings(evaluations: List[Evaluation]) -> List[Finding]:
    findings: List[Finding] = []
    for item in evaluations:
        if _has_sensitive_reference(item) and _looks_like_egress(item):
            findings.append(
                {
                    "id": "traj_secret_in_egress_action",
                    "title": "Secret-like material referenced in egress action",
                    "severity": "CRITICAL",
                    "response": "block",
                    "indices": [item["trajectory_index"]],
                    "reason": "one action references secret-like material and an external egress channel",
                }
            )
    return findings


def _data_export_egress_findings(evaluations: List[Evaluation]) -> List[Finding]:
    exports = [item for item in evaluations if _looks_like_data_export(item)]
    if not exports:
        return []

    first_export = exports[0]
    for item in evaluations:
        if item["trajectory_index"] <= first_export["trajectory_index"]:
            continue
        if _looks_like_egress(item):
            return [
                {
                    "id": "traj_data_export_then_egress",
                    "title": "Data export followed by external egress",
                    "severity": "HIGH",
                    "response": "block",
                    "indices": [first_export["trajectory_index"], item["trajectory_index"]],
                    "reason": "trajectory exports data before a network, publish, or upload action",
                }
            ]
    return []


def _external_download_execution_findings(evaluations: List[Evaluation]) -> List[Finding]:
    """Detect external artifact download followed by later local execution."""
    downloaded: list[tuple[Evaluation, str]] = []
    findings: List[Finding] = []

    for item in evaluations:
        downloaded.extend((item, path) for path in _external_download_targets(item))
        if not downloaded:
            continue

        executed_path = _executed_artifact_path(item)
        if not executed_path:
            continue

        normalized_executed = _normalize_artifact_reference(executed_path)
        for source, path in downloaded:
            if source["trajectory_index"] >= item["trajectory_index"]:
                continue
            if normalized_executed != _normalize_artifact_reference(path):
                continue
            findings.append(
                {
                    "id": "traj_external_download_then_execute",
                    "title": "External artifact downloaded then executed",
                    "severity": "CRITICAL",
                    "response": "block",
                    "indices": [source["trajectory_index"], item["trajectory_index"]],
                    "path": path,
                    "reason": "trajectory executes an artifact that was downloaded from an external source earlier in the run",
                }
            )
            break

    return findings


def _trajectory_verdict(evaluations: List[Evaluation], findings: List[Finding]) -> str:
    if any(item.get("verdict") == "error" for item in evaluations):
        return "error"
    if any(item.get("verdict") == "block" for item in evaluations):
        return "block"
    if any(finding.get("response") == "block" for finding in findings):
        return "block"
    if any(item.get("verdict") == "pending_approval" for item in evaluations):
        return "pending_approval"
    if any(finding.get("response") == "approval" for finding in findings):
        return "pending_approval"
    if any(item.get("verdict") == "unknown" for item in evaluations):
        return "unknown"
    return "allow"


def _summary(evaluations: List[Evaluation], findings: List[Finding]) -> Dict[str, Any]:
    counts = {
        "actions": len(evaluations),
        "allowed": 0,
        "blocked": 0,
        "unknown": 0,
        "pending_approval": 0,
        "errors": 0,
        "trajectory_findings": len(findings),
    }
    for item in evaluations:
        verdict = item.get("verdict")
        if verdict == "allow":
            counts["allowed"] += 1
        elif verdict == "block":
            counts["blocked"] += 1
        elif verdict == "unknown":
            counts["unknown"] += 1
        elif verdict == "pending_approval":
            counts["pending_approval"] += 1
        elif verdict == "error":
            counts["errors"] += 1
    return counts


def _run_id(actions: List[ActionRecord], contract: Optional[Dict[str, Any]]) -> str:
    material = {"actions": actions, "contract": contract or {}}
    encoded = repr(material).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def _run_fingerprint(actions: List[ActionRecord], contract: Optional[Dict[str, Any]]) -> str:
    material = {"schema_version": 1, "actions": actions, "contract": contract or {}}
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def _normalized_command(item: Evaluation) -> str:
    command = item.get("command")
    return normalize_for_matching(command) if isinstance(command, str) else ""


def _looks_like_secret_read(item: Evaluation) -> bool:
    command = _normalized_command(item)
    if not command:
        return False

    read_terms = ("cat ", "type ", "get-content", " gc ", "grep ", "rg ", "printenv", " env", " set")
    return _has_sensitive_reference(item) and any(term in f" {command}" for term in read_terms)


def _looks_like_sensitive_derivation(item: Evaluation) -> bool:
    command = _normalized_command(item)
    if not command or not _has_sensitive_reference(item):
        return False

    derivation_terms = (
        "base64 ",
        "openssl ",
        "gpg ",
        "tar ",
        "zip ",
        "7z ",
        "gzip ",
        "python ",
        "python3 ",
        "node ",
        "jq ",
        "sed ",
        "awk ",
        "cp ",
        "copy ",
        "xcopy ",
        "move ",
        "mv ",
    )
    return any(term in f" {command}" for term in derivation_terms) or ">" in command


def _secret_source_kind(item: Evaluation) -> str:
    if _looks_like_sensitive_derivation(item):
        return "derived_or_transformed_sensitive_material"
    return "direct_sensitive_read"


def _looks_like_egress(item: Evaluation) -> bool:
    command = _normalized_command(item)
    if not command:
        return False

    egress_patterns = (
        "curl ",
        "wget ",
        "http ",
        "httpie ",
        "scp ",
        "sftp ",
        "ssh ",
        "rsync ",
        "nc ",
        "ncat ",
        "netcat ",
        "socat ",
        "telnet ",
        "ftp ",
        "rclone copy",
        "rclone sync",
        "aws s3 cp",
        "aws s3 sync",
        "az storage blob upload",
        "gcloud storage cp",
        "gsutil cp",
        "gh pr create",
        "gh gist create",
        "git push",
        "slack",
        "webhook",
        "pastebin",
        "http://",
        "https://",
    )
    searchable = f" {command}"
    return any(pattern in searchable for pattern in egress_patterns) or _looks_like_custom_egress(command)


def _external_download_targets(item: Evaluation) -> List[str]:
    command = _normalized_command(item)
    if not command:
        return []

    tokens = _simple_tokens(command)
    if not tokens:
        return []

    command_name = tokens[0]
    if command_name == "curl" and _has_external_url(tokens):
        return _clean_path_tokens(_curl_download_targets(tokens))
    if command_name == "wget" and _has_external_url(tokens):
        return _clean_path_tokens(_wget_download_targets(tokens))
    return []


def _curl_download_targets(tokens: List[str]) -> List[str]:
    targets: List[str] = []
    lowered = [token.lower() for token in tokens]
    for option in ("-o", "--output"):
        for index, token in enumerate(lowered):
            if token == option and index + 1 < len(tokens):
                targets.append(tokens[index + 1])
            elif token.startswith(f"{option}="):
                targets.append(tokens[index].split("=", 1)[1])

    if "-o" in lowered or "--remote-name" in lowered:
        for token in tokens[1:]:
            if token.startswith(("http://", "https://")):
                targets.append(token.rstrip("/").rsplit("/", 1)[-1])
    return targets


def _wget_download_targets(tokens: List[str]) -> List[str]:
    targets: List[str] = []
    lowered = [token.lower() for token in tokens]
    for option in ("-o", "--output-document"):
        for index, token in enumerate(lowered):
            if token == option and index + 1 < len(tokens):
                targets.append(tokens[index + 1])
            elif token.startswith(f"{option}="):
                targets.append(tokens[index].split("=", 1)[1])

    if not targets:
        for token in tokens[1:]:
            if token.startswith(("http://", "https://")):
                targets.append(token.rstrip("/").rsplit("/", 1)[-1])
    return targets


def _has_external_url(tokens: List[str]) -> bool:
    return any(token.startswith(("http://", "https://")) for token in tokens)


def _executed_artifact_path(item: Evaluation) -> Optional[str]:
    command = _normalized_command(item)
    if not command:
        return None

    tokens = _simple_tokens(command)
    if not tokens:
        return None

    command_name = tokens[0]
    interpreters = {
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
        "python",
        "python3",
        "py",
        "node",
        "ruby",
        "perl",
        "php",
        "pwsh",
        "powershell",
    }
    if command_name in interpreters:
        for token in tokens[1:]:
            if token.startswith("-"):
                continue
            return token

    if command_name.startswith(("./", "../", "/", "~")) or re.match(r"^[a-z]:/", command_name):
        return command_name
    return None


def _normalize_artifact_reference(path: str) -> str:
    return normalize_for_matching(path).replace("\\", "/").lstrip("./")


def _looks_like_custom_egress(command: str) -> bool:
    """Detect common custom-script egress shapes without treating all scripts as egress."""
    tokens = _simple_tokens(command)
    if not tokens:
        return False

    command_name = tokens[0]
    args = tokens[1:]
    runtimes = {
        "python",
        "python3",
        "py",
        "node",
        "npm",
        "npx",
        "ruby",
        "perl",
        "php",
        "go",
        "java",
        "bash",
        "sh",
        "pwsh",
        "powershell",
    }
    egress_words = (
        "upload",
        "exfil",
        "egress",
        "send",
        "post",
        "webhook",
        "callback",
        "socket",
        "http",
        "client",
    )
    if command_name in runtimes and any(any(word in arg for word in egress_words) for arg in args):
        return True

    executable = command_name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return any(word in executable for word in egress_words)


def _looks_like_data_export(item: Evaluation) -> bool:
    command = _normalized_command(item)
    if not command:
        return False

    export_patterns = (
        "pg_dump",
        "mysqldump",
        "mongodump",
        "mongoexport",
        "sqlite3 ",
        ".dump",
        "redis-cli --rdb",
        "bq extract",
        "snowflake",
        "expdp",
        "tar ",
        "zip ",
        "7z ",
    )
    export_targets = (
        ".sql",
        ".dump",
        ".bak",
        ".backup",
        ".csv",
        ".parquet",
        ".tar",
        ".tar.gz",
        ".tgz",
        ".zip",
        ".7z",
    )
    return any(pattern in command for pattern in export_patterns) and any(target in command for target in export_targets)


def _has_sensitive_reference(item: Evaluation) -> bool:
    command = _normalized_command(item)
    if not command:
        return False

    sensitive_terms = (
        ".env",
        "id_rsa",
        "id_ed25519",
        "known_hosts",
        "aws_secret_access_key",
        "github_token",
        "gh_token",
        "openai_api_key",
        "api_key",
        "secret",
        "secrets.json",
        "token",
        "password",
        "passwd",
        "credential",
        "credentials",
        ".npmrc",
        ".pypirc",
        "kubeconfig",
        ".kube/config",
    )
    return any(term in command for term in sensitive_terms)


def _output_channel(item: Evaluation) -> Optional[str]:
    command = _normalized_command(item)
    if not command:
        return None

    tokens = _simple_tokens(command)
    lowered = [token.lower() for token in tokens]

    if _is_github_output(command):
        return "github"
    if _is_slack_output(command):
        return "slack"
    if _is_s3_output(command, lowered):
        return "s3"
    if _is_cloud_storage_output(command):
        return "cloud-storage"
    if _is_http_output(command, lowered):
        return "http"
    return None


def _is_github_output(command: str) -> bool:
    return any(
        pattern in f" {command}"
        for pattern in (
            " gh pr create",
            " hub pull-request",
            " git push",
            " gh gist create",
            " gh release create",
        )
    )


def _is_slack_output(command: str) -> bool:
    return any(pattern in command for pattern in ("chat.postmessage", "slack"))


def _is_s3_output(command: str, tokens: List[str]) -> bool:
    if "aws s3 sync" in command:
        return len(tokens) >= 4 and tokens[-1].startswith("s3://")
    if "aws s3 cp" in command:
        return len(tokens) >= 4 and tokens[-1].startswith("s3://")
    return False


def _is_cloud_storage_output(command: str) -> bool:
    return any(
        pattern in command
        for pattern in (
            "az storage blob upload",
            "gcloud storage cp",
            "gsutil cp",
        )
    )


def _is_http_output(command: str, tokens: List[str]) -> bool:
    if "webhook" in command:
        return True
    if not tokens:
        return False

    command_name = tokens[0]
    if command_name in {"http", "https", "httpie"}:
        return any(token in {"post", "put", "patch", "delete"} for token in tokens[1:3])

    if command_name == "curl":
        return _has_any_option(tokens, _curl_output_options()) or _has_http_method(tokens, {"post", "put", "patch", "delete"})

    if command_name == "wget":
        return _has_any_option(tokens, _wget_output_options()) or _has_http_method(tokens, {"post", "put", "patch", "delete"})

    return False


def _curl_output_options() -> tuple[str, ...]:
    return (
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "--form",
        "--json",
        "--upload-file",
    )


def _wget_output_options() -> tuple[str, ...]:
    return (
        "--post-data",
        "--post-file",
        "--body-data",
        "--body-file",
    )


def _has_any_option(tokens: List[str], options: tuple[str, ...]) -> bool:
    for token in tokens[1:]:
        if token in options or any(token.startswith(f"{option}=") for option in options):
            return True
    return False


def _has_http_method(tokens: List[str], methods: set[str]) -> bool:
    for index, token in enumerate(tokens):
        if token in {"-x", "--request", "--method"} and index + 1 < len(tokens):
            return tokens[index + 1] in methods
        for option in ("--request=", "--method="):
            if token.startswith(option) and token.split("=", 1)[1] in methods:
                return True
    return False


def _is_write_like(command: str) -> bool:
    normalized = normalize_for_matching(command)
    write_patterns = (
        "rm ",
        "del ",
        "remove-item",
        "mv ",
        "move ",
        "cp ",
        "copy ",
        "touch ",
        "mkdir ",
        "new-item",
        "write ",
        "writefile",
        "edit ",
        "patch ",
        "git add",
        "tee ",
        "curl -o",
        "curl --output",
        "wget -o",
        "wget --output-document",
        "out-file",
        "set-content",
        "add-content",
    )
    return any(pattern in f" {normalized}" for pattern in write_patterns) or ">" in normalized


def _path_tokens(command: str) -> List[str]:
    candidates = re.findall(r"(?<![\w:])([A-Za-z0-9_.\-/\\]+(?:\.[A-Za-z0-9_]+|/[A-Za-z0-9_.\-/\\]*|\\[A-Za-z0-9_.\-/\\]*))", command)
    return _clean_path_tokens(candidates)


def _write_target_tokens(command: str) -> List[str]:
    """Return likely write destinations from a command."""
    tokens = _simple_tokens(command)
    lowered = [token.lower() for token in tokens]
    targets: List[str] = []

    for option in ("-o", "--output", "-output", "--output-document"):
        for index, token in enumerate(lowered):
            if token == option and index + 1 < len(tokens):
                targets.append(tokens[index + 1])
            elif token.startswith(f"{option}="):
                targets.append(tokens[index].split("=", 1)[1])

    if "tee" in lowered:
        tee_index = lowered.index("tee")
        for token in tokens[tee_index + 1 :]:
            if not token.startswith("-"):
                targets.append(token)

    for index, token in enumerate(tokens):
        if token in {">", ">>", "1>", "1>>", "2>", "2>>"} and index + 1 < len(tokens):
            targets.append(tokens[index + 1])
        elif token.startswith((">", ">>")) and len(token) > 1:
            targets.append(token.lstrip(">"))

    if targets:
        return _clean_path_tokens(targets)
    return _path_tokens(command)


def _clean_path_tokens(candidates: List[str]) -> List[str]:
    ignored_prefixes = ("http://", "https://", "s3://")
    paths: List[str] = []
    for candidate in candidates:
        cleaned = candidate.strip("'\"")
        if not cleaned or cleaned.startswith("-") or cleaned.lower().startswith(ignored_prefixes):
            continue
        if cleaned in {".", "..", "/"}:
            continue
        paths.append(cleaned)
    return paths


def _simple_tokens(command: str) -> List[str]:
    """Return shell-like tokens for lightweight trajectory heuristics."""
    try:
        import shlex

        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _normalize_scope(value: str) -> str:
    normalized = normalize_for_matching(value).replace("\\", "/").strip()
    normalized = normalized.lstrip("./")
    if normalized and not normalized.endswith("/") and "." not in normalized.rsplit("/", 1)[-1]:
        normalized = f"{normalized}/"
    return normalized


def _is_external_or_absolute(path: str) -> bool:
    return path.startswith(("/", "~")) or re.match(r"^[a-z]:/", path) is not None


def _optional_string(value: Any, field: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"trajectory contract {field} must be a string")
    return value


def _string_list(value: Any, field: str) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"trajectory contract {field} must be a list of strings")
    return value


def _optional_int(value: Any, field: str, default: Optional[int]) -> Optional[int]:
    if value is None:
        return default
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"trajectory contract {field} must be a non-negative integer")
    return value


def _optional_bool(value: Any, field: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"trajectory contract {field} must be a boolean")
    return value


def _delegation_pairs(value: Any) -> List[tuple[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("trajectory contract allowed_delegations must be a list")

    pairs: List[tuple[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"trajectory contract allowed_delegations[{index}] must be an object")
        source = item.get("from")
        target = item.get("to")
        if not isinstance(source, str) or not source:
            raise ValueError(f"trajectory contract allowed_delegations[{index}].from must be a non-empty string")
        if not isinstance(target, str) or not target:
            raise ValueError(f"trajectory contract allowed_delegations[{index}].to must be a non-empty string")
        pairs.append((source, target))
    return pairs
