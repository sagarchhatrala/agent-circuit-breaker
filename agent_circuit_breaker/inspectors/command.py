"""Command Inspector - Tokenizes shell commands for later safety analysis."""

import base64
import binascii
import re
import shlex
from typing import Any, Dict, List, Optional

from agent_circuit_breaker.normalization import normalize_for_matching


class CommandInspector:
    """Inspects shell command text without executing it."""

    RISK_SCORES = {
        "cmd_git_force_push": 85,
        "cmd_recursive_world_writable": 85,
        "cmd_remote_script_to_shell": 100,
        "cmd_nested_dangerous_execution": 100,
        "cmd_package_publish_without_context": 75,
        "cmd_destructive_docker": 85,
        "cmd_cloud_resource_deletion": 85,
        "cmd_forceful_kubernetes_delete": 85,
        "cmd_disk_overwrite_or_format": 100,
        "cmd_find_root_delete": 100,
        "cmd_shell_fork_bomb": 100,
    }

    @staticmethod
    def analyze_command(command: str) -> Dict[str, Any]:
        """
        Analyze a command string into a deterministic token structure.

        This foundation step only tokenizes and identifies the command/args.
        Risk detection is added in later v0.2 slices.
        """
        result: Dict[str, Any] = {
            "raw": command,
            "normalized": command,
            "tokens": [],
            "command": None,
            "args": [],
            "segments": [],
            "operators": [],
            "is_valid": True,
            "error": None,
            "risk_flags": [],
            "risk_score": 0,
            "is_dangerous": False,
            "danger_reason": None,
        }

        if not isinstance(command, str):
            result["is_valid"] = False
            result["error"] = "Command must be a string"
            return result

        normalized = normalize_for_matching(command)
        result["normalized"] = normalized

        if not normalized.strip():
            return result

        try:
            split_result = CommandInspector.split_segments(normalized)
        except ValueError as exc:
            result["is_valid"] = False
            result["error"] = str(exc)
            return result

        result["segments"] = split_result["segments"]
        result["operators"] = split_result["operators"]
        CommandInspector._apply_risk_analysis(result)

        if result["segments"]:
            first_segment = result["segments"][0]
            result["tokens"] = first_segment["tokens"]
            result["command"] = first_segment["command"]
            result["args"] = first_segment["args"]

        return result

    @staticmethod
    def split_segments(command: str) -> Dict[str, Any]:
        """
        Split command text on shell operators while respecting quotes.

        Supported operators: &&, ||, ;, |, and newlines.
        """
        if not isinstance(command, str):
            raise ValueError("Command must be a string")

        raw_segments: List[str] = []
        operators: List[str] = []
        current: List[str] = []
        quote: Optional[str] = None
        escaped = False
        index = 0

        while index < len(command):
            char = command[index]

            if escaped:
                current.append(char)
                escaped = False
                index += 1
                continue

            if char == "\\":
                current.append(char)
                escaped = True
                index += 1
                continue

            if quote:
                current.append(char)
                if char == quote:
                    quote = None
                index += 1
                continue

            if char in ("'", '"'):
                quote = char
                current.append(char)
                index += 1
                continue

            two_char = command[index : index + 2]
            if two_char in ("&&", "||"):
                CommandInspector._append_segment(raw_segments, current)
                operators.append(two_char)
                current = []
                index += 2
                continue

            if char in (";", "|", "\n", "\r"):
                CommandInspector._append_segment(raw_segments, current)
                operators.append("newline" if char in ("\n", "\r") else char)
                current = []
                index += 1
                continue

            current.append(char)
            index += 1

        if escaped:
            current.append("\\")

        if quote:
            raise ValueError(f"Unclosed {quote} quote")

        CommandInspector._append_segment(raw_segments, current)

        segments = [
            CommandInspector._build_segment(segment)
            for segment in raw_segments
            if segment.strip()
        ]

        return {
            "segments": segments,
            "operators": operators,
        }

    @staticmethod
    def _append_segment(raw_segments: List[str], current: List[str]) -> None:
        """Append the current raw segment if it contains non-whitespace text."""
        segment = "".join(current).strip()
        if segment:
            raw_segments.append(segment)

    @staticmethod
    def _build_segment(raw: str) -> Dict[str, Any]:
        """Build deterministic segment analysis for one command segment."""
        tokens = CommandInspector.tokenize(raw)
        return {
            "raw": raw,
            "tokens": tokens,
            "command": tokens[0] if tokens else None,
            "args": tokens[1:] if len(tokens) > 1 else [],
            "risk_flags": [],
            "risk_score": 0,
            "is_dangerous": False,
            "danger_reason": None,
        }

    @staticmethod
    def _apply_risk_analysis(result: Dict[str, Any]) -> None:
        """Apply command risk detection to all analyzed segments."""
        for index, segment in enumerate(result["segments"]):
            CommandInspector._detect_segment_risks(segment)
            CommandInspector._detect_pipeline_risks(result, index)

        CommandInspector._detect_full_command_risks(result)

        risk_flags: List[str] = []
        danger_reasons: List[str] = []

        for segment in result["segments"]:
            for flag in segment["risk_flags"]:
                if flag not in risk_flags:
                    risk_flags.append(flag)

            if segment["danger_reason"] and segment["danger_reason"] not in danger_reasons:
                danger_reasons.append(segment["danger_reason"])

        result["risk_flags"] = risk_flags
        result["risk_score"] = CommandInspector._score_risks(risk_flags)
        result["is_dangerous"] = any(segment["is_dangerous"] for segment in result["segments"])
        result["danger_reason"] = "; ".join(danger_reasons) if danger_reasons else None

    @staticmethod
    def _detect_segment_risks(segment: Dict[str, Any]) -> None:
        """Detect single-segment command risk patterns."""
        tokens = segment["tokens"]
        if not tokens:
            return

        command = tokens[0].lower()
        args = [token.lower() for token in tokens[1:]]

        if command == "git" and CommandInspector._is_git_force_push(args):
            CommandInspector._mark_dangerous(
                segment,
                "cmd_git_force_push",
                "Git force push detected",
            )

        if command == "chmod" and CommandInspector._is_recursive_world_writable(args):
            CommandInspector._mark_dangerous(
                segment,
                "cmd_recursive_world_writable",
                "Recursive chmod 777 detected",
            )

        if CommandInspector._is_package_publish_without_context(command, args):
            CommandInspector._mark_dangerous(
                segment,
                "cmd_package_publish_without_context",
                "Package publish command without explicit release context detected",
            )

        if CommandInspector._is_destructive_docker(command, args):
            CommandInspector._mark_dangerous(
                segment,
                "cmd_destructive_docker",
                "Destructive Docker command detected",
            )

        if CommandInspector._is_cloud_resource_deletion(command, args):
            CommandInspector._mark_dangerous(
                segment,
                "cmd_cloud_resource_deletion",
                "Cloud resource deletion command detected",
            )

        if CommandInspector._is_forceful_kubernetes_delete(command, args):
            CommandInspector._mark_dangerous(
                segment,
                "cmd_forceful_kubernetes_delete",
                "Forceful Kubernetes deletion detected",
            )

        if CommandInspector._is_disk_overwrite_or_format(command, args):
            CommandInspector._mark_dangerous(
                segment,
                "cmd_disk_overwrite_or_format",
                "Disk overwrite or format command detected",
            )

        if CommandInspector._is_find_root_delete(command, args):
            CommandInspector._mark_dangerous(
                segment,
                "cmd_find_root_delete",
                "Root-level find delete command detected",
            )

        nested = CommandInspector._nested_command_payload(command, segment["args"])
        if nested and CommandInspector._nested_payload_is_dangerous(nested):
            CommandInspector._mark_dangerous(
                segment,
                "cmd_nested_dangerous_execution",
                "Nested command payload contains dangerous action",
            )

    @staticmethod
    def _detect_full_command_risks(result: Dict[str, Any]) -> None:
        """Detect risks that are easier to identify from the full command text."""
        if not CommandInspector._has_shell_fork_bomb_shape(result["normalized"]):
            return

        for segment in result["segments"]:
            CommandInspector._mark_dangerous(
                segment,
                "cmd_shell_fork_bomb",
                "Shell fork bomb pattern detected",
            )

    @staticmethod
    def _detect_pipeline_risks(result: Dict[str, Any], index: int) -> None:
        """Detect risk patterns that depend on adjacent pipeline segments."""
        segments = result["segments"]
        operators = result["operators"]

        if index >= len(segments) - 1 or index >= len(operators):
            return

        if operators[index] != "|":
            return

        current = segments[index]
        next_segment = segments[index + 1]

        current_command = (current["command"] or "").lower()
        next_command = (next_segment["command"] or "").lower()

        if current_command in {"curl", "wget"} and next_command in {"sh", "bash"}:
            CommandInspector._mark_dangerous(
                current,
                "cmd_remote_script_to_shell",
                "Remote script piped to shell detected",
            )
            CommandInspector._mark_dangerous(
                next_segment,
                "cmd_remote_script_to_shell",
                "Remote script piped to shell detected",
            )

    @staticmethod
    def _is_git_force_push(args: List[str]) -> bool:
        """Return true when git args represent a force push."""
        if not args or args[0] != "push":
            return False

        return any(arg in {"--force", "-f", "--force-with-lease"} for arg in args[1:])

    @staticmethod
    def _is_recursive_world_writable(args: List[str]) -> bool:
        """Return true when chmod args represent recursive world-writable permissions."""
        has_recursive = any(
            arg == "-r" or (arg.startswith("-") and "r" in arg and not arg.startswith("--"))
            for arg in args
        )
        has_world_writable = any(CommandInspector._is_world_writable_mode(arg) for arg in args)

        return has_recursive and has_world_writable

    @staticmethod
    def _is_world_writable_mode(arg: str) -> bool:
        """Return true when a chmod mode grants write+execute access to everyone."""
        if arg == "777":
            return True

        if not any(operator in arg for operator in ("+", "=")):
            return False

        clauses = [clause for clause in arg.split(",") if clause]
        if not clauses:
            return False

        grants = {
            "u": set(),
            "g": set(),
            "o": set(),
        }

        for clause in clauses:
            match = re.fullmatch(r"([ugoa]*)([+=])([rwxXstugo]+)", clause)
            if not match:
                continue

            classes, _operator, permissions = match.groups()
            target_classes = set(classes or "a")
            if "a" in target_classes:
                target_classes.update({"u", "g", "o"})

            for class_name in target_classes & set(grants):
                grants[class_name].update(permissions.lower())

        return all({"r", "w", "x"}.issubset(grants[class_name]) for class_name in grants)

    @staticmethod
    def _is_package_publish_without_context(command: str, args: List[str]) -> bool:
        """Return true for package publish commands without explicit release context."""
        if not CommandInspector._is_package_publish_command(command, args):
            return False

        context_flags = {
            "--access",
            "--dry-run",
            "--index-url",
            "--otp",
            "--publish-url",
            "--registry",
            "--repository",
            "--repository-url",
            "--tag",
            "-r",
        }

        return not any(
            arg in context_flags or any(arg.startswith(f"{flag}=") for flag in context_flags if flag.startswith("--"))
            for arg in args
        )

    @staticmethod
    def _is_package_publish_command(command: str, args: List[str]) -> bool:
        """Return true for common package publish command shapes."""
        if command == "twine" and args[:1] == ["upload"]:
            return True

        if command in {"python", "python3", "py"} and args[:3] == ["-m", "twine", "upload"]:
            return True

        if command in {"uv", "poetry", "npm", "pnpm"} and args[:1] == ["publish"]:
            return True

        if command == "yarn" and args[:2] == ["npm", "publish"]:
            return True

        return False

    @staticmethod
    def _nested_command_payload(command: str, args: List[str]) -> Optional[str]:
        """Return the command string passed to common shell/interpreter wrappers."""
        shell_wrappers = {"sh", "bash", "zsh", "dash", "ksh"}
        if command in shell_wrappers:
            for index, arg in enumerate(args):
                if arg.lower() == "-c" and index + 1 < len(args):
                    return args[index + 1]

        if command in {"cmd", "cmd.exe"}:
            for index, arg in enumerate(args):
                if arg.lower() in {"/c", "/k"} and index + 1 < len(args):
                    return " ".join(args[index + 1 :])

        if command in {"pwsh", "pwsh.exe", "powershell", "powershell.exe"}:
            command_flags = {"-c", "-command", "/c", "/command"}
            encoded_flags = {"-encodedcommand", "-enc", "/encodedcommand", "/enc"}
            for index, arg in enumerate(args):
                lowered = arg.lower()
                if lowered in command_flags and index + 1 < len(args):
                    return " ".join(args[index + 1 :])
                if lowered in encoded_flags and index + 1 < len(args):
                    decoded = CommandInspector._decode_powershell_encoded_command(args[index + 1])
                    if decoded is not None:
                        return decoded

        interpreter_flags = {
            "python": {"-c"},
            "python3": {"-c"},
            "py": {"-c"},
            "node": {"-e", "--eval"},
            "ruby": {"-e"},
            "perl": {"-e"},
            "php": {"-r"},
        }
        flags = interpreter_flags.get(command)
        if flags:
            for index, arg in enumerate(args):
                if arg.lower() in flags and index + 1 < len(args):
                    return args[index + 1]

        return None

    @staticmethod
    def _nested_payload_is_dangerous(payload: str) -> bool:
        """Return true when a wrapped payload deterministically contains danger."""
        if not payload.strip():
            return False

        try:
            nested = CommandInspector.analyze_command(payload)
        except Exception:
            return True

        if not nested.get("is_valid"):
            return True

        if nested.get("risk_flags") or nested.get("is_dangerous"):
            return True

        try:
            from agent_circuit_breaker.inspectors.filesystem import FilesystemInspector
            from agent_circuit_breaker.inspectors.sql import SQLInspector
        except Exception:
            return False

        for segment in nested.get("segments") or []:
            operation = FilesystemInspector.analyze_operation(segment.get("raw") or "")
            if operation.get("operation") == "delete" and (
                operation.get("is_dangerous") or "recursive" in operation.get("flags", set())
            ):
                return True

        sql = SQLInspector.analyze_sql(payload)
        if sql.get("is_valid") and (sql.get("risk_flags") or sql.get("is_dangerous")):
            return True

        for embedded in CommandInspector._embedded_command_literals(payload):
            if embedded.strip() and CommandInspector._nested_payload_is_dangerous(embedded):
                return True

        return False

    @staticmethod
    def _decode_powershell_encoded_command(value: str) -> Optional[str]:
        """Decode PowerShell -EncodedCommand payloads without executing them."""
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return None

        for encoding in ("utf-16le", "utf-8"):
            try:
                decoded = raw.decode(encoding)
            except UnicodeDecodeError:
                continue
            if decoded.strip():
                return decoded
        return None

    @staticmethod
    def _embedded_command_literals(payload: str) -> List[str]:
        """Extract command string literals from common interpreter execution APIs."""
        candidates: List[str] = []
        patterns = (
            r"(?i)\b(?:os\.)?system\s*\(\s*(['\"])(?P<system>.*?)(?<!\\)\1",
            r"(?i)\b(?:exec|execSync|spawnSync)\s*\(\s*(['\"])(?P<exec>.*?)(?<!\\)\1",
            r"(?i)\bchild_process\.(?:exec|execSync|spawnSync)\s*\(\s*(['\"])(?P<child>.*?)(?<!\\)\1",
            r"(?i)\bsystem\s*\(\s*%q\{(?P<ruby>[^}]*)\}",
        )
        for pattern in patterns:
            for match in re.finditer(pattern, payload):
                for value in match.groupdict().values():
                    if value:
                        candidates.append(CommandInspector._unescape_literal(value))
        return candidates

    @staticmethod
    def _unescape_literal(value: str) -> str:
        """Decode common escaped quote and slash forms in extracted literals."""
        return (
            value.replace(r"\"", '"')
            .replace(r"\'", "'")
            .replace(r"\\", "\\")
        )

    @staticmethod
    def _is_destructive_docker(command: str, args: List[str]) -> bool:
        """Return true for destructive Docker command shapes."""
        if command != "docker" or not args:
            return False

        if args[:2] == ["system", "prune"] and ("-a" in args or "--all" in args or "--volumes" in args):
            return True

        if args[:2] in (["volume", "rm"], ["volume", "prune"], ["network", "rm"]):
            return True

        if args[:2] == ["image", "prune"] and ("-a" in args or "--all" in args):
            return True

        if args[:1] == ["rm"] and ("-f" in args or "--force" in args):
            return True

        if args[:3] in (["compose", "down", "--volumes"], ["compose", "down", "-v"]):
            return True

        if args[:2] == ["compose", "down"] and (
            "--volumes" in args or "-v" in args or "--rmi" in args
        ):
            return True

        return False

    @staticmethod
    def _is_cloud_resource_deletion(command: str, args: List[str]) -> bool:
        """Return true for common cloud resource deletion command shapes."""
        if command not in {"aws", "az", "gcloud"}:
            return False

        if args[:2] == ["s3", "rm"] and "--recursive" in args:
            return True

        if args[:2] == ["s3", "rb"]:
            return True

        destructive_tokens = {
            "delete",
            "destroy",
            "remove",
            "terminate-instances",
            "delete-stack",
            "delete-cluster",
            "delete-bucket",
            "delete-function",
            "delete-service",
        }

        return any(
            arg in destructive_tokens or arg.startswith("delete-")
            for arg in args
        )

    @staticmethod
    def _is_forceful_kubernetes_delete(command: str, args: List[str]) -> bool:
        """Return true for Kubernetes deletion commands using forceful flags."""
        if command not in {"kubectl", "oc"}:
            return False

        if not args or args[0] != "delete":
            return False

        force_flags = {"--force", "--now"}
        has_force = any(
            arg in force_flags or arg == "--grace-period=0"
            for arg in args[1:]
        )
        return has_force

    @staticmethod
    def _is_disk_overwrite_or_format(command: str, args: List[str]) -> bool:
        """Return true for commands that can overwrite or format block devices."""
        if command == "dd":
            return any(arg.startswith("of=/dev/") for arg in args)

        if command.startswith("mkfs"):
            return any(arg.startswith("/dev/") for arg in args)

        return False

    @staticmethod
    def _is_find_root_delete(command: str, args: List[str]) -> bool:
        """Return true for find-delete rooted at system-level paths."""
        if command != "find" or "-delete" not in args:
            return False

        dangerous_roots = {"/", "/etc", "/home", "/var", "/usr", "/root", "/sys"}
        return any(CommandInspector._is_dangerous_find_root(arg, dangerous_roots) for arg in args)

    @staticmethod
    def _is_dangerous_find_root(arg: str, dangerous_roots: set[str]) -> bool:
        """Return true when a find root is a protected path or its child."""
        if not arg.startswith("/"):
            return False

        normalized = arg.rstrip("/") or "/"
        if normalized == "/":
            return True

        for root in dangerous_roots - {"/"}:
            if normalized == root or normalized.startswith(f"{root}/"):
                return True

        return False

    @staticmethod
    def _has_shell_fork_bomb_shape(command: str) -> bool:
        """Return true for shell function fork bombs, regardless of function name."""
        pattern = re.compile(
            r"(?P<name>[:A-Za-z_][A-Za-z0-9_:-]*)"
            r"\s*\(\s*\)\s*\{\s*"
            r"(?P=name)\s*\|\s*(?P=name)\s*&\s*"
            r"\}\s*;\s*(?P=name)(?=$|\s|[;&|])"
        )
        return bool(pattern.search(command))

    @staticmethod
    def _mark_dangerous(segment: Dict[str, Any], flag: str, reason: str) -> None:
        """Mark a segment as dangerous with a risk flag and reason."""
        if flag not in segment["risk_flags"]:
            segment["risk_flags"].append(flag)

        segment["risk_score"] = CommandInspector._score_risks(segment["risk_flags"])
        segment["is_dangerous"] = True
        segment["danger_reason"] = reason

    @staticmethod
    def _score_risks(risk_flags: List[str]) -> int:
        """Return the highest score for the detected command risk flags."""
        if not risk_flags:
            return 0
        return max(CommandInspector.RISK_SCORES.get(flag, 50) for flag in risk_flags)

    @staticmethod
    def tokenize(command: str) -> List[str]:
        """
        Tokenize command text using POSIX shell lexical rules.

        Handles shell quote removal, quote concatenation, and backslash
        escaping through the Python stdlib `shlex` parser. Raises ValueError
        for malformed quoted input.
        """
        if not isinstance(command, str):
            raise ValueError("Command must be a string")

        try:
            lexer = shlex.shlex(normalize_for_matching(command), posix=True)
            lexer.whitespace_split = True
            lexer.commenters = ""
            return list(lexer)
        except ValueError as exc:
            message = str(exc)
            if "No closing quotation" in message:
                quote = "'" if "'" in command and '"' not in command else '"'
                raise ValueError(f"Unclosed {quote} quote") from exc
            raise
