"""Command Inspector - Tokenizes shell commands for later safety analysis."""

from typing import Any, Dict, List, Optional


class CommandInspector:
    """Inspects shell command text without executing it."""

    @staticmethod
    def analyze_command(command: str) -> Dict[str, Any]:
        """
        Analyze a command string into a deterministic token structure.

        This foundation step only tokenizes and identifies the command/args.
        Risk detection is added in later v0.2 slices.
        """
        result: Dict[str, Any] = {
            "raw": command,
            "tokens": [],
            "command": None,
            "args": [],
            "segments": [],
            "operators": [],
            "is_valid": True,
            "error": None,
            "risk_flags": [],
            "is_dangerous": False,
            "danger_reason": None,
        }

        if not isinstance(command, str):
            result["is_valid"] = False
            result["error"] = "Command must be a string"
            return result

        if not command.strip():
            return result

        try:
            split_result = CommandInspector.split_segments(command)
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
            "is_dangerous": False,
            "danger_reason": None,
        }

    @staticmethod
    def _apply_risk_analysis(result: Dict[str, Any]) -> None:
        """Apply command risk detection to all analyzed segments."""
        for index, segment in enumerate(result["segments"]):
            CommandInspector._detect_segment_risks(segment)
            CommandInspector._detect_pipeline_risks(result, index)

        risk_flags: List[str] = []
        danger_reasons: List[str] = []

        for segment in result["segments"]:
            for flag in segment["risk_flags"]:
                if flag not in risk_flags:
                    risk_flags.append(flag)

            if segment["danger_reason"] and segment["danger_reason"] not in danger_reasons:
                danger_reasons.append(segment["danger_reason"])

        result["risk_flags"] = risk_flags
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
        """Return true when chmod args represent recursive chmod 777."""
        has_recursive = any(
            arg == "-r" or (arg.startswith("-") and "r" in arg and not arg.startswith("--"))
            for arg in args
        )
        has_world_writable = "777" in args

        return has_recursive and has_world_writable

    @staticmethod
    def _mark_dangerous(segment: Dict[str, Any], flag: str, reason: str) -> None:
        """Mark a segment as dangerous with a risk flag and reason."""
        if flag not in segment["risk_flags"]:
            segment["risk_flags"].append(flag)

        segment["is_dangerous"] = True
        segment["danger_reason"] = reason

    @staticmethod
    def tokenize(command: str) -> List[str]:
        """
        Tokenize command text while preserving quoted strings as single tokens.

        Handles whitespace, single quotes, double quotes, and simple backslash
        escaping. Raises ValueError for malformed quoted input.
        """
        if not isinstance(command, str):
            raise ValueError("Command must be a string")

        tokens: List[str] = []
        current: List[str] = []
        quote: Optional[str] = None
        escaped = False

        for char in command:
            if escaped:
                current.append(char)
                escaped = False
                continue

            if char == "\\":
                escaped = True
                continue

            if quote:
                if char == quote:
                    quote = None
                else:
                    current.append(char)
                continue

            if char in ("'", '"'):
                quote = char
                continue

            if char.isspace():
                if current:
                    tokens.append("".join(current))
                    current = []
                continue

            current.append(char)

        if escaped:
            current.append("\\")

        if quote:
            raise ValueError(f"Unclosed {quote} quote")

        if current:
            tokens.append("".join(current))

        return tokens
