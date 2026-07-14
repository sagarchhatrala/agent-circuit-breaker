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

        Supported operators: &&, ||, ;, |
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

            if char in (";", "|"):
                CommandInspector._append_segment(raw_segments, current)
                operators.append(char)
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
