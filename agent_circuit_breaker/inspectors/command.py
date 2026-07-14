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
            tokens = CommandInspector.tokenize(command)
        except ValueError as exc:
            result["is_valid"] = False
            result["error"] = str(exc)
            return result

        result["tokens"] = tokens
        if tokens:
            result["command"] = tokens[0]
            result["args"] = tokens[1:]

        return result

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
