"""SQL Inspector - Tokenizes SQL text for later safety analysis."""

from typing import Any, Dict, List, Optional


class SQLInspector:
    """Inspects SQL text without executing it."""

    PUNCTUATION = {"*", "=", ",", "(", ")"}

    @staticmethod
    def analyze_sql(sql: str) -> Dict[str, Any]:
        """
        Analyze SQL text into a deterministic token structure.

        This foundation step only tokenizes. Statement splitting and risk
        detection are added in later v0.3 slices.
        """
        result: Dict[str, Any] = {
            "raw": sql,
            "tokens": [],
            "statements": [],
            "is_valid": True,
            "error": None,
            "risk_flags": [],
            "is_dangerous": False,
            "danger_reason": None,
        }

        if not isinstance(sql, str):
            result["is_valid"] = False
            result["error"] = "SQL must be a string"
            return result

        if not sql.strip():
            return result

        try:
            result["tokens"] = SQLInspector.tokenize(sql)
        except ValueError as exc:
            result["is_valid"] = False
            result["error"] = str(exc)

        return result

    @staticmethod
    def tokenize(sql: str) -> List[str]:
        """
        Tokenize SQL text while ignoring comments.

        Handles whitespace, selected punctuation, single-quoted strings,
        double-quoted identifiers, line comments, and block comments.
        """
        if not isinstance(sql, str):
            raise ValueError("SQL must be a string")

        tokens: List[str] = []
        current: List[str] = []
        index = 0

        while index < len(sql):
            char = sql[index]
            next_char = sql[index + 1] if index + 1 < len(sql) else ""

            if char.isspace():
                SQLInspector._append_token(tokens, current)
                current = []
                index += 1
                continue

            if char == "-" and next_char == "-":
                SQLInspector._append_token(tokens, current)
                current = []
                index = SQLInspector._skip_line_comment(sql, index + 2)
                continue

            if char == "/" and next_char == "*":
                SQLInspector._append_token(tokens, current)
                current = []
                index = SQLInspector._skip_block_comment(sql, index + 2)
                continue

            if char == "'":
                SQLInspector._append_token(tokens, current)
                current = []
                token, index = SQLInspector._read_quoted(sql, index, "'")
                tokens.append(token)
                continue

            if char == '"':
                SQLInspector._append_token(tokens, current)
                current = []
                token, index = SQLInspector._read_quoted(sql, index, '"')
                tokens.append(token)
                continue

            if char in SQLInspector.PUNCTUATION:
                SQLInspector._append_token(tokens, current)
                current = []
                tokens.append(char)
                index += 1
                continue

            current.append(char)
            index += 1

        SQLInspector._append_token(tokens, current)
        return tokens

    @staticmethod
    def _append_token(tokens: List[str], current: List[str]) -> None:
        """Append current token text when non-empty."""
        if current:
            tokens.append("".join(current))

    @staticmethod
    def _read_quoted(sql: str, start: int, quote: str) -> tuple[str, int]:
        """Read a quoted SQL string or identifier."""
        current: List[str] = []
        index = start + 1

        while index < len(sql):
            char = sql[index]
            next_char = sql[index + 1] if index + 1 < len(sql) else ""

            if char == quote:
                if next_char == quote:
                    current.append(quote)
                    index += 2
                    continue

                return "".join(current), index + 1

            current.append(char)
            index += 1

        raise ValueError(f"Unclosed {quote} quote")

    @staticmethod
    def _skip_line_comment(sql: str, start: int) -> int:
        """Skip a SQL line comment."""
        index = start
        while index < len(sql) and sql[index] not in ("\n", "\r"):
            index += 1
        return index

    @staticmethod
    def _skip_block_comment(sql: str, start: int) -> int:
        """Skip a SQL block comment."""
        index = start
        while index < len(sql) - 1:
            if sql[index] == "*" and sql[index + 1] == "/":
                return index + 2
            index += 1

        raise ValueError("Unclosed block comment")
