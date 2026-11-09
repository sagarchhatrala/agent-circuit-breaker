"""SQL Inspector - Tokenizes SQL text for later safety analysis."""

from decimal import Decimal, InvalidOperation
import re
from typing import Any, Dict, List, Optional

from agent_circuit_breaker.normalization import normalize_for_matching


class SQLInspector:
    """Inspects SQL text without executing it."""

    PUNCTUATION = {"*", "=", ",", "(", ")", ">", "<", "!"}
    RISK_SCORES = {
        "sql_drop_table": 100,
        "sql_drop_database": 100,
        "sql_truncate": 100,
        "sql_unqualified_delete": 85,
        "sql_unqualified_update": 85,
        "sql_tautological_delete": 90,
        "sql_tautological_update": 90,
    }

    @staticmethod
    def analyze_sql(sql: str) -> Dict[str, Any]:
        """
        Analyze SQL text into a deterministic token structure.

        This foundation step tokenizes, splits statements, and marks a small
        set of destructive SQL statement shapes for later rule evaluation.
        """
        result: Dict[str, Any] = {
            "raw": sql,
            "normalized": sql,
            "tokens": [],
            "statements": [],
            "is_valid": True,
            "error": None,
            "risk_flags": [],
            "risk_score": 0,
            "is_dangerous": False,
            "danger_reason": None,
        }

        if not isinstance(sql, str):
            result["is_valid"] = False
            result["error"] = "SQL must be a string"
            return result

        normalized = normalize_for_matching(sql)
        result["normalized"] = normalized

        if not normalized.strip():
            return result

        try:
            result["tokens"] = SQLInspector.tokenize(normalized)
            result["statements"] = SQLInspector.split_statements(normalized)
            SQLInspector._apply_risk_analysis(result)
        except ValueError as exc:
            result["is_valid"] = False
            result["error"] = str(exc)

        return result

    @staticmethod
    def split_statements(sql: str) -> List[Dict[str, Any]]:
        """Split SQL text into statements on semicolons outside comments and quotes."""
        if not isinstance(sql, str):
            raise ValueError("SQL must be a string")

        raw_statements: List[str] = []
        current: List[str] = []
        index = 0

        while index < len(sql):
            char = sql[index]
            next_char = sql[index + 1] if index + 1 < len(sql) else ""

            if char == "-" and next_char == "-":
                index = SQLInspector._skip_line_comment(sql, index + 2)
                current.append(" ")
                continue

            if char == "/" and next_char == "*":
                index = SQLInspector._skip_block_comment(sql, index + 2)
                current.append(" ")
                continue

            if char == "'":
                start = index
                token, index = SQLInspector._read_quoted(sql, index, "'")
                current.append(sql[start:index])
                continue

            if char == '"':
                start = index
                token, index = SQLInspector._read_quoted(sql, index, '"')
                current.append(sql[start:index])
                continue

            if char == ";":
                SQLInspector._append_statement(raw_statements, current)
                current = []
                index += 1
                continue

            current.append(char)
            index += 1

        SQLInspector._append_statement(raw_statements, current)

        return [
            SQLInspector._build_statement(statement)
            for statement in raw_statements
            if statement.strip()
        ]

    @staticmethod
    def tokenize(sql: str, *, _preserve_quotes: bool = False) -> List[str]:
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
                start = index
                token, index = SQLInspector._read_quoted(sql, index, "'")
                tokens.append(sql[start:index] if _preserve_quotes else token)
                continue

            if char == '"':
                SQLInspector._append_token(tokens, current)
                current = []
                start = index
                token, index = SQLInspector._read_quoted(sql, index, '"')
                tokens.append(sql[start:index] if _preserve_quotes else token)
                continue

            if char + next_char in {">=", "<=", "!=", "<>", "=="}:
                SQLInspector._append_token(tokens, current)
                current = []
                tokens.append(char + next_char)
                index += 2
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
    def _append_statement(raw_statements: List[str], current: List[str]) -> None:
        """Append current statement text when non-empty."""
        statement = "".join(current).strip()
        if statement:
            raw_statements.append(statement)

    @staticmethod
    def _build_statement(raw: str) -> Dict[str, Any]:
        """Build deterministic statement analysis for one SQL statement."""
        tokens = SQLInspector.tokenize(raw)
        return {
            "raw": raw,
            "tokens": tokens,
            "statement_type": tokens[0].lower() if tokens else None,
            "risk_flags": [],
            "risk_score": 0,
            "is_dangerous": False,
            "danger_reason": None,
        }

    @staticmethod
    def _apply_risk_analysis(result: Dict[str, Any]) -> None:
        """Apply statement risk detection and aggregate top-level flags."""
        risk_flags: List[str] = []
        danger_reasons: List[str] = []

        for statement in result["statements"]:
            SQLInspector._detect_statement_risks(statement)

            for risk_flag in statement["risk_flags"]:
                if risk_flag not in risk_flags:
                    risk_flags.append(risk_flag)

            danger_reason = statement["danger_reason"]
            if danger_reason and danger_reason not in danger_reasons:
                danger_reasons.append(danger_reason)

        result["risk_flags"] = risk_flags
        result["risk_score"] = SQLInspector._score_risks(risk_flags)
        result["is_dangerous"] = bool(risk_flags)
        result["danger_reason"] = "; ".join(danger_reasons) if danger_reasons else None

    @staticmethod
    def _detect_statement_risks(statement: Dict[str, Any]) -> None:
        """Mark destructive SQL statement shapes using parsed tokens only."""
        tokens = SQLInspector.tokenize(statement["raw"], _preserve_quotes=True)
        tokens = [token if token.startswith(("'", '"')) else token.lower() for token in tokens]
        risks = []
        for candidate in SQLInspector._policy_statements(tokens):
            for risk in SQLInspector._token_risks(candidate):
                if risk not in risks:
                    risks.append(risk)
        if not risks:
            return
        statement["risk_flags"] = [risk_flag for risk_flag, _ in risks]
        statement["risk_score"] = SQLInspector._score_risks(statement["risk_flags"])
        statement["is_dangerous"] = True
        statement["danger_reason"] = "; ".join(reason for _, reason in risks)

    @staticmethod
    def _policy_statements(tokens: List[str], depth: int = 0) -> List[List[str]]:
        """Expose the main statement and data-changing CTE bodies, never execute SQL."""
        if depth > 64:
            raise ValueError("SQL nesting exceeds inspection limit")
        if not tokens or tokens[0] != "with":
            return [tokens]
        statements = []
        index = 1
        while index < len(tokens):
            token = tokens[index]
            if token in {"select", "delete", "update", "insert", "replace"}:
                statements.append(tokens[index:])
                return statements
            if token == "(":
                end = SQLInspector._closing_parenthesis(tokens, index)
                body = tokens[index + 1:end]
                if body and body[0] in {"with", "delete", "update", "insert", "replace"}:
                    statements.extend(SQLInspector._policy_statements(body, depth + 1))
                index = end
            index += 1
        return statements

    @staticmethod
    def _closing_parenthesis(tokens: List[str], start: int) -> int:
        depth = 0
        for index in range(start, len(tokens)):
            if tokens[index] == "(":
                depth += 1
            elif tokens[index] == ")":
                depth -= 1
                if depth == 0:
                    return index
        raise ValueError("Unclosed SQL parenthesis")

    @staticmethod
    def _top_level_index(tokens: List[str], keyword: str) -> Optional[int]:
        depth = 0
        for index, token in enumerate(tokens):
            if token == "(":
                depth += 1
            elif token == ")":
                depth -= 1
            elif depth == 0 and token == keyword:
                return index
        return None

    @staticmethod
    def _token_risks(tokens_lower: List[str]) -> List[tuple[str, str]]:
        risks: List[tuple[str, str]] = []

        if len(tokens_lower) >= 2 and tokens_lower[:2] == ["drop", "table"]:
            risks.append(("sql_drop_table", "DROP TABLE detected"))

        if len(tokens_lower) >= 2 and tokens_lower[:2] == ["drop", "database"]:
            risks.append(("sql_drop_database", "DROP DATABASE detected"))

        if tokens_lower and tokens_lower[0] == "truncate":
            risks.append(("sql_truncate", "TRUNCATE detected"))

        if (
            len(tokens_lower) >= 3
            and tokens_lower[:2] == ["delete", "from"]
            and SQLInspector._top_level_index(tokens_lower, "where") is None
        ):
            risks.append(("sql_unqualified_delete", "Unqualified DELETE detected"))

        if (
            len(tokens_lower) >= 3
            and tokens_lower[:2] == ["delete", "from"]
            and SQLInspector._has_tautological_where(tokens_lower)
        ):
            risks.append(("sql_tautological_delete", "Tautological DELETE detected"))

        if (
            len(tokens_lower) >= 4
            and tokens_lower[0] == "update"
            and "set" in tokens_lower
            and SQLInspector._top_level_index(tokens_lower, "where") is None
        ):
            risks.append(("sql_unqualified_update", "Unqualified UPDATE detected"))

        if (
            len(tokens_lower) >= 4
            and tokens_lower[0] == "update"
            and "set" in tokens_lower
            and SQLInspector._has_tautological_where(tokens_lower)
        ):
            risks.append(("sql_tautological_update", "Tautological UPDATE detected"))

        return risks

    @staticmethod
    def _score_risks(risk_flags: List[str]) -> int:
        """Return the highest score for detected SQL risk flags."""
        if not risk_flags:
            return 0
        return max(SQLInspector.RISK_SCORES.get(flag, 50) for flag in risk_flags)

    @staticmethod
    def _has_tautological_where(tokens_lower: List[str]) -> bool:
        """Return true for simple always-true WHERE predicates."""
        where_index = SQLInspector._top_level_index(tokens_lower, "where")
        if where_index is None:
            return False
        predicate = tokens_lower[where_index + 1 :]
        for suffix in ("returning", "order", "limit"):
            index = SQLInspector._top_level_index(predicate, suffix)
            if index is not None:
                predicate = predicate[:index]
        if SQLInspector._constant_predicate(predicate) is True:
            return True

        if SQLInspector._has_update_functional_tautology(tokens_lower, predicate):
            return True

        return False

    @staticmethod
    def _constant_predicate(tokens: List[str], depth: int = 0) -> Optional[bool]:
        """Prove only literal predicates, respecting SQL AND/OR precedence.

        Unknown expressions stay unknown. No eval, database, or user code runs.
        In particular, a true conjunct cannot erase a selective predicate.
        """
        if depth > 64:
            raise ValueError("SQL predicate nesting exceeds inspection limit")
        while tokens and tokens[0] == "(" and SQLInspector._closing_parenthesis(tokens, 0) == len(tokens) - 1:
            tokens = tokens[1:-1]
            depth += 1
            if depth > 64:
                raise ValueError("SQL predicate nesting exceeds inspection limit")
        for operator in ("or", "and"):
            index = SQLInspector._top_level_index(tokens, operator)
            if index is not None:
                left = SQLInspector._constant_predicate(tokens[:index], depth + 1)
                right = SQLInspector._constant_predicate(tokens[index + 1:], depth + 1)
                if operator == "or":
                    return True if left is True or right is True else False if left is False and right is False else None
                return False if left is False or right is False else True if left is True and right is True else None
        if tokens[:1] == ["not"]:
            value = SQLInspector._constant_predicate(tokens[1:], depth + 1)
            return None if value is None else not value
        if len(tokens) == 1 and tokens[0] in {"true", "false"}:
            return tokens[0] == "true"
        if len(tokens) != 3 or tokens[1] not in {"=", "==", "!=", "<>", ">", "<", ">=", "<="}:
            return None
        left, operator, right = tokens
        # String ordering depends on collation. Equality of identical literals
        # is invariant; do not guess inequality or cross-type coercions.
        if left.startswith("'") or right.startswith("'"):
            if left == right and operator in {"=", "=="}:
                return True
            return None
        if not all(re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?", value) for value in (left, right)):
            return None
        try:
            a, b = Decimal(left), Decimal(right)
        except InvalidOperation:
            return None
        return {"=": a == b, "==": a == b, "!=": a != b, "<>": a != b,
                ">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b}[operator]

    @staticmethod
    def _has_update_functional_tautology(tokens_lower: List[str], predicate: List[str]) -> bool:
        """Detect UPDATE predicates that select every row the SET changes.

        Examples:
        - UPDATE users SET active = true WHERE active = false
        - UPDATE users SET status = active WHERE status != active
        - UPDATE users SET verified = true WHERE verified IS NULL
        """
        if not tokens_lower or tokens_lower[0] != "update" or "set" not in tokens_lower:
            return False
        try:
            set_index = tokens_lower.index("set")
            where_index = tokens_lower.index("where")
        except ValueError:
            return False
        if where_index <= set_index + 3:
            return False

        assignments = tokens_lower[set_index + 1 : where_index]
        if len(assignments) < 3 or assignments[1] != "=":
            return False
        set_col = assignments[0]
        set_val = assignments[2]
        if len(predicate) not in {3, 4} or predicate[0] != set_col:
            return False

        op = predicate[1]
        pred_val = predicate[2]
        if op in {"!=", "<>"} and pred_val == set_val:
            return True
        if op == "=" and SQLInspector._is_boolean_opposite(set_val, pred_val):
            return True
        if len(predicate) >= 3 and predicate[:3] == [set_col, "is", "null"] and set_val in {"true", "t", "1"}:
            return True
        if len(predicate) >= 4 and predicate[:4] == [set_col, "is", "not", set_val]:
            return True
        return False

    @staticmethod
    def _is_boolean_opposite(left: str, right: str) -> bool:
        true_values = {"true", "t", "1"}
        false_values = {"false", "f", "0"}
        return (left in true_values and right in false_values) or (left in false_values and right in true_values)

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
