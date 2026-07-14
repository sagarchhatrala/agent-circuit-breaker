"""Tests for SQL Inspector tokenizer foundation."""

import unittest

from agent_circuit_breaker.inspectors.sql import SQLInspector


class TestSQLInspectorAnalysis(unittest.TestCase):
    """Test SQL analysis output shape."""

    def test_empty_sql(self):
        """Empty SQL should produce a valid empty analysis."""
        result = SQLInspector.analyze_sql("")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["tokens"], [])
        self.assertEqual(result["statements"], [])
        self.assertEqual(result["risk_flags"], [])
        self.assertFalse(result["is_dangerous"])

    def test_whitespace_sql(self):
        """Whitespace-only SQL should produce a valid empty analysis."""
        result = SQLInspector.analyze_sql("   \n\t  ")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["tokens"], [])

    def test_non_string_sql(self):
        """Non-string SQL should produce an explicit invalid analysis."""
        result = SQLInspector.analyze_sql(None)

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["error"], "SQL must be a string")
        self.assertEqual(result["tokens"], [])

    def test_basic_select(self):
        """Basic SELECT should tokenize words and punctuation."""
        result = SQLInspector.analyze_sql("SELECT * FROM users")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["tokens"], ["SELECT", "*", "FROM", "users"])
        self.assertEqual(len(result["statements"]), 1)
        self.assertEqual(result["statements"][0]["raw"], "SELECT * FROM users")

    def test_delete_statement(self):
        """Unqualified DELETE statement should be marked dangerous."""
        result = SQLInspector.analyze_sql("DELETE FROM users")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["tokens"], ["DELETE", "FROM", "users"])
        self.assertEqual(result["statements"][0]["statement_type"], "delete")
        self.assertTrue(result["is_dangerous"])
        self.assertEqual(result["risk_flags"], ["sql_unqualified_delete"])

    def test_update_statement_with_punctuation(self):
        """UPDATE statement should tokenize assignment punctuation."""
        result = SQLInspector.analyze_sql("UPDATE users SET active = false")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["tokens"], ["UPDATE", "users", "SET", "active", "=", "false"])


class TestSQLInspectorTokenize(unittest.TestCase):
    """Test SQL tokenizer details."""

    def test_single_quoted_string(self):
        """Single-quoted strings should stay as one token."""
        tokens = SQLInspector.tokenize("SELECT 'DROP TABLE users'")

        self.assertEqual(tokens, ["SELECT", "DROP TABLE users"])

    def test_single_quote_escape(self):
        """Doubled single quotes should unescape inside string tokens."""
        tokens = SQLInspector.tokenize("SELECT 'Bob''s account'")

        self.assertEqual(tokens, ["SELECT", "Bob's account"])

    def test_double_quoted_identifier(self):
        """Double-quoted identifiers should stay as one token."""
        tokens = SQLInspector.tokenize('SELECT "user name" FROM users')

        self.assertEqual(tokens, ["SELECT", "user name", "FROM", "users"])

    def test_double_quote_escape(self):
        """Doubled double quotes should unescape inside identifier tokens."""
        tokens = SQLInspector.tokenize('SELECT "weird""name" FROM users')

        self.assertEqual(tokens, ["SELECT", 'weird"name', "FROM", "users"])

    def test_punctuation_tokens(self):
        """Selected punctuation should be separate tokens."""
        tokens = SQLInspector.tokenize("SELECT id,name FROM users WHERE id=(1)")

        self.assertEqual(
            tokens,
            ["SELECT", "id", ",", "name", "FROM", "users", "WHERE", "id", "=", "(", "1", ")"],
        )

    def test_line_comment_ignored(self):
        """Line comments should be ignored."""
        tokens = SQLInspector.tokenize("SELECT 1 -- DELETE FROM users\nFROM dual")

        self.assertEqual(tokens, ["SELECT", "1", "FROM", "dual"])

    def test_block_comment_ignored(self):
        """Block comments should be ignored."""
        tokens = SQLInspector.tokenize("SELECT /* DROP TABLE users */ 1")

        self.assertEqual(tokens, ["SELECT", "1"])

    def test_unclosed_single_quote_invalid(self):
        """Unclosed single quote should be explicit invalid input."""
        result = SQLInspector.analyze_sql("SELECT 'abc")

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["tokens"], [])
        self.assertIn("Unclosed", result["error"])

    def test_unclosed_double_quote_invalid(self):
        """Unclosed double quote should be explicit invalid input."""
        result = SQLInspector.analyze_sql('SELECT "abc')

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["tokens"], [])
        self.assertIn("Unclosed", result["error"])

    def test_unclosed_block_comment_invalid(self):
        """Unclosed block comment should be explicit invalid input."""
        result = SQLInspector.analyze_sql("SELECT /* abc")

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["tokens"], [])
        self.assertEqual(result["error"], "Unclosed block comment")

    def test_non_string_tokenize_raises(self):
        """Direct tokenization rejects non-string input."""
        with self.assertRaises(ValueError):
            SQLInspector.tokenize(None)


class TestSQLInspectorStatements(unittest.TestCase):
    """Test SQL statement splitting."""

    def test_two_select_statements(self):
        """Semicolon should split two statements."""
        result = SQLInspector.analyze_sql("SELECT 1; SELECT 2")

        self.assertTrue(result["is_valid"])
        self.assertEqual([statement["raw"] for statement in result["statements"]], ["SELECT 1", "SELECT 2"])
        self.assertEqual([statement["tokens"] for statement in result["statements"]], [["SELECT", "1"], ["SELECT", "2"]])

    def test_delete_then_select(self):
        """Multiple statement types should preserve order."""
        result = SQLInspector.analyze_sql("DELETE FROM users; SELECT * FROM users")

        self.assertTrue(result["is_valid"])
        self.assertEqual(
            [statement["statement_type"] for statement in result["statements"]],
            ["delete", "select"],
        )

    def test_semicolon_inside_single_quote_not_split(self):
        """Semicolons inside single-quoted strings should not split."""
        result = SQLInspector.analyze_sql("SELECT ';'")

        self.assertTrue(result["is_valid"])
        self.assertEqual(len(result["statements"]), 1)
        self.assertEqual(result["statements"][0]["tokens"], ["SELECT", ";"])

    def test_semicolon_inside_double_quote_not_split(self):
        """Semicolons inside double-quoted identifiers should not split."""
        result = SQLInspector.analyze_sql('SELECT "a;b" FROM users')

        self.assertTrue(result["is_valid"])
        self.assertEqual(len(result["statements"]), 1)
        self.assertEqual(result["statements"][0]["tokens"], ["SELECT", "a;b", "FROM", "users"])

    def test_line_comment_after_statement(self):
        """Line comments should be ignored during statement splitting."""
        result = SQLInspector.analyze_sql("SELECT 1; -- comment\nSELECT 2")

        self.assertTrue(result["is_valid"])
        self.assertEqual([statement["raw"] for statement in result["statements"]], ["SELECT 1", "SELECT 2"])

    def test_block_comment_semicolon_not_split(self):
        """Semicolons inside block comments should not split."""
        result = SQLInspector.analyze_sql("SELECT /* ; */ 1; SELECT 2")

        self.assertTrue(result["is_valid"])
        self.assertEqual([statement["tokens"] for statement in result["statements"]], [["SELECT", "1"], ["SELECT", "2"]])

    def test_trailing_semicolon_ignored(self):
        """Trailing semicolon should not create an empty statement."""
        result = SQLInspector.analyze_sql("SELECT 1;")

        self.assertTrue(result["is_valid"])
        self.assertEqual(len(result["statements"]), 1)

    def test_split_statements_directly(self):
        """Direct statement splitting should expose statement dictionaries."""
        statements = SQLInspector.split_statements("SELECT 1; SELECT 2")

        self.assertEqual([statement["tokens"] for statement in statements], [["SELECT", "1"], ["SELECT", "2"]])

    def test_malformed_quote_invalid_for_statements(self):
        """Malformed quote should keep analysis invalid."""
        result = SQLInspector.analyze_sql("SELECT ';")

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["statements"], [])
        self.assertIn("Unclosed", result["error"])

    def test_malformed_block_comment_invalid_for_statements(self):
        """Malformed block comment should keep analysis invalid."""
        result = SQLInspector.analyze_sql("SELECT /* ;")

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["statements"], [])
        self.assertEqual(result["error"], "Unclosed block comment")


class TestSQLInspectorDestructiveStatements(unittest.TestCase):
    """Test destructive SQL statement detection."""

    def assertDangerousSql(self, sql, expected_flags, expected_reason):
        """Assert a SQL string is marked dangerous with expected flags."""
        result = SQLInspector.analyze_sql(sql)

        self.assertTrue(result["is_valid"])
        self.assertTrue(result["is_dangerous"])
        self.assertEqual(result["risk_flags"], expected_flags)
        self.assertEqual(result["danger_reason"], expected_reason)
        self.assertTrue(result["statements"][0]["is_dangerous"])
        self.assertEqual(result["statements"][0]["risk_flags"], expected_flags)

    def test_drop_table_dangerous(self):
        """DROP TABLE should be marked dangerous."""
        self.assertDangerousSql(
            "DROP TABLE users",
            ["sql_drop_table"],
            "DROP TABLE detected",
        )

    def test_drop_database_dangerous(self):
        """DROP DATABASE should be marked dangerous."""
        self.assertDangerousSql(
            "DROP DATABASE prod",
            ["sql_drop_database"],
            "DROP DATABASE detected",
        )

    def test_truncate_dangerous(self):
        """TRUNCATE should be marked dangerous."""
        self.assertDangerousSql(
            "TRUNCATE users",
            ["sql_truncate"],
            "TRUNCATE detected",
        )

    def test_truncate_table_dangerous(self):
        """TRUNCATE TABLE should be marked dangerous."""
        self.assertDangerousSql(
            "TRUNCATE TABLE users",
            ["sql_truncate"],
            "TRUNCATE detected",
        )

    def test_unqualified_delete_dangerous(self):
        """DELETE FROM without WHERE should be marked dangerous."""
        self.assertDangerousSql(
            "DELETE FROM users",
            ["sql_unqualified_delete"],
            "Unqualified DELETE detected",
        )

    def test_unqualified_update_dangerous(self):
        """UPDATE without WHERE should be marked dangerous."""
        self.assertDangerousSql(
            "UPDATE users SET active = false",
            ["sql_unqualified_update"],
            "Unqualified UPDATE detected",
        )

    def test_quoted_drop_table_not_dangerous(self):
        """Destructive text inside a quoted string should not be dangerous."""
        result = SQLInspector.analyze_sql("SELECT 'DROP TABLE users'")

        self.assertTrue(result["is_valid"])
        self.assertFalse(result["is_dangerous"])
        self.assertEqual(result["risk_flags"], [])

    def test_quoted_line_comment_not_dangerous(self):
        """Comment-like text inside a quoted string should not be dangerous."""
        result = SQLInspector.analyze_sql("SELECT '-- DELETE FROM users'")

        self.assertTrue(result["is_valid"])
        self.assertFalse(result["is_dangerous"])
        self.assertEqual(result["risk_flags"], [])

    def test_qualified_delete_not_dangerous(self):
        """DELETE FROM with WHERE should not be marked dangerous."""
        result = SQLInspector.analyze_sql("DELETE FROM users WHERE id = 1")

        self.assertTrue(result["is_valid"])
        self.assertFalse(result["is_dangerous"])
        self.assertEqual(result["risk_flags"], [])

    def test_qualified_update_not_dangerous(self):
        """UPDATE with WHERE should not be marked dangerous."""
        result = SQLInspector.analyze_sql("UPDATE users SET active = false WHERE id = 1")

        self.assertTrue(result["is_valid"])
        self.assertFalse(result["is_dangerous"])
        self.assertEqual(result["risk_flags"], [])

    def test_identifier_containing_truncate_not_dangerous(self):
        """A table name containing truncate should not be marked dangerous."""
        result = SQLInspector.analyze_sql("SELECT * FROM truncate_log")

        self.assertTrue(result["is_valid"])
        self.assertFalse(result["is_dangerous"])
        self.assertEqual(result["risk_flags"], [])

    def test_multiple_statements_aggregate_risks(self):
        """Multiple destructive statements should aggregate unique flags."""
        result = SQLInspector.analyze_sql("DROP TABLE users; DELETE FROM audit_log")

        self.assertTrue(result["is_valid"])
        self.assertTrue(result["is_dangerous"])
        self.assertEqual(result["risk_flags"], ["sql_drop_table", "sql_unqualified_delete"])
        self.assertEqual(result["danger_reason"], "DROP TABLE detected; Unqualified DELETE detected")

    def test_dangerous_analysis_deterministic(self):
        """Repeated destructive SQL analysis should return the same structure."""
        sql = "DROP DATABASE prod; UPDATE users SET active = false"

        result1 = SQLInspector.analyze_sql(sql)
        result2 = SQLInspector.analyze_sql(sql)
        result3 = SQLInspector.analyze_sql(sql)

        self.assertEqual(result1, result2)
        self.assertEqual(result2, result3)


class TestSQLInspectorDeterminism(unittest.TestCase):
    """Test deterministic SQL analysis."""

    def test_same_sql_same_result(self):
        """Repeated analysis should return the same structure."""
        sql = "SELECT 'DROP TABLE users' FROM logs"

        result1 = SQLInspector.analyze_sql(sql)
        result2 = SQLInspector.analyze_sql(sql)
        result3 = SQLInspector.analyze_sql(sql)

        self.assertEqual(result1, result2)
        self.assertEqual(result2, result3)

    def test_same_sql_statements_same_result(self):
        """Repeated statement splitting should return the same structure."""
        sql = "SELECT ';'; SELECT /* ignored ; */ 2"

        result1 = SQLInspector.analyze_sql(sql)
        result2 = SQLInspector.analyze_sql(sql)
        result3 = SQLInspector.analyze_sql(sql)

        self.assertEqual(result1, result2)
        self.assertEqual(result2, result3)


if __name__ == "__main__":
    unittest.main()
