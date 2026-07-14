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

    def test_delete_statement(self):
        """DELETE statement should tokenize without risk detection yet."""
        result = SQLInspector.analyze_sql("DELETE FROM users")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["tokens"], ["DELETE", "FROM", "users"])
        self.assertFalse(result["is_dangerous"])

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


if __name__ == "__main__":
    unittest.main()
