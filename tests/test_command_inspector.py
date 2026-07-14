"""Tests for Command Inspector tokenizer foundation."""

import unittest

from agent_circuit_breaker.inspectors.command import CommandInspector


class TestCommandInspectorAnalysis(unittest.TestCase):
    """Test command analysis output shape."""

    def test_empty_command(self):
        """Empty input should produce a valid empty analysis."""
        result = CommandInspector.analyze_command("")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["tokens"], [])
        self.assertIsNone(result["command"])
        self.assertEqual(result["args"], [])
        self.assertEqual(result["segments"], [])
        self.assertEqual(result["operators"], [])
        self.assertFalse(result["is_dangerous"])

    def test_whitespace_command(self):
        """Whitespace-only input should produce a valid empty analysis."""
        result = CommandInspector.analyze_command("   \t  ")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["tokens"], [])
        self.assertIsNone(result["command"])

    def test_non_string_command(self):
        """Non-string input should produce an explicit invalid analysis."""
        result = CommandInspector.analyze_command(None)

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["error"], "Command must be a string")
        self.assertEqual(result["tokens"], [])

    def test_basic_command(self):
        """Basic commands should split into command and args."""
        result = CommandInspector.analyze_command("git status")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["tokens"], ["git", "status"])
        self.assertEqual(result["command"], "git")
        self.assertEqual(result["args"], ["status"])
        self.assertEqual(len(result["segments"]), 1)
        self.assertEqual(result["segments"][0]["raw"], "git status")

    def test_double_quoted_string(self):
        """Double quoted strings should stay as one token."""
        result = CommandInspector.analyze_command('echo "hello world"')

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["tokens"], ["echo", "hello world"])
        self.assertEqual(result["args"], ["hello world"])

    def test_single_quoted_string(self):
        """Single quoted strings should stay as one token."""
        result = CommandInspector.analyze_command("cat '.env'")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["tokens"], ["cat", ".env"])

    def test_malformed_double_quote(self):
        """Unclosed double quote should be explicit invalid input."""
        result = CommandInspector.analyze_command('echo "hello')

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["tokens"], [])
        self.assertIn("Unclosed", result["error"])

    def test_malformed_single_quote(self):
        """Unclosed single quote should be explicit invalid input."""
        result = CommandInspector.analyze_command("cat '.env")

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["tokens"], [])
        self.assertIn("Unclosed", result["error"])


class TestCommandInspectorTokenize(unittest.TestCase):
    """Test tokenizer details."""

    def test_backslash_escaped_space(self):
        """Backslash escapes should keep the next character in the token."""
        tokens = CommandInspector.tokenize(r"echo hello\ world")

        self.assertEqual(tokens, ["echo", "hello world"])

    def test_quoted_substring_in_token(self):
        """Quoted substrings should combine with surrounding token text."""
        tokens = CommandInspector.tokenize('echo file-"name with spaces".txt')

        self.assertEqual(tokens, ["echo", "file-name with spaces.txt"])

    def test_repeated_whitespace(self):
        """Repeated whitespace should not create empty tokens."""
        tokens = CommandInspector.tokenize("git    status\t--short")

        self.assertEqual(tokens, ["git", "status", "--short"])

    def test_non_string_tokenize_raises(self):
        """Direct tokenization rejects non-string input."""
        with self.assertRaises(ValueError):
            CommandInspector.tokenize(None)


class TestCommandInspectorSegments(unittest.TestCase):
    """Test command segment splitting on shell operators."""

    def test_and_operator(self):
        """Commands joined with && should split into two segments."""
        result = CommandInspector.analyze_command("echo ok && git status")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["operators"], ["&&"])
        self.assertEqual([segment["raw"] for segment in result["segments"]], ["echo ok", "git status"])
        self.assertEqual(result["segments"][0]["tokens"], ["echo", "ok"])
        self.assertEqual(result["segments"][1]["tokens"], ["git", "status"])

    def test_or_operator(self):
        """Commands joined with || should split into two segments."""
        result = CommandInspector.analyze_command("false || echo fallback")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["operators"], ["||"])
        self.assertEqual([segment["command"] for segment in result["segments"]], ["false", "echo"])

    def test_semicolon_operator(self):
        """Commands joined with semicolon should split into two segments."""
        result = CommandInspector.analyze_command("echo one; echo two")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["operators"], [";"])
        self.assertEqual([segment["raw"] for segment in result["segments"]], ["echo one", "echo two"])

    def test_pipe_operator(self):
        """Commands joined with a pipe should split into two segments."""
        result = CommandInspector.analyze_command("cat file | grep text")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["operators"], ["|"])
        self.assertEqual([segment["command"] for segment in result["segments"]], ["cat", "grep"])

    def test_multiple_operators(self):
        """Multiple operators should preserve order."""
        result = CommandInspector.analyze_command("echo ok && git status | cat")

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["operators"], ["&&", "|"])
        self.assertEqual([segment["raw"] for segment in result["segments"]], ["echo ok", "git status", "cat"])

    def test_quoted_operator_not_split(self):
        """Operators inside quotes should not split command segments."""
        result = CommandInspector.analyze_command('echo "a && b"')

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["operators"], [])
        self.assertEqual(len(result["segments"]), 1)
        self.assertEqual(result["tokens"], ["echo", "a && b"])

    def test_malformed_quote_invalid_for_segments(self):
        """Malformed quotes should remain invalid with segment splitting."""
        result = CommandInspector.analyze_command('echo "a && b')

        self.assertFalse(result["is_valid"])
        self.assertEqual(result["segments"], [])
        self.assertIn("Unclosed", result["error"])

    def test_split_segments_directly(self):
        """Direct segment splitting should expose segments and operators."""
        result = CommandInspector.split_segments("cat file | grep text")

        self.assertEqual(result["operators"], ["|"])
        self.assertEqual([segment["tokens"] for segment in result["segments"]], [["cat", "file"], ["grep", "text"]])


class TestCommandInspectorDeterminism(unittest.TestCase):
    """Test deterministic command analysis."""

    def test_same_command_same_result(self):
        """Repeated analysis should return the same structure."""
        command = 'echo "hello world"'

        result1 = CommandInspector.analyze_command(command)
        result2 = CommandInspector.analyze_command(command)
        result3 = CommandInspector.analyze_command(command)

        self.assertEqual(result1, result2)
        self.assertEqual(result2, result3)

    def test_same_chain_same_result(self):
        """Repeated chain analysis should return the same structure."""
        command = 'echo "a && b" && git status | cat'

        result1 = CommandInspector.analyze_command(command)
        result2 = CommandInspector.analyze_command(command)
        result3 = CommandInspector.analyze_command(command)

        self.assertEqual(result1, result2)
        self.assertEqual(result2, result3)


if __name__ == "__main__":
    unittest.main()
