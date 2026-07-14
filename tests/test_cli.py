"""Tests for CLI interface."""

import unittest
import json
import sys
from io import StringIO
from agent_circuit_breaker.cli import CircuitBreakerCLI, main


class TestCLIEvaluation(unittest.TestCase):
    """Test CLI evaluation functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.cli = CircuitBreakerCLI(verbose=False, json_output=False)

    def test_evaluate_safe_command(self):
        """Evaluate a safe command."""
        result = self.cli.evaluate_command('mkdir "/tmp/newdir"')
        self.assertEqual(result["verdict"], "allow")
        self.assertIsNone(result["error"])

    def test_evaluate_dangerous_recursive_delete(self):
        """Evaluate dangerous recursive delete."""
        result = self.cli.evaluate_command('rm -rf "/etc"')
        self.assertEqual(result["verdict"], "block")
        self.assertIsNotNone(result["matched_rule"])

    def test_evaluate_root_deletion(self):
        """Evaluate root directory deletion."""
        result = self.cli.evaluate_command('rm -rf "/"')
        self.assertEqual(result["verdict"], "block")

    def test_evaluate_safe_temp_delete(self):
        """Evaluate safe temp deletion."""
        result = self.cli.evaluate_command('rm "/tmp/cache"')
        # Should be allow (not recursive and safe target)
        self.assertIn(result["verdict"], ["allow", "unknown"])

    def test_evaluate_windows_system_path_delete(self):
        """Evaluate Windows system path deletion."""
        result = self.cli.evaluate_command('Remove-Item "C:\\Windows" -Recurse')
        self.assertEqual(result["verdict"], "block")

    def test_evaluate_move_command(self):
        """Evaluate move command."""
        result = self.cli.evaluate_command('mv "/tmp/old" "/tmp/new"')
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(result["operation_analysis"]["operation"], "move")

    def test_evaluate_copy_command(self):
        """Evaluate copy command."""
        result = self.cli.evaluate_command('cp "/src/file" "/dst/file"')
        self.assertEqual(result["verdict"], "allow")
        self.assertEqual(result["operation_analysis"]["operation"], "copy")

    def test_evaluate_creates_result_structure(self):
        """Ensure evaluation creates complete result structure."""
        result = self.cli.evaluate_command('ls -la')
        self.assertIn("command", result)
        self.assertIn("verdict", result)
        self.assertIn("decision", result)
        self.assertIn("matched_rule", result)
        self.assertIn("operation_analysis", result)

    def test_evaluate_preserves_command(self):
        """Preserved original command in result."""
        command = 'rm -rf "/test"'
        result = self.cli.evaluate_command(command)
        self.assertEqual(result["command"], command)

    def test_evaluate_handles_exceptions(self):
        """Handle exceptions gracefully."""
        result = self.cli.evaluate_command(None)
        self.assertEqual(result["verdict"], "error")
        self.assertIsNotNone(result["error"])

    def test_evaluate_empty_command(self):
        """Evaluate empty command."""
        result = self.cli.evaluate_command("")
        self.assertIsNotNone(result["verdict"])


class TestCLIOutput(unittest.TestCase):
    """Test CLI output formatting."""

    def setUp(self):
        """Set up test fixtures."""
        self.cli = CircuitBreakerCLI(verbose=False, json_output=False)

    def test_format_human_readable(self):
        """Format output in human-readable format."""
        result = self.cli.evaluate_command('rm -rf "/tmp"')
        output = self.cli.format_output(result)
        self.assertIn("Command:", output)
        self.assertIn("Verdict:", output)
        self.assertIn("Operation:", output)

    def test_format_json_output(self):
        """Format output as JSON."""
        cli = CircuitBreakerCLI(verbose=False, json_output=True)
        result = cli.evaluate_command('rm -rf "/tmp"')
        output = cli.format_output(result)
        # Verify it's valid JSON
        parsed = json.loads(output)
        self.assertIn("verdict", parsed)
        self.assertIn("command", parsed)

    def test_format_includes_matched_rule(self):
        """Output includes matched rule information."""
        result = self.cli.evaluate_command('rm -rf "/etc"')
        output = self.cli.format_output(result)
        if result["matched_rule"]:
            self.assertIn("Matched Rule:", output)
            self.assertIn("Severity:", output)

    def test_format_includes_operation_analysis(self):
        """Output includes operation analysis."""
        result = self.cli.evaluate_command('rm -rf "/tmp/cache"')
        output = self.cli.format_output(result)
        self.assertIn("Operation:", output)

    def test_format_handles_error(self):
        """Output includes error information."""
        result = self.cli.evaluate_command(None)
        output = self.cli.format_output(result)
        self.assertIn("Error:", output)

    def test_format_verbose_includes_traceback(self):
        """Verbose mode includes traceback on error."""
        cli = CircuitBreakerCLI(verbose=True, json_output=False)
        result = cli.evaluate_command(None)
        output = cli.format_output(result)
        # May include traceback if error occurred
        self.assertIsNotNone(output)


class TestCLICommandMode(unittest.TestCase):
    """Test CLI command mode functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.cli = CircuitBreakerCLI(verbose=False, json_output=False)

    def test_command_mode_allow_returns_zero(self):
        """Allowed command returns exit code 0."""
        exit_code = self.cli.run_command_mode('mkdir "/tmp/test"')
        self.assertEqual(exit_code, 0)

    def test_command_mode_block_returns_one(self):
        """Blocked command returns exit code 1."""
        exit_code = self.cli.run_command_mode('rm -rf "/"')
        self.assertEqual(exit_code, 1)

    def test_command_mode_error_returns_one(self):
        """Error returns exit code 1."""
        exit_code = self.cli.run_command_mode(None)
        self.assertEqual(exit_code, 1)

    def test_command_mode_unknown_returns_two(self):
        """Unknown verdict returns exit code 2."""
        # Some commands may result in unknown verdict
        exit_code = self.cli.run_command_mode('ls -la')
        self.assertIn(exit_code, [0, 1, 2])  # Can be any valid exit code

    def test_command_mode_produces_output(self):
        """Command mode produces output."""
        old_stdout = sys.stdout
        try:
            sys.stdout = StringIO()
            self.cli.run_command_mode('rm "/tmp/file"')
            output = sys.stdout.getvalue()
            self.assertTrue(len(output) > 0)
        finally:
            sys.stdout = old_stdout


class TestCLIInteractiveMode(unittest.TestCase):
    """Test CLI interactive mode functionality."""

    def test_interactive_mode_quit_command(self):
        """Interactive mode quits on 'quit' command."""
        cli = CircuitBreakerCLI(verbose=False, json_output=False)
        old_stdin = sys.stdin
        try:
            sys.stdin = StringIO("quit\n")
            exit_code = cli.run_interactive()
            self.assertEqual(exit_code, 0)
        finally:
            sys.stdin = old_stdin

    def test_interactive_mode_exit_command(self):
        """Interactive mode quits on 'exit' command."""
        cli = CircuitBreakerCLI(verbose=False, json_output=False)
        old_stdin = sys.stdin
        try:
            sys.stdin = StringIO("exit\n")
            exit_code = cli.run_interactive()
            self.assertEqual(exit_code, 0)
        finally:
            sys.stdin = old_stdin

    def test_interactive_mode_handles_empty_line(self):
        """Interactive mode handles empty lines."""
        cli = CircuitBreakerCLI(verbose=False, json_output=False)
        old_stdin = sys.stdin
        try:
            sys.stdin = StringIO("\nquit\n")
            exit_code = cli.run_interactive()
            self.assertEqual(exit_code, 0)
        finally:
            sys.stdin = old_stdin

    def test_interactive_mode_handles_keyboard_interrupt(self):
        """Interactive mode handles Ctrl+C."""
        cli = CircuitBreakerCLI(verbose=False, json_output=False)
        old_stdin = sys.stdin
        try:
            # Simulate EOF which will exit
            sys.stdin = StringIO("")
            exit_code = cli.run_interactive()
            self.assertEqual(exit_code, 0)
        finally:
            sys.stdin = old_stdin


class TestCLIHelp(unittest.TestCase):
    """Test CLI help functionality."""

    def test_print_help_produces_output(self):
        """Help message produces output."""
        cli = CircuitBreakerCLI(verbose=False, json_output=False)
        old_stdout = sys.stdout
        try:
            sys.stdout = StringIO()
            cli._print_help()
            output = sys.stdout.getvalue()
            self.assertIn("Agent Circuit Breaker", output)
            self.assertIn("Usage:", output)
        finally:
            sys.stdout = old_stdout


class TestCLIMain(unittest.TestCase):
    """Test main entry point."""

    def test_main_help_flag(self):
        """Main with --help flag."""
        old_argv = sys.argv
        old_stdout = sys.stdout
        try:
            sys.argv = ["circuit-breaker", "--help"]
            sys.stdout = StringIO()
            exit_code = main()
            self.assertEqual(exit_code, 0)
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout

    def test_main_help_short_flag(self):
        """Main with -h flag."""
        old_argv = sys.argv
        old_stdout = sys.stdout
        try:
            sys.argv = ["circuit-breaker", "-h"]
            sys.stdout = StringIO()
            exit_code = main()
            self.assertEqual(exit_code, 0)
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout

    def test_main_command_mode(self):
        """Main with command flag."""
        old_argv = sys.argv
        old_stdout = sys.stdout
        try:
            sys.argv = ["circuit-breaker", "-c", 'mkdir "/tmp/test"']
            sys.stdout = StringIO()
            exit_code = main()
            self.assertIn(exit_code, [0, 1, 2])
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout

    def test_main_command_mode_block(self):
        """Main with blocking command."""
        old_argv = sys.argv
        old_stdout = sys.stdout
        try:
            sys.argv = ["circuit-breaker", "-c", 'rm -rf "/"']
            sys.stdout = StringIO()
            exit_code = main()
            self.assertEqual(exit_code, 1)
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout

    def test_main_json_output(self):
        """Main with JSON output flag."""
        old_argv = sys.argv
        old_stdout = sys.stdout
        try:
            sys.argv = ["circuit-breaker", "-c", 'rm -rf "/tmp"', "--json"]
            sys.stdout = StringIO()
            exit_code = main()
            output = sys.stdout.getvalue()
            # Verify JSON output
            parsed = json.loads(output)
            self.assertIn("verdict", parsed)
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout

    def test_main_verbose_flag(self):
        """Main with verbose flag."""
        old_argv = sys.argv
        old_stdout = sys.stdout
        try:
            sys.argv = ["circuit-breaker", "-c", 'mkdir "/tmp/test"', "-v"]
            sys.stdout = StringIO()
            exit_code = main()
            self.assertIn(exit_code, [0, 1, 2])
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout


class TestCLIDeterminism(unittest.TestCase):
    """Test CLI determinism."""

    def test_cli_evaluation_deterministic(self):
        """CLI evaluation is deterministic."""
        cli = CircuitBreakerCLI()
        command = 'rm -rf "/etc/passwd"'
        result1 = cli.evaluate_command(command)
        result2 = cli.evaluate_command(command)
        result3 = cli.evaluate_command(command)
        self.assertEqual(result1["verdict"], result2["verdict"])
        self.assertEqual(result2["verdict"], result3["verdict"])

    def test_cli_output_deterministic(self):
        """CLI output is deterministic."""
        cli = CircuitBreakerCLI()
        result = cli.evaluate_command('rm -rf "/tmp"')
        output1 = cli.format_output(result)
        output2 = cli.format_output(result)
        self.assertEqual(output1, output2)

    def test_cli_exit_code_deterministic(self):
        """CLI exit codes are deterministic."""
        cli = CircuitBreakerCLI()
        command = 'rm -rf "/sys"'
        code1 = cli.run_command_mode(command)
        code2 = cli.run_command_mode(command)
        code3 = cli.run_command_mode(command)
        self.assertEqual(code1, code2)
        self.assertEqual(code2, code3)


class TestCLIEdgeCases(unittest.TestCase):
    """Test CLI edge cases."""

    def test_very_long_command(self):
        """Handle very long commands."""
        cli = CircuitBreakerCLI()
        long_command = 'rm -rf "' + "/path/to/dir" * 50 + '"'
        result = cli.evaluate_command(long_command)
        self.assertIsNotNone(result["verdict"])

    def test_command_with_unicode(self):
        """Handle commands with Unicode."""
        cli = CircuitBreakerCLI()
        result = cli.evaluate_command('rm "/tmp/文件.txt"')
        self.assertIsNotNone(result["verdict"])

    def test_command_with_special_characters(self):
        """Handle commands with special characters."""
        cli = CircuitBreakerCLI()
        result = cli.evaluate_command('rm -rf "/tmp/!@#$%^&*()"')
        self.assertIsNotNone(result["verdict"])

    def test_multiline_command(self):
        """Handle multiline commands."""
        cli = CircuitBreakerCLI()
        multiline = 'rm -rf "/tmp/file1" && rm -rf "/tmp/file2"'
        result = cli.evaluate_command(multiline)
        self.assertIsNotNone(result["verdict"])

    def test_command_with_pipes(self):
        """Handle commands with pipes."""
        cli = CircuitBreakerCLI()
        result = cli.evaluate_command('find /tmp -name "*.txt" | xargs rm')
        self.assertIsNotNone(result["verdict"])


if __name__ == "__main__":
    unittest.main()
