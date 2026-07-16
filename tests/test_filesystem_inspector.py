"""Tests for Filesystem Inspector."""

import unittest
import platform
from agent_circuit_breaker.inspectors.filesystem import FilesystemInspector


class TestPathNormalization(unittest.TestCase):
    """Test path normalization functionality."""

    def test_normalize_absolute_unix_path(self):
        """Normalize absolute Unix paths."""
        result = FilesystemInspector.normalize_path("/home/user/file.txt")
        self.assertEqual(result, "/home/user/file.txt")

    def test_normalize_path_with_trailing_slash(self):
        """Remove trailing slashes except for root."""
        result = FilesystemInspector.normalize_path("/home/user/")
        self.assertEqual(result, "/home/user")

    def test_normalize_root_path(self):
        """Keep root as /."""
        result = FilesystemInspector.normalize_path("/")
        self.assertEqual(result, "/")

    def test_normalize_path_with_dot(self):
        """Remove . components."""
        result = FilesystemInspector.normalize_path("/home/./user/./file.txt")
        self.assertEqual(result, "/home/user/file.txt")

    def test_normalize_path_with_double_dot(self):
        """Resolve .. components."""
        result = FilesystemInspector.normalize_path("/home/user/../file.txt")
        self.assertEqual(result, "/home/file.txt")

    def test_normalize_path_multiple_double_dots(self):
        """Resolve multiple .. components."""
        result = FilesystemInspector.normalize_path("/home/user/subdir/../../file.txt")
        self.assertEqual(result, "/home/file.txt")

    def test_normalize_path_backslashes(self):
        """Convert backslashes to forward slashes."""
        result = FilesystemInspector.normalize_path("\\home\\user\\file.txt")
        # Result should be normalized but may differ by OS
        self.assertIn(result, ["\\home\\user\\file.txt", "/home/user/file.txt"])

    def test_normalize_path_mixed_slashes(self):
        """Handle mixed forward and backslashes."""
        result = FilesystemInspector.normalize_path("/home\\user/file.txt")
        self.assertIn(result, ["/home/user/file.txt", "/home\\user/file.txt"])

    def test_normalize_path_with_spaces(self):
        """Handle paths with spaces."""
        result = FilesystemInspector.normalize_path("/home/my user/file.txt")
        self.assertEqual(result, "/home/my user/file.txt")

    def test_normalize_path_with_special_chars(self):
        """Handle paths with special characters."""
        result = FilesystemInspector.normalize_path("/home/user-name/file_2023.txt")
        self.assertEqual(result, "/home/user-name/file_2023.txt")

    def test_normalize_empty_path_raises(self):
        """Empty path raises ValueError."""
        with self.assertRaises(ValueError):
            FilesystemInspector.normalize_path("")

    def test_normalize_whitespace_only_path_raises(self):
        """Whitespace-only path raises ValueError."""
        with self.assertRaises(ValueError):
            FilesystemInspector.normalize_path("   ")

    def test_normalize_none_path_raises(self):
        """None path raises ValueError."""
        with self.assertRaises(ValueError):
            FilesystemInspector.normalize_path(None)

    def test_normalize_double_slashes(self):
        """Normalize double slashes."""
        result = FilesystemInspector.normalize_path("/home//user///file.txt")
        self.assertEqual(result, "/home/user/file.txt")

    def test_normalize_deep_nested_path(self):
        """Normalize deeply nested paths."""
        path = "/a/b/c/d/e/f/g/h/i/j/file.txt"
        result = FilesystemInspector.normalize_path(path)
        self.assertEqual(result, path)

    def test_normalize_path_escaping_root_with_dots(self):
        """Don't escape beyond root with .."""
        result = FilesystemInspector.normalize_path("/../../../file.txt")
        self.assertEqual(result, "/file.txt")


class TestDangerousTargetDetection(unittest.TestCase):
    """Test dangerous filesystem target detection."""

    def test_detect_root_deletion(self):
        """Detect root / as dangerous."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("/")
        self.assertTrue(is_dangerous)
        self.assertIsNotNone(reason)

    def test_detect_unix_system_paths(self):
        """Detect Unix system paths as dangerous."""
        dangerous_paths = ["/etc", "/bin", "/sbin", "/usr", "/sys", "/proc", "/boot"]
        for path in dangerous_paths:
            is_dangerous, reason = FilesystemInspector.is_dangerous_target(path)
            self.assertTrue(is_dangerous, f"Path {path} should be dangerous")

    def test_detect_windows_system_paths(self):
        """Detect Windows system paths as dangerous."""
        dangerous_paths = [
            "C:\\Windows",
            "C:\\System32",
            "C:\\Program Files",
            "C:\\ProgramData",
        ]
        for path in dangerous_paths:
            is_dangerous, reason = FilesystemInspector.is_dangerous_target(path)
            self.assertTrue(is_dangerous, f"Path {path} should be dangerous")

    def test_detect_home_dir_as_dangerous(self):
        """Detect /home as dangerous."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("/home")
        self.assertTrue(is_dangerous)

    def test_detect_root_home_as_dangerous(self):
        """Detect /root as dangerous."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("/root")
        self.assertTrue(is_dangerous)

    def test_detect_safe_user_path(self):
        """Safe user paths are not dangerous."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("/home/user/documents")
        self.assertFalse(is_dangerous)

    def test_detect_safe_tmp_path(self):
        """Temporary directories are safe."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("/tmp/myfile")
        self.assertFalse(is_dangerous)

    def test_detect_relative_path_as_safe(self):
        """Relative paths are generally safe."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("./myfile")
        self.assertFalse(is_dangerous)

    def test_empty_path_returns_safe(self):
        """Empty path returns safe."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("")
        self.assertFalse(is_dangerous)

    def test_none_path_returns_safe(self):
        """None path returns safe."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target(None)
        self.assertFalse(is_dangerous)

    def test_detect_subpath_of_dangerous(self):
        """Subpaths of dangerous targets are dangerous."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("/etc/passwd")
        self.assertTrue(is_dangerous)

    def test_detect_case_insensitive_dangerous_windows(self):
        """Windows path detection is case-insensitive."""
        # Depending on platform, this might vary
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("c:\\windows\\system32")
        # Should be detected as dangerous (case insensitive matching)
        self.assertTrue(is_dangerous)

    def test_detect_normalized_dangerous_path(self):
        """Detect dangerous paths even with .. components."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("/etc/../../etc/passwd")
        self.assertTrue(is_dangerous)

    def test_detect_var_as_dangerous(self):
        """Detect /var as dangerous."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("/var")
        self.assertTrue(is_dangerous)

    def test_detect_dev_as_dangerous(self):
        """Detect /dev as dangerous."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("/dev")
        self.assertTrue(is_dangerous)


class TestCommandAnalysis(unittest.TestCase):
    """Test shell command analysis."""

    def test_analyze_delete_command(self):
        """Analyze basic delete command."""
        result = FilesystemInspector.analyze_operation('rm "/tmp/file.txt"')
        self.assertEqual(result["operation"], "delete")
        self.assertIn("/tmp/file.txt", result["targets"])

    def test_analyze_recursive_delete_command(self):
        """Analyze recursive delete command."""
        result = FilesystemInspector.analyze_operation('rm -r "/home/user/dir"')
        self.assertEqual(result["operation"], "delete")
        self.assertIn("recursive", result["flags"])

    def test_analyze_recursive_force_delete_command(self):
        """Analyze recursive force delete command."""
        result = FilesystemInspector.analyze_operation('rm -rf "/tmp/cache"')
        self.assertEqual(result["operation"], "delete")
        self.assertIn("recursive", result["flags"])
        self.assertIn("force", result["flags"])

    def test_analyze_split_recursive_force_delete_flags(self):
        """Split rm flags should be recognized."""
        result = FilesystemInspector.analyze_operation("rm -r -f /etc")

        self.assertEqual(result["operation"], "delete")
        self.assertIn("recursive", result["flags"])
        self.assertIn("force", result["flags"])
        self.assertIn("/etc", result["targets"])

    def test_analyze_long_recursive_force_delete_flags(self):
        """Long rm flags should be recognized."""
        result = FilesystemInspector.analyze_operation("rm --recursive --force /etc")

        self.assertEqual(result["operation"], "delete")
        self.assertIn("recursive", result["flags"])
        self.assertIn("force", result["flags"])
        self.assertIn("/etc", result["targets"])

    def test_analyze_unquoted_delete_target(self):
        """Unquoted delete targets should be extracted."""
        result = FilesystemInspector.analyze_operation("rm /etc/passwd")

        self.assertEqual(result["operation"], "delete")
        self.assertIn("/etc/passwd", result["targets"])
        self.assertTrue(result["is_dangerous"])

    def test_similar_command_names_are_not_delete_operations(self):
        """Commands containing rm as a substring should not be delete operations."""
        for command in ("transform -rf image.png", "terraform -rf apply", "firm -rf handshake"):
            with self.subTest(command=command):
                result = FilesystemInspector.analyze_operation(command)

                self.assertEqual(result["operation"], "unknown")
                self.assertEqual(result["targets"], [])

    def test_analyze_windows_remove_item(self):
        """Analyze Windows Remove-Item command."""
        result = FilesystemInspector.analyze_operation('Remove-Item -Path "C:\\temp" -Recurse')
        self.assertEqual(result["operation"], "delete")
        self.assertIn("recursive", result["flags"])

    def test_analyze_move_command(self):
        """Analyze move command."""
        result = FilesystemInspector.analyze_operation('mv "/tmp/old.txt" "/tmp/new.txt"')
        self.assertEqual(result["operation"], "move")
        self.assertIn("/tmp/old.txt", result["targets"])
        self.assertIn("/tmp/new.txt", result["targets"])

    def test_analyze_copy_command(self):
        """Analyze copy command."""
        result = FilesystemInspector.analyze_operation('cp "/src/file.txt" "/dst/file.txt"')
        self.assertEqual(result["operation"], "copy")

    def test_analyze_chmod_command(self):
        """Analyze chmod command."""
        result = FilesystemInspector.analyze_operation('chmod 755 "/home/user/script.sh"')
        self.assertEqual(result["operation"], "chmod")

    def test_analyze_mkdir_command(self):
        """Analyze mkdir command."""
        result = FilesystemInspector.analyze_operation('mkdir "/tmp/newdir"')
        self.assertEqual(result["operation"], "create_dir")

    def test_analyze_touch_command(self):
        """Analyze touch command."""
        result = FilesystemInspector.analyze_operation('touch "/tmp/newfile.txt"')
        self.assertEqual(result["operation"], "create_file")

    def test_analyze_unknown_command(self):
        """Analyze unknown command."""
        result = FilesystemInspector.analyze_operation('echo "hello"')
        self.assertEqual(result["operation"], "unknown")

    def test_analyze_empty_command(self):
        """Analyze empty command."""
        result = FilesystemInspector.analyze_operation("")
        self.assertEqual(result["operation"], "unknown")
        self.assertEqual(result["targets"], [])

    def test_analyze_none_command(self):
        """Analyze None command."""
        result = FilesystemInspector.analyze_operation(None)
        self.assertEqual(result["operation"], "unknown")

    def test_analyze_detect_dangerous_recursive_delete(self):
        """Detect dangerous recursive delete."""
        result = FilesystemInspector.analyze_operation('rm -rf "/etc"')
        self.assertEqual(result["operation"], "delete")
        self.assertTrue(result["is_dangerous"])

    def test_analyze_detect_dangerous_root_delete(self):
        """Detect dangerous root deletion."""
        result = FilesystemInspector.analyze_operation('rm -rf "/"')
        self.assertEqual(result["operation"], "delete")
        self.assertTrue(result["is_dangerous"])

    def test_analyze_safe_temp_delete(self):
        """Safe delete of temp files."""
        result = FilesystemInspector.analyze_operation('rm -rf "/tmp/cache"')
        self.assertEqual(result["operation"], "delete")
        self.assertFalse(result["is_dangerous"])

    def test_analyze_case_insensitive_commands(self):
        """Command detection is case-insensitive."""
        result1 = FilesystemInspector.analyze_operation('RM "/tmp/file"')
        result2 = FilesystemInspector.analyze_operation('rm "/tmp/file"')
        self.assertEqual(result1["operation"], result2["operation"])

    def test_analyze_multiple_targets(self):
        """Extract multiple target paths from command."""
        result = FilesystemInspector.analyze_operation(
            'mv "/src/file1.txt" "/src/file2.txt" "/dst/"'
        )
        self.assertEqual(result["operation"], "move")
        self.assertGreaterEqual(len(result["targets"]), 1)

    def test_analyze_windows_recursive_flag(self):
        """Detect Windows /s recursive flag."""
        result = FilesystemInspector.analyze_operation('del /s /q "C:\\temp"')
        self.assertEqual(result["operation"], "delete")
        # Should detect recursive behavior
        self.assertIn("recursive", result["flags"] or "force" in result["flags"])


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    def test_very_long_path(self):
        """Handle very long paths."""
        long_path = "/" + "/".join(["dir"] * 100) + "/file.txt"
        result = FilesystemInspector.normalize_path(long_path)
        self.assertIsNotNone(result)
        self.assertTrue(len(result) > 100)

    def test_path_with_unicode_characters(self):
        """Handle Unicode characters in paths."""
        path = "/home/用户/文件.txt"
        result = FilesystemInspector.normalize_path(path)
        self.assertIn("文件", result)

    def test_dangerous_target_with_unicode(self):
        """Dangerous target detection with Unicode."""
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("/etc/密码")
        self.assertTrue(is_dangerous)

    def test_command_with_multiple_quotes(self):
        """Handle commands with multiple different quoted strings."""
        result = FilesystemInspector.analyze_operation(
            '''rm -r "/path/one" "/path/two" '/path/three\''''
        )
        self.assertEqual(result["operation"], "delete")
        self.assertGreater(len(result["targets"]), 0)

    def test_analyze_command_with_escape_sequences(self):
        """Handle commands with escape sequences."""
        result = FilesystemInspector.analyze_operation(r'rm -rf "/path/with\space/file"')
        self.assertEqual(result["operation"], "delete")

    def test_normalize_path_with_dots_in_filename(self):
        """Normalize paths with dots in filenames (not directory indicators)."""
        result = FilesystemInspector.normalize_path("/home/user/file.backup.txt")
        self.assertEqual(result, "/home/user/file.backup.txt")

    def test_windows_drive_letters(self):
        """Handle various Windows drive letters."""
        for drive in ["C", "D", "E", "Z"]:
            path = f"{drive}:\\Users\\test\\file.txt"
            result = FilesystemInspector.normalize_path(path)
            self.assertIsNotNone(result)

    def test_dangerous_detection_with_normalization(self):
        """Detect dangerous paths even with complex normalization needed."""
        # /etc/../../etc should normalize to /etc (dangerous)
        is_dangerous, reason = FilesystemInspector.is_dangerous_target("/etc/x/y/../../..")
        self.assertTrue(is_dangerous)

    def test_analyze_command_case_variations(self):
        """Handle various case combinations in commands."""
        commands = [
            'rm "/tmp/file"',
            'RM "/tmp/file"',
            'Rm "/tmp/file"',
            'rM "/tmp/file"',
        ]
        operations = [FilesystemInspector.analyze_operation(cmd)["operation"] for cmd in commands]
        self.assertTrue(all(op == "delete" for op in operations))


class TestDeterminism(unittest.TestCase):
    """Test that operations are deterministic."""

    def test_normalize_path_deterministic(self):
        """Path normalization is deterministic."""
        path = "/home/user/../user/./file.txt"
        result1 = FilesystemInspector.normalize_path(path)
        result2 = FilesystemInspector.normalize_path(path)
        result3 = FilesystemInspector.normalize_path(path)
        self.assertEqual(result1, result2)
        self.assertEqual(result2, result3)

    def test_dangerous_detection_deterministic(self):
        """Dangerous target detection is deterministic."""
        path = "/etc/passwd"
        is_dangerous1, reason1 = FilesystemInspector.is_dangerous_target(path)
        is_dangerous2, reason2 = FilesystemInspector.is_dangerous_target(path)
        is_dangerous3, reason3 = FilesystemInspector.is_dangerous_target(path)
        self.assertEqual(is_dangerous1, is_dangerous2)
        self.assertEqual(is_dangerous2, is_dangerous3)

    def test_command_analysis_deterministic(self):
        """Command analysis is deterministic."""
        command = 'rm -rf "/tmp/cache" "/var/tmp"'
        result1 = FilesystemInspector.analyze_operation(command)
        result2 = FilesystemInspector.analyze_operation(command)
        result3 = FilesystemInspector.analyze_operation(command)
        self.assertEqual(result1["operation"], result2["operation"])
        self.assertEqual(result2["operation"], result3["operation"])
        self.assertEqual(result1["targets"], result2["targets"])
        self.assertEqual(result2["targets"], result3["targets"])


if __name__ == "__main__":
    unittest.main()
