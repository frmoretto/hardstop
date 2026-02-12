#!/usr/bin/env python3
"""
Unit tests for uncovered code paths in pre_read.py.

Targets: log_decision, block, warn, block_error, get_skip_count,
decrement_skip, main() — covering lines missed by test_read_hook.py.
"""

import sys
import os
import json
import tempfile
import shutil
from pathlib import Path
from unittest import TestCase, main as unittest_main
from unittest.mock import patch, MagicMock
from io import StringIO

# Add hooks to path
sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

import pre_read


class TestLogDecision(TestCase):
    """Test audit logging in pre_read."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig_state_dir = pre_read.STATE_DIR
        self._orig_log_file = pre_read.LOG_FILE
        pre_read.STATE_DIR = Path(self.temp_dir)
        pre_read.LOG_FILE = Path(self.temp_dir) / "audit.log"

    def tearDown(self):
        pre_read.STATE_DIR = self._orig_state_dir
        pre_read.LOG_FILE = self._orig_log_file
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_basic_log(self):
        pre_read.log_decision("/home/user/.ssh/id_rsa", "BLOCK", "SSH key", "pattern")
        content = pre_read.LOG_FILE.read_text().strip()
        entry = json.loads(content)
        self.assertEqual(entry["tool"], "Read")
        self.assertEqual(entry["verdict"], "BLOCK")
        self.assertEqual(entry["reason"], "SSH key")
        self.assertEqual(entry["layer"], "pattern")
        self.assertIn("timestamp", entry)

    def test_log_with_pattern_data(self):
        pattern_data = {
            "id": "SSH-001",
            "severity": "critical",
            "category": "credential",
        }
        pre_read.log_decision(
            "/home/user/.ssh/id_rsa", "BLOCK", "SSH key", "pattern",
            pattern_data=pattern_data, risk_score=25, risk_level="moderate"
        )
        content = pre_read.LOG_FILE.read_text().strip()
        entry = json.loads(content)
        self.assertEqual(entry["pattern_id"], "SSH-001")
        self.assertEqual(entry["severity"], "critical")
        self.assertEqual(entry["risk_score"], 25)
        self.assertEqual(entry["risk_level"], "moderate")

    def test_log_truncates_long_path(self):
        long_path = "x" * 1000
        pre_read.log_decision(long_path, "BLOCK", "test", "pattern")
        content = pre_read.LOG_FILE.read_text().strip()
        entry = json.loads(content)
        self.assertEqual(len(entry["file_path"]), 500)

    def test_log_handles_io_error(self):
        """Logging failure should not raise."""
        pre_read.LOG_FILE = Path("/nonexistent/dir/audit.log")
        pre_read.STATE_DIR = Path("/nonexistent/dir")
        # Should not raise
        pre_read.log_decision("/test", "BLOCK", "test", "pattern")


class TestBlockFunction(TestCase):
    """Test the block() output function."""

    def test_block_basic(self):
        with self.assertRaises(SystemExit) as ctx:
            with patch("sys.stdout", new_callable=StringIO) as mock_out:
                pre_read.block("SSH key detected", "/home/.ssh/id_rsa")

        self.assertEqual(ctx.exception.code, 0)

    def test_block_json_output(self):
        captured = StringIO()
        with self.assertRaises(SystemExit):
            with patch("sys.stdout", captured):
                pre_read.block("SSH key", "/home/.ssh/id_rsa", pattern="SSH-001")

        output = json.loads(captured.getvalue())
        hook = output["hookSpecificOutput"]
        self.assertEqual(hook["permissionDecision"], "deny")
        self.assertIn("BLOCKED", hook["permissionDecisionReason"])
        self.assertIn("SSH key", hook["permissionDecisionReason"])

    def test_block_with_risk_score(self):
        captured = StringIO()
        with self.assertRaises(SystemExit):
            with patch("sys.stdout", captured):
                pre_read.block(
                    "SSH key", "/home/.ssh/id_rsa",
                    risk_score=25, risk_level="moderate", blocked_count=3
                )

        output = json.loads(captured.getvalue())
        self.assertEqual(output["risk_score"], 25)
        self.assertEqual(output["risk_level"], "moderate")
        self.assertEqual(output["session_stats"]["total_blocked"], 3)

    def test_block_without_risk_score(self):
        captured = StringIO()
        with self.assertRaises(SystemExit):
            with patch("sys.stdout", captured):
                pre_read.block("test", "/test", risk_score=0)

        output = json.loads(captured.getvalue())
        self.assertNotIn("risk_score", output)


class TestWarnFunction(TestCase):
    """Test the warn() output function."""

    def test_warn_output(self):
        captured = StringIO()
        with patch("sys.stderr", captured):
            pre_read.warn("Config file detected", "/project/config.json")

        output = captured.getvalue()
        self.assertIn("WARNING", output)
        self.assertIn("Config file detected", output)
        self.assertIn("/project/config.json", output)


class TestBlockError(TestCase):
    """Test the block_error() function."""

    def test_block_error_json(self):
        captured = StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with patch("sys.stdout", captured):
                pre_read.block_error("Failed to parse input")

        self.assertEqual(ctx.exception.code, 0)
        output = json.loads(captured.getvalue())
        hook = output["hookSpecificOutput"]
        self.assertEqual(hook["permissionDecision"], "deny")
        self.assertIn("fail-closed", hook["permissionDecisionReason"])


class TestGetSkipCount(TestCase):
    """Test get_skip_count()."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig = pre_read.SKIP_FILE
        pre_read.SKIP_FILE = Path(self.temp_dir) / "skip_next"

    def tearDown(self):
        pre_read.SKIP_FILE = self._orig
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_no_file_returns_zero(self):
        self.assertEqual(pre_read.get_skip_count(), 0)

    def test_valid_count(self):
        pre_read.SKIP_FILE.write_text("3")
        self.assertEqual(pre_read.get_skip_count(), 3)

    def test_invalid_content_returns_one(self):
        pre_read.SKIP_FILE.write_text("not-a-number")
        self.assertEqual(pre_read.get_skip_count(), 1)

    def test_empty_file_returns_one(self):
        pre_read.SKIP_FILE.touch()
        self.assertEqual(pre_read.get_skip_count(), 1)


class TestDecrementSkip(TestCase):
    """Test decrement_skip()."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig = pre_read.SKIP_FILE
        pre_read.SKIP_FILE = Path(self.temp_dir) / "skip_next"

    def tearDown(self):
        pre_read.SKIP_FILE = self._orig
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_no_file(self):
        was_skipped, remaining = pre_read.decrement_skip()
        self.assertFalse(was_skipped)
        self.assertEqual(remaining, 0)

    def test_last_skip_removes_file(self):
        pre_read.SKIP_FILE.write_text("1")
        was_skipped, remaining = pre_read.decrement_skip()
        self.assertTrue(was_skipped)
        self.assertEqual(remaining, 0)
        self.assertFalse(pre_read.SKIP_FILE.exists())

    def test_multi_skip_decrements(self):
        pre_read.SKIP_FILE.write_text("3")
        was_skipped, remaining = pre_read.decrement_skip()
        self.assertTrue(was_skipped)
        self.assertEqual(remaining, 2)
        self.assertEqual(pre_read.SKIP_FILE.read_text(), "2")

    def test_invalid_content_treated_as_one(self):
        pre_read.SKIP_FILE.write_text("garbage")
        was_skipped, remaining = pre_read.decrement_skip()
        self.assertTrue(was_skipped)
        self.assertEqual(remaining, 0)
        self.assertFalse(pre_read.SKIP_FILE.exists())


class TestMainFunction(TestCase):
    """Test the main() entry point of pre_read.py."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig_state_dir = pre_read.STATE_DIR
        self._orig_skip_file = pre_read.SKIP_FILE
        self._orig_log_file = pre_read.LOG_FILE
        self._orig_debug_file = pre_read.DEBUG_FILE
        pre_read.STATE_DIR = Path(self.temp_dir)
        pre_read.SKIP_FILE = Path(self.temp_dir) / "skip_next"
        pre_read.LOG_FILE = Path(self.temp_dir) / "audit.log"
        pre_read.DEBUG_FILE = Path(self.temp_dir) / "hook_debug.log"

    def tearDown(self):
        pre_read.STATE_DIR = self._orig_state_dir
        pre_read.SKIP_FILE = self._orig_skip_file
        pre_read.LOG_FILE = self._orig_log_file
        pre_read.DEBUG_FILE = self._orig_debug_file
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_main(self, input_data):
        """Run main() with given stdin data, return (stdout, stderr, exit_code)."""
        stdin_data = json.dumps(input_data) if isinstance(input_data, dict) else input_data
        stdout = StringIO()
        stderr = StringIO()
        exit_code = None

        with patch("sys.stdin", StringIO(stdin_data)), \
             patch("sys.stdout", stdout), \
             patch("sys.stderr", stderr):
            try:
                pre_read.main()
            except SystemExit as e:
                exit_code = e.code

        return stdout.getvalue(), stderr.getvalue(), exit_code

    def test_empty_file_path_allows(self):
        stdout, _, exit_code = self._run_main({
            "tool_input": {"file_path": ""},
            "cwd": "/project"
        })
        self.assertEqual(exit_code, 0)
        # No deny output
        if stdout.strip():
            data = json.loads(stdout)
            self.assertNotEqual(
                data.get("hookSpecificOutput", {}).get("permissionDecision"),
                "deny"
            )

    def test_safe_file_allows(self):
        stdout, _, exit_code = self._run_main({
            "tool_input": {"file_path": "main.py"},
            "cwd": "/project"
        })
        self.assertEqual(exit_code, 0)

    def test_dangerous_file_blocks(self):
        stdout, _, exit_code = self._run_main({
            "tool_input": {"file_path": "~/.ssh/id_rsa"},
            "cwd": "/project"
        })
        self.assertEqual(exit_code, 0)
        data = json.loads(stdout)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_sensitive_file_warns(self):
        stdout, stderr, exit_code = self._run_main({
            "tool_input": {"file_path": "config.json"},
            "cwd": "/project"
        })
        self.assertEqual(exit_code, 0)
        self.assertIn("WARNING", stderr)

    def test_skip_bypasses_check(self):
        pre_read.SKIP_FILE.write_text("1")
        stdout, stderr, exit_code = self._run_main({
            "tool_input": {"file_path": "~/.ssh/id_rsa"},
            "cwd": "/project"
        })
        self.assertEqual(exit_code, 0)
        # Should not be blocked
        if stdout.strip():
            data = json.loads(stdout)
            self.assertNotEqual(
                data.get("hookSpecificOutput", {}).get("permissionDecision"),
                "deny"
            )
        self.assertIn("skipped", stderr.lower())

    def test_multi_skip_decrements(self):
        pre_read.SKIP_FILE.write_text("2")
        stdout, stderr, exit_code = self._run_main({
            "tool_input": {"file_path": "~/.ssh/id_rsa"},
            "cwd": "/project"
        })
        self.assertEqual(exit_code, 0)
        self.assertIn("1 skip", stderr)
        # File should still exist with count=1
        self.assertTrue(pre_read.SKIP_FILE.exists())

    def test_invalid_json_blocks_fail_closed(self):
        stdout, _, exit_code = self._run_main("not valid json")
        self.assertEqual(exit_code, 0)
        data = json.loads(stdout)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_unknown_file_allows(self):
        """Files matching no pattern should be allowed (default)."""
        stdout, _, exit_code = self._run_main({
            "tool_input": {"file_path": "random_binary.dat"},
            "cwd": "/project"
        })
        self.assertEqual(exit_code, 0)


class TestNormalizePath(TestCase):
    """Additional path normalization tests."""

    def test_absolute_path_unchanged(self):
        result = pre_read.normalize_path("/absolute/path/file.txt", "/cwd")
        self.assertIn("absolute", result)

    def test_env_var_expansion(self):
        with patch.dict(os.environ, {"MY_VAR": "expanded"}):
            result = pre_read.normalize_path("$MY_VAR/file.txt", "/cwd")
            self.assertIn("expanded", result)


if __name__ == "__main__":
    unittest_main()
