#!/usr/bin/env python3
"""
Unit tests for uncovered code paths in pre_tool_use.py.

Targets: block_command, allow_command, check_uninstall_script,
decrement_skip, get_skip_count, _build_claude_exec, ask_claude,
find_claude_cli, main() — covering lines missed by test_hook.py.
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

import pre_tool_use


class TestBlockCommand(TestCase):
    """Test block_command() JSON output."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig_state_dir = pre_tool_use.STATE_DIR
        self._orig_log_file = pre_tool_use.LOG_FILE
        pre_tool_use.STATE_DIR = Path(self.temp_dir)
        pre_tool_use.LOG_FILE = Path(self.temp_dir) / "audit.log"

    def tearDown(self):
        pre_tool_use.STATE_DIR = self._orig_state_dir
        pre_tool_use.LOG_FILE = self._orig_log_file
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_basic_block(self):
        captured = StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with patch("sys.stdout", captured):
                pre_tool_use.block_command("Dangerous", "rm -rf /", "pattern", "/tmp")

        self.assertEqual(ctx.exception.code, 0)
        output = json.loads(captured.getvalue())
        hook = output["hookSpecificOutput"]
        self.assertEqual(hook["permissionDecision"], "deny")
        self.assertIn("BLOCKED", hook["permissionDecisionReason"])
        self.assertIn("Dangerous", hook["permissionDecisionReason"])

    def test_block_with_risk_score(self):
        captured = StringIO()
        with self.assertRaises(SystemExit):
            with patch("sys.stdout", captured):
                pre_tool_use.block_command(
                    "Bad", "rm -rf /", "pattern", "/tmp",
                    risk_score=50, risk_level="high", blocked_count=5
                )

        output = json.loads(captured.getvalue())
        self.assertEqual(output["risk_score"], 50)
        self.assertEqual(output["risk_level"], "high")
        self.assertEqual(output["session_stats"]["total_blocked"], 5)

    def test_block_truncates_long_command(self):
        captured = StringIO()
        long_cmd = "x" * 200
        with self.assertRaises(SystemExit):
            with patch("sys.stdout", captured):
                pre_tool_use.block_command("test", long_cmd, "pattern", "/tmp")

        output = json.loads(captured.getvalue())
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("...", reason)

    def test_block_logs_decision(self):
        with self.assertRaises(SystemExit):
            with patch("sys.stdout", StringIO()):
                pre_tool_use.block_command("test", "rm -rf /", "pattern", "/tmp")

        self.assertTrue(pre_tool_use.LOG_FILE.exists())


class TestAllowCommand(TestCase):
    """Test allow_command()."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig_state_dir = pre_tool_use.STATE_DIR
        self._orig_log_file = pre_tool_use.LOG_FILE
        pre_tool_use.STATE_DIR = Path(self.temp_dir)
        pre_tool_use.LOG_FILE = Path(self.temp_dir) / "audit.log"

    def tearDown(self):
        pre_tool_use.STATE_DIR = self._orig_state_dir
        pre_tool_use.LOG_FILE = self._orig_log_file
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_allow_exits_zero(self):
        with self.assertRaises(SystemExit) as ctx:
            with patch("sys.stderr", StringIO()):
                pre_tool_use.allow_command("Safe command", "ls", "pattern", "/tmp")
        self.assertEqual(ctx.exception.code, 0)

    def test_allow_silent(self):
        stderr = StringIO()
        with self.assertRaises(SystemExit):
            with patch("sys.stderr", stderr):
                pre_tool_use.allow_command("Safe", "ls", "pattern", "/tmp", silent=True)
        self.assertEqual(stderr.getvalue(), "")

    def test_allow_with_reason_prints(self):
        stderr = StringIO()
        with self.assertRaises(SystemExit):
            with patch("sys.stderr", stderr):
                pre_tool_use.allow_command("Safe command", "ls", "pattern", "/tmp")
        self.assertIn("Safe command", stderr.getvalue())

    def test_allow_parenthetical_reason_silent(self):
        """Reasons starting with ( are suppressed from stderr."""
        stderr = StringIO()
        with self.assertRaises(SystemExit):
            with patch("sys.stderr", stderr):
                pre_tool_use.allow_command("(internal)", "ls", "pattern", "/tmp")
        self.assertEqual(stderr.getvalue(), "")


class TestCheckUninstallScript(TestCase):
    """Test check_uninstall_script()."""

    def test_detects_uninstall_sh(self):
        with self.assertRaises(SystemExit) as ctx:
            with patch("sys.stdout", StringIO()) as out:
                pre_tool_use.check_uninstall_script("./uninstall.sh")
        self.assertEqual(ctx.exception.code, 0)

    def test_detects_uninstall_ps1(self):
        with self.assertRaises(SystemExit):
            with patch("sys.stdout", StringIO()):
                pre_tool_use.check_uninstall_script("powershell uninstall.ps1")

    def test_detects_uninstall_json_output(self):
        captured = StringIO()
        with self.assertRaises(SystemExit):
            with patch("sys.stdout", captured):
                pre_tool_use.check_uninstall_script("bash uninstall.sh")

        output = json.loads(captured.getvalue())
        self.assertEqual(output["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("REMOVAL", output["hookSpecificOutput"]["permissionDecisionReason"])

    def test_ignores_normal_command(self):
        result = pre_tool_use.check_uninstall_script("ls -la")
        self.assertFalse(result)


class TestDecrementSkipToolUse(TestCase):
    """Test decrement_skip() in pre_tool_use."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig = pre_tool_use.SKIP_FILE
        pre_tool_use.SKIP_FILE = Path(self.temp_dir) / "skip_next"

    def tearDown(self):
        pre_tool_use.SKIP_FILE = self._orig
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_no_file(self):
        self.assertFalse(pre_tool_use.decrement_skip())

    def test_last_skip(self):
        pre_tool_use.SKIP_FILE.write_text("1")
        self.assertTrue(pre_tool_use.decrement_skip())
        self.assertFalse(pre_tool_use.SKIP_FILE.exists())

    def test_multi_skip(self):
        pre_tool_use.SKIP_FILE.write_text("3")
        self.assertTrue(pre_tool_use.decrement_skip())
        self.assertEqual(pre_tool_use.SKIP_FILE.read_text(), "2")

    def test_invalid_content(self):
        pre_tool_use.SKIP_FILE.write_text("garbage")
        self.assertTrue(pre_tool_use.decrement_skip())
        self.assertFalse(pre_tool_use.SKIP_FILE.exists())


class TestGetSkipCountToolUse(TestCase):
    """Test get_skip_count() in pre_tool_use."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig = pre_tool_use.SKIP_FILE
        pre_tool_use.SKIP_FILE = Path(self.temp_dir) / "skip_next"

    def tearDown(self):
        pre_tool_use.SKIP_FILE = self._orig
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_no_file(self):
        self.assertEqual(pre_tool_use.get_skip_count(), 0)

    def test_valid_count(self):
        pre_tool_use.SKIP_FILE.write_text("5")
        self.assertEqual(pre_tool_use.get_skip_count(), 5)

    def test_invalid_returns_one(self):
        pre_tool_use.SKIP_FILE.write_text("bad")
        self.assertEqual(pre_tool_use.get_skip_count(), 1)


class TestClearSkip(TestCase):
    """Test clear_skip()."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig = pre_tool_use.SKIP_FILE
        pre_tool_use.SKIP_FILE = Path(self.temp_dir) / "skip_next"

    def tearDown(self):
        pre_tool_use.SKIP_FILE = self._orig
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_clear_existing(self):
        pre_tool_use.SKIP_FILE.write_text("2")
        pre_tool_use.clear_skip()
        self.assertFalse(pre_tool_use.SKIP_FILE.exists())

    def test_clear_nonexistent(self):
        # Should not raise
        pre_tool_use.clear_skip()


class TestBuildClaudeExec(TestCase):
    """Test _build_claude_exec()."""

    def test_unix_path(self):
        with patch("platform.system", return_value="Linux"):
            result = pre_tool_use._build_claude_exec("/usr/bin/claude", ["--version"])
            self.assertEqual(result, ["/usr/bin/claude", "--version"])

    def test_windows_cmd(self):
        with patch("platform.system", return_value="Windows"):
            result = pre_tool_use._build_claude_exec("C:\\npm\\claude.cmd", ["--version"])
            self.assertEqual(result, ["cmd", "/c", "C:\\npm\\claude.cmd", "--version"])

    def test_windows_non_cmd(self):
        with patch("platform.system", return_value="Windows"):
            result = pre_tool_use._build_claude_exec("C:\\bin\\claude.exe", ["--version"])
            self.assertEqual(result, ["C:\\bin\\claude.exe", "--version"])


class TestFindClaudeCli(TestCase):
    """Test find_claude_cli()."""

    def test_claude_in_path(self):
        with patch("shutil.which", return_value="/usr/local/bin/claude"):
            result = pre_tool_use.find_claude_cli()
            self.assertEqual(result, "/usr/local/bin/claude")

    def test_claude_not_found(self):
        with patch("shutil.which", return_value=None):
            # All candidates won't exist in test env
            result = pre_tool_use.find_claude_cli()
            # May or may not find it depending on env, but shouldn't crash
            # In most test envs it returns None
            self.assertTrue(result is None or isinstance(result, str))


class TestAskClaude(TestCase):
    """Test ask_claude() with mocked subprocess."""

    def test_cli_unavailable_blocks(self):
        with patch.object(pre_tool_use, "find_claude_cli", return_value=None):
            verdict, reason = pre_tool_use.ask_claude("test cmd", "/tmp")
            self.assertEqual(verdict, "BLOCK")
            self.assertIn("unavailable", reason.lower())

    def test_cli_success_allow(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"verdict": "ALLOW", "reason": "Safe command"}'

        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch("subprocess.run", return_value=mock_result):
            verdict, reason = pre_tool_use.ask_claude("ls", "/tmp")
            self.assertEqual(verdict, "ALLOW")

    def test_cli_success_block(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"verdict": "BLOCK", "reason": "Dangerous operation"}'

        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch("subprocess.run", return_value=mock_result):
            verdict, reason = pre_tool_use.ask_claude("rm -rf /", "/tmp")
            self.assertEqual(verdict, "BLOCK")

    def test_cli_error_blocks(self):
        mock_result = MagicMock()
        mock_result.returncode = 1

        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch("subprocess.run", return_value=mock_result):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "BLOCK")

    def test_cli_timeout_blocks(self):
        import subprocess
        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("claude", 15)):
            verdict, reason = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "BLOCK")
            self.assertIn("timed out", reason.lower())

    def test_cli_subprocess_error_blocks(self):
        import subprocess
        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch("subprocess.run", side_effect=subprocess.SubprocessError("fail")):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "BLOCK")

    def test_cli_os_error_blocks(self):
        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch("subprocess.run", side_effect=OSError("not found")):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "BLOCK")

    def test_unparseable_response_blocks(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "I have no idea what to say about this"

        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch("subprocess.run", return_value=mock_result):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "BLOCK")


class TestParseLlmResponseEdgeCases(TestCase):
    """Additional edge cases for parse_llm_response."""

    def test_markdown_without_json_keyword_block(self):
        response = "```\nI think you should BLOCK this command\n```"
        verdict, _ = pre_tool_use.parse_llm_response(response)
        self.assertEqual(verdict, "BLOCK")

    def test_brace_matching_nested(self):
        response = 'Some text {"verdict": "ALLOW", "nested": {"a": 1}} more text'
        verdict, _ = pre_tool_use.parse_llm_response(response)
        self.assertEqual(verdict, "ALLOW")

    def test_empty_response(self):
        verdict, _ = pre_tool_use.parse_llm_response("")
        self.assertEqual(verdict, "UNKNOWN")


class TestLogDecisionToolUse(TestCase):
    """Test log_decision in pre_tool_use."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig_state_dir = pre_tool_use.STATE_DIR
        self._orig_log_file = pre_tool_use.LOG_FILE
        pre_tool_use.STATE_DIR = Path(self.temp_dir)
        pre_tool_use.LOG_FILE = Path(self.temp_dir) / "audit.log"

    def tearDown(self):
        pre_tool_use.STATE_DIR = self._orig_state_dir
        pre_tool_use.LOG_FILE = self._orig_log_file
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_log_with_pattern_data(self):
        pattern_data = {"id": "DEL-001", "severity": "critical", "category": "filesystem"}
        pre_tool_use.log_decision(
            "rm -rf /", "BLOCK", "Danger", "pattern", "/tmp",
            pattern_data=pattern_data, risk_score=25, risk_level="moderate"
        )
        content = pre_tool_use.LOG_FILE.read_text().strip()
        entry = json.loads(content)
        self.assertEqual(entry["pattern_id"], "DEL-001")
        self.assertEqual(entry["severity"], "critical")
        self.assertEqual(entry["risk_score"], 25)

    def test_log_io_error(self):
        """Log failure should not raise."""
        pre_tool_use.LOG_FILE = Path("/nonexistent/dir/audit.log")
        pre_tool_use.STATE_DIR = Path("/nonexistent/dir")
        pre_tool_use.log_decision("test", "ALLOW", "test", "pattern", "/tmp")


class TestMainFunction(TestCase):
    """Test main() entry point of pre_tool_use.py."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig_state_dir = pre_tool_use.STATE_DIR
        self._orig_state_file = pre_tool_use.STATE_FILE
        self._orig_skip_file = pre_tool_use.SKIP_FILE
        self._orig_log_file = pre_tool_use.LOG_FILE
        self._orig_debug_file = pre_tool_use.DEBUG_FILE

        pre_tool_use.STATE_DIR = Path(self.temp_dir)
        pre_tool_use.STATE_FILE = Path(self.temp_dir) / "state.json"
        pre_tool_use.SKIP_FILE = Path(self.temp_dir) / "skip_next"
        pre_tool_use.LOG_FILE = Path(self.temp_dir) / "audit.log"
        pre_tool_use.DEBUG_FILE = Path(self.temp_dir) / "hook_debug.log"

        # Write default enabled state
        Path(self.temp_dir).mkdir(parents=True, exist_ok=True)
        pre_tool_use.STATE_FILE.write_text('{"enabled": true}')

    def tearDown(self):
        pre_tool_use.STATE_DIR = self._orig_state_dir
        pre_tool_use.STATE_FILE = self._orig_state_file
        pre_tool_use.SKIP_FILE = self._orig_skip_file
        pre_tool_use.LOG_FILE = self._orig_log_file
        pre_tool_use.DEBUG_FILE = self._orig_debug_file
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_main(self, input_data):
        stdin_data = json.dumps(input_data) if isinstance(input_data, dict) else input_data
        stdout = StringIO()
        stderr = StringIO()
        exit_code = None

        with patch("sys.stdin", StringIO(stdin_data)), \
             patch("sys.stdout", stdout), \
             patch("sys.stderr", stderr):
            try:
                pre_tool_use.main()
            except SystemExit as e:
                exit_code = e.code

        return stdout.getvalue(), stderr.getvalue(), exit_code

    def test_empty_command_allows(self):
        _, _, exit_code = self._run_main({
            "tool_input": {"command": ""},
            "cwd": "/tmp"
        })
        self.assertEqual(exit_code, 0)

    def test_safe_command_allows(self):
        stdout, _, exit_code = self._run_main({
            "tool_input": {"command": "ls -la"},
            "cwd": "/tmp"
        })
        self.assertEqual(exit_code, 0)
        # Should not have deny
        if stdout.strip():
            data = json.loads(stdout)
            self.assertNotEqual(
                data.get("hookSpecificOutput", {}).get("permissionDecision"),
                "deny"
            )

    def test_dangerous_command_blocks(self):
        stdout, _, exit_code = self._run_main({
            "tool_input": {"command": "rm -rf ~/"},
            "cwd": "/tmp"
        })
        self.assertEqual(exit_code, 0)
        data = json.loads(stdout)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_disabled_state_allows(self):
        pre_tool_use.STATE_FILE.write_text('{"enabled": false}')
        stdout, _, exit_code = self._run_main({
            "tool_input": {"command": "rm -rf ~/"},
            "cwd": "/tmp"
        })
        self.assertEqual(exit_code, 0)
        # Should be allowed (no deny)
        if stdout.strip():
            data = json.loads(stdout)
            self.assertNotEqual(
                data.get("hookSpecificOutput", {}).get("permissionDecision"),
                "deny"
            )

    def test_skip_bypasses_dangerous(self):
        pre_tool_use.SKIP_FILE.write_text("1")
        stdout, stderr, exit_code = self._run_main({
            "tool_input": {"command": "rm -rf ~/"},
            "cwd": "/tmp"
        })
        self.assertEqual(exit_code, 0)
        # Should be allowed due to skip
        if stdout.strip():
            data = json.loads(stdout)
            self.assertNotEqual(
                data.get("hookSpecificOutput", {}).get("permissionDecision"),
                "deny"
            )
        self.assertIn("skipped", stderr.lower())

    def test_multi_skip_shows_remaining(self):
        pre_tool_use.SKIP_FILE.write_text("3")
        _, stderr, _ = self._run_main({
            "tool_input": {"command": "rm -rf ~/"},
            "cwd": "/tmp"
        })
        self.assertIn("2 skip", stderr)

    def test_invalid_json_fails_closed(self):
        _, stderr, exit_code = self._run_main("not json at all")
        self.assertEqual(exit_code, 2)
        self.assertIn("BLOCKED", stderr)

    def test_uninstall_detected(self):
        stdout, _, exit_code = self._run_main({
            "tool_input": {"command": "./uninstall.sh"},
            "cwd": "/tmp"
        })
        self.assertEqual(exit_code, 0)
        data = json.loads(stdout)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("REMOVAL", data["hookSpecificOutput"]["permissionDecisionReason"])

    def test_unknown_command_goes_to_llm(self):
        """Commands not matching safe or dangerous should go to LLM layer."""
        with patch.object(pre_tool_use, "ask_claude", return_value=("ALLOW", "looks fine")):
            stdout, _, exit_code = self._run_main({
                "tool_input": {"command": "some-unknown-tool --flag"},
                "cwd": "/tmp"
            })
            self.assertEqual(exit_code, 0)

    def test_llm_blocks_unknown(self):
        with patch.object(pre_tool_use, "ask_claude", return_value=("BLOCK", "suspicious")):
            stdout, _, exit_code = self._run_main({
                "tool_input": {"command": "some-unknown-tool --flag"},
                "cwd": "/tmp"
            })
            self.assertEqual(exit_code, 0)
            data = json.loads(stdout)
            self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")


class TestStateManagementEdgeCases(TestCase):
    """Additional state management tests."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self._orig_state_dir = pre_tool_use.STATE_DIR
        self._orig_state_file = pre_tool_use.STATE_FILE
        pre_tool_use.STATE_DIR = Path(self.temp_dir)
        pre_tool_use.STATE_FILE = Path(self.temp_dir) / "state.json"

    def tearDown(self):
        pre_tool_use.STATE_DIR = self._orig_state_dir
        pre_tool_use.STATE_FILE = self._orig_state_file
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_load_state_invalid_enabled_type(self):
        pre_tool_use.STATE_FILE.write_text('{"enabled": "yes"}')
        state = pre_tool_use.load_state()
        self.assertTrue(state["enabled"])  # Falls back to True

    def test_load_state_io_error(self):
        # Simulate IO error by making STATE_FILE a directory
        pre_tool_use.STATE_FILE.mkdir(parents=True, exist_ok=True)
        state = pre_tool_use.load_state()
        self.assertTrue(state["enabled"])  # Default

    def test_save_state_creates_dir(self):
        new_dir = Path(self.temp_dir) / "subdir"
        pre_tool_use.STATE_DIR = new_dir
        pre_tool_use.STATE_FILE = new_dir / "state.json"
        pre_tool_use.save_state({"enabled": False})
        self.assertTrue(pre_tool_use.STATE_FILE.exists())


class TestCheckDangerousRegexError(TestCase):
    """Test regex error handling in check_dangerous."""

    def test_invalid_regex_skipped(self):
        """Invalid regex patterns should be skipped without crashing."""
        orig = pre_tool_use.DANGEROUS_PATTERNS
        pre_tool_use.DANGEROUS_PATTERNS = [("[invalid", "TEST-001")]
        try:
            is_dangerous, _ = pre_tool_use.check_dangerous("test command")
            self.assertFalse(is_dangerous)
        finally:
            pre_tool_use.DANGEROUS_PATTERNS = orig

    def test_invalid_safe_regex_skipped(self):
        orig = pre_tool_use.SAFE_PATTERNS
        pre_tool_use.SAFE_PATTERNS = ["[invalid"]
        try:
            self.assertFalse(pre_tool_use.check_safe("test"))
        finally:
            pre_tool_use.SAFE_PATTERNS = orig


if __name__ == "__main__":
    unittest_main()
