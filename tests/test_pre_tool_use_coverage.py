#!/usr/bin/env python3
"""
Unit tests for uncovered code paths in pre_tool_use.py.

Targets: block_command, allow_command, check_uninstall_script,
decrement_skip, get_skip_count, _build_claude_exec, ask_claude,
find_claude_cli, main(), pattern loading fallbacks, session tracker
integration, FAIL_CLOSED=False paths, import fallbacks.
"""

import sys
import os
import json
import tempfile
import shutil
import subprocess
import importlib
import runpy
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

    def test_block_truncates_long_command(self):
        captured = StringIO()
        long_cmd = "x" * 200
        with self.assertRaises(SystemExit):
            with patch("sys.stdout", captured):
                pre_tool_use.block_command("test", long_cmd, "pattern", "/tmp")

        output = json.loads(captured.getvalue())
        self.assertIn("...", output["hookSpecificOutput"]["permissionDecisionReason"])

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
        stderr = StringIO()
        with self.assertRaises(SystemExit):
            with patch("sys.stderr", stderr):
                pre_tool_use.allow_command("(internal)", "ls", "pattern", "/tmp")
        self.assertEqual(stderr.getvalue(), "")


class TestCheckUninstallScript(TestCase):
    """Test check_uninstall_script()."""

    def test_detects_uninstall_sh(self):
        with self.assertRaises(SystemExit):
            with patch("sys.stdout", StringIO()):
                pre_tool_use.check_uninstall_script("./uninstall.sh")

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

    def test_unlink_io_error(self):
        """Covers lines 345-346."""
        pre_tool_use.SKIP_FILE.write_text("1")
        with patch.object(Path, "unlink", side_effect=OSError("perm")):
            self.assertTrue(pre_tool_use.decrement_skip())

    def test_read_io_error(self):
        """Covers lines 352-353."""
        pre_tool_use.SKIP_FILE.write_text("1")
        with patch.object(Path, "read_text", side_effect=OSError("read error")):
            self.assertFalse(pre_tool_use.decrement_skip())


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
        pre_tool_use.clear_skip()

    def test_clear_skip_type_error_then_success(self):
        """Covers lines 371-375: TypeError from unlink(missing_ok=True) then compat path."""
        pre_tool_use.SKIP_FILE.write_text("1")
        call_count = [0]
        original_unlink = Path.unlink

        def smart_unlink(self_path, *args, **kwargs):
            call_count[0] += 1
            if 'missing_ok' in kwargs:
                raise TypeError("unexpected keyword")
            # Normal unlink (no missing_ok kwarg) - call original
            original_unlink(self_path)

        with patch.object(Path, "unlink", smart_unlink):
            pre_tool_use.clear_skip()
        # Should have called unlink twice: first with missing_ok, then without
        self.assertEqual(call_count[0], 2)

    def test_clear_skip_type_error_then_os_error(self):
        """Covers line 377: inner OSError in compat path."""
        pre_tool_use.SKIP_FILE.write_text("1")

        def smart_unlink(self_path, *args, **kwargs):
            if 'missing_ok' in kwargs:
                raise TypeError("unexpected keyword")
            raise OSError("permission denied")

        with patch.object(Path, "unlink", smart_unlink):
            pre_tool_use.clear_skip()  # Should not raise

    def test_clear_skip_os_error(self):
        """Covers line 378-379: (IOError, OSError) in clear_skip."""
        pre_tool_use.SKIP_FILE.write_text("1")
        with patch.object(Path, "unlink", side_effect=OSError("perm denied")):
            pre_tool_use.clear_skip()
            # Should not raise


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

    def test_windows_bat(self):
        with patch("platform.system", return_value="Windows"):
            result = pre_tool_use._build_claude_exec("C:\\npm\\claude.bat", ["--print"])
            self.assertEqual(result, ["cmd", "/c", "C:\\npm\\claude.bat", "--print"])

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

    def test_claude_not_in_path_checks_candidates(self):
        """Covers lines 580, 600-603: candidate loop with failures."""
        temp_dir = tempfile.mkdtemp()
        try:
            # Create a fake candidate file
            fake_claude = Path(temp_dir) / "claude"
            fake_claude.write_text("fake")

            with patch("shutil.which", return_value=None), \
                 patch("platform.system", return_value="Linux"), \
                 patch.object(pre_tool_use, "_build_claude_exec",
                              return_value=["fake_claude"]):
                # Mock the candidates list
                with patch.object(Path, "exists", return_value=True), \
                     patch.object(Path, "is_file", return_value=True), \
                     patch.object(pre_tool_use.subprocess, "run", side_effect=subprocess.TimeoutExpired("x", 5)):
                    result = pre_tool_use.find_claude_cli()
                    # All candidates fail with timeout → returns None
                    self.assertIsNone(result)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_claude_not_found_returns_none(self):
        """Covers line 603: return None at end."""
        with patch("shutil.which", return_value=None), \
             patch("platform.system", return_value="Linux"):
            result = pre_tool_use.find_claude_cli()
            self.assertIsNone(result)

    def test_windows_candidates_branch(self):
        """Covers lines 566-577: Windows candidate path building."""
        with patch("shutil.which", return_value=None), \
             patch("platform.system", return_value="Windows"), \
             patch.dict(os.environ, {"APPDATA": "C:\\Users\\test\\AppData\\Roaming",
                                     "LOCALAPPDATA": "C:\\Users\\test\\AppData\\Local"}), \
             patch.object(Path, "exists", return_value=False):
            result = pre_tool_use.find_claude_cli()
            self.assertIsNone(result)

    def test_candidate_found_successfully(self):
        """Covers lines 598-599: successful candidate returns path."""
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("shutil.which", return_value=None), \
             patch("platform.system", return_value="Linux"), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "is_file", return_value=True), \
             patch.object(pre_tool_use.subprocess, "run", return_value=mock_result):
            result = pre_tool_use.find_claude_cli()
            self.assertIsNotNone(result)


class TestAskClaude(TestCase):
    """Test ask_claude() with mocked subprocess.

    All tests that mock subprocess.run also mock _build_claude_exec to prevent
    platform.system() from calling subprocess internally on Windows (Python 3.10+
    routes subprocess.check_output through subprocess.run).
    """

    _MOCK_EXEC = ["claude", "--print", "--model", "haiku"]

    def test_cli_unavailable_blocks(self):
        with patch.object(pre_tool_use, "find_claude_cli", return_value=None):
            verdict, reason = pre_tool_use.ask_claude("test cmd", "/tmp")
            self.assertEqual(verdict, "BLOCK")
            self.assertIn("unavailable", reason.lower())

    def test_cli_unavailable_fail_open(self):
        """Covers line 676: FAIL_CLOSED=False path."""
        with patch.object(pre_tool_use, "find_claude_cli", return_value=None), \
             patch.object(pre_tool_use, "FAIL_CLOSED", False):
            verdict, reason = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "ALLOW")

    def test_cli_success_allow(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"verdict": "ALLOW", "reason": "Safe command"}'

        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch.object(pre_tool_use, "_build_claude_exec", return_value=self._MOCK_EXEC), \
             patch.object(pre_tool_use.subprocess, "run", return_value=mock_result):
            verdict, reason = pre_tool_use.ask_claude("ls", "/tmp")
            self.assertEqual(verdict, "ALLOW")

    def test_cli_success_block(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"verdict": "BLOCK", "reason": "Dangerous operation"}'

        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch.object(pre_tool_use, "_build_claude_exec", return_value=self._MOCK_EXEC), \
             patch.object(pre_tool_use.subprocess, "run", return_value=mock_result):
            verdict, reason = pre_tool_use.ask_claude("rm -rf /", "/tmp")
            self.assertEqual(verdict, "BLOCK")

    def test_cli_error_blocks(self):
        mock_result = MagicMock()
        mock_result.returncode = 1

        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch.object(pre_tool_use, "_build_claude_exec", return_value=self._MOCK_EXEC), \
             patch.object(pre_tool_use.subprocess, "run", return_value=mock_result):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "BLOCK")

    def test_cli_error_fail_open(self):
        """Covers line 694: FAIL_CLOSED=False on CLI error."""
        mock_result = MagicMock()
        mock_result.returncode = 1

        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch.object(pre_tool_use, "_build_claude_exec", return_value=self._MOCK_EXEC), \
             patch.object(pre_tool_use.subprocess, "run", return_value=mock_result), \
             patch.object(pre_tool_use, "FAIL_CLOSED", False):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "ALLOW")

    def test_unparseable_response_blocks(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "I have no idea what to say about this"

        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch.object(pre_tool_use, "_build_claude_exec", return_value=self._MOCK_EXEC), \
             patch.object(pre_tool_use.subprocess, "run", return_value=mock_result):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "BLOCK")

    def test_unparseable_response_fail_open(self):
        """Covers line 703: FAIL_CLOSED=False on unparseable."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "I have no idea"

        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch.object(pre_tool_use, "_build_claude_exec", return_value=self._MOCK_EXEC), \
             patch.object(pre_tool_use.subprocess, "run", return_value=mock_result), \
             patch.object(pre_tool_use, "FAIL_CLOSED", False):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "ALLOW")

    def test_cli_timeout_blocks(self):
        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch.object(pre_tool_use, "_build_claude_exec", return_value=self._MOCK_EXEC), \
             patch.object(pre_tool_use.subprocess, "run", side_effect=subprocess.TimeoutExpired("claude", 15)):
            verdict, reason = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "BLOCK")
            self.assertIn("timed out", reason.lower())

    def test_cli_timeout_fail_open(self):
        """Covers line 711: FAIL_CLOSED=False on timeout."""
        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch.object(pre_tool_use, "_build_claude_exec", return_value=self._MOCK_EXEC), \
             patch.object(pre_tool_use.subprocess, "run", side_effect=subprocess.TimeoutExpired("claude", 15)), \
             patch.object(pre_tool_use, "FAIL_CLOSED", False):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "ALLOW")

    def test_cli_subprocess_error_blocks(self):
        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch.object(pre_tool_use, "_build_claude_exec", return_value=self._MOCK_EXEC), \
             patch.object(pre_tool_use.subprocess, "run", side_effect=subprocess.SubprocessError("fail")):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "BLOCK")

    def test_cli_subprocess_error_fail_open(self):
        """Covers line 717: FAIL_CLOSED=False on SubprocessError."""
        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch.object(pre_tool_use, "_build_claude_exec", return_value=self._MOCK_EXEC), \
             patch.object(pre_tool_use.subprocess, "run", side_effect=subprocess.SubprocessError("fail")), \
             patch.object(pre_tool_use, "FAIL_CLOSED", False):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "ALLOW")

    def test_cli_os_error_blocks(self):
        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch.object(pre_tool_use, "_build_claude_exec", return_value=self._MOCK_EXEC), \
             patch.object(pre_tool_use.subprocess, "run", side_effect=OSError("not found")):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "BLOCK")

    def test_cli_os_error_fail_open(self):
        """Covers line 723: FAIL_CLOSED=False on OSError."""
        with patch.object(pre_tool_use, "find_claude_cli", return_value="/usr/bin/claude"), \
             patch.object(pre_tool_use, "_build_claude_exec", return_value=self._MOCK_EXEC), \
             patch.object(pre_tool_use.subprocess, "run", side_effect=OSError("not found")), \
             patch.object(pre_tool_use, "FAIL_CLOSED", False):
            verdict, _ = pre_tool_use.ask_claude("test", "/tmp")
            self.assertEqual(verdict, "ALLOW")


class TestParseLlmResponseEdgeCases(TestCase):
    """Additional edge cases for parse_llm_response."""

    def test_markdown_without_json_keyword_block(self):
        response = "```\nI think you should BLOCK this command\n```"
        verdict, _ = pre_tool_use.parse_llm_response(response)
        self.assertEqual(verdict, "BLOCK")

    def test_brace_matching_no_markdown(self):
        """Covers lines 628-635: brace matching when ``` present but no json block."""
        response = '```\nsome text\n```\nmore text {"verdict": "ALLOW", "reason": "ok"}'
        verdict, _ = pre_tool_use.parse_llm_response(response)
        self.assertEqual(verdict, "ALLOW")

    def test_empty_response(self):
        verdict, _ = pre_tool_use.parse_llm_response("")
        self.assertEqual(verdict, "UNKNOWN")

    def test_keyword_allow(self):
        """Covers line 676 (via parse): keyword ALLOW detection."""
        response = "I think this is safe, I ALLOW it to proceed"
        verdict, _ = pre_tool_use.parse_llm_response(response)
        self.assertEqual(verdict, "ALLOW")


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
        """Covers lines 278-280 (pattern_data branch)."""
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
        """Covers lines 278-280 (except branch)."""
        with patch("builtins.open", side_effect=OSError("disk full")):
            pre_tool_use.log_decision("test", "ALLOW", "test", "pattern", "/tmp")


class TestPatternLoadingFallbacks(TestCase):
    """Test pattern loading when pattern_loader is unavailable."""

    def test_load_dangerous_patterns_unavailable(self):
        """Covers lines 78-79."""
        orig = pre_tool_use.PATTERN_LOADER_AVAILABLE
        try:
            pre_tool_use.PATTERN_LOADER_AVAILABLE = False
            result = pre_tool_use._load_dangerous_patterns()
            self.assertEqual(result, [])
        finally:
            pre_tool_use.PATTERN_LOADER_AVAILABLE = orig

    def test_load_dangerous_patterns_exception(self):
        """Covers lines 95-97."""
        with patch.object(pre_tool_use, "load_dangerous_commands", side_effect=Exception("yaml error")):
            orig = pre_tool_use.PATTERN_LOADER_AVAILABLE
            try:
                pre_tool_use.PATTERN_LOADER_AVAILABLE = True
                result = pre_tool_use._load_dangerous_patterns()
                self.assertEqual(result, [])
            finally:
                pre_tool_use.PATTERN_LOADER_AVAILABLE = orig


class TestPatternRegistryFallback(TestCase):
    """Test fallback when registry lookup fails."""

    def test_dangerous_registry_miss(self):
        """Covers line 467."""
        orig_patterns = pre_tool_use.DANGEROUS_PATTERNS
        orig_registry = pre_tool_use._PATTERN_REGISTRY.copy()
        try:
            pre_tool_use.DANGEROUS_PATTERNS = [(".*test_match.*", "NONEXISTENT-ID")]
            pre_tool_use._PATTERN_REGISTRY.clear()

            matched, data = pre_tool_use.check_dangerous("test_match_command")
            self.assertTrue(matched)
            self.assertEqual(data["id"], "NONEXISTENT-ID")
            self.assertEqual(data["severity"], "medium")
        finally:
            pre_tool_use.DANGEROUS_PATTERNS = orig_patterns
            pre_tool_use._PATTERN_REGISTRY.clear()
            pre_tool_use._PATTERN_REGISTRY.update(orig_registry)


class TestCheckDangerousRegexError(TestCase):
    """Test regex error handling in check_dangerous."""

    def test_invalid_regex_skipped(self):
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


class TestIsAllSafeEdge(TestCase):
    """Test is_all_safe edge cases."""

    def test_empty_string(self):
        """Covers line 536."""
        self.assertTrue(pre_tool_use.is_all_safe(""))

    def test_whitespace_only(self):
        self.assertTrue(pre_tool_use.is_all_safe("   "))


class TestSaveStateError(TestCase):
    """Test save_state error handling."""

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

    def test_save_state_io_error(self):
        """Covers lines 322-323."""
        with patch("tempfile.NamedTemporaryFile", side_effect=OSError("disk full")):
            # Should not raise
            pre_tool_use.save_state({"enabled": True})

    def test_load_state_invalid_enabled_type(self):
        pre_tool_use.STATE_FILE.write_text('{"enabled": "yes"}')
        state = pre_tool_use.load_state()
        self.assertTrue(state["enabled"])

    def test_load_state_io_error(self):
        pre_tool_use.STATE_FILE.mkdir(parents=True, exist_ok=True)
        state = pre_tool_use.load_state()
        self.assertTrue(state["enabled"])

    def test_save_state_creates_dir(self):
        new_dir = Path(self.temp_dir) / "subdir"
        pre_tool_use.STATE_DIR = new_dir
        pre_tool_use.STATE_FILE = new_dir / "state.json"
        pre_tool_use.save_state({"enabled": False})
        self.assertTrue(pre_tool_use.STATE_FILE.exists())


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

    def test_skip_bypasses_dangerous(self):
        pre_tool_use.SKIP_FILE.write_text("1")
        _, stderr, exit_code = self._run_main({
            "tool_input": {"command": "rm -rf ~/"},
            "cwd": "/tmp"
        })
        self.assertEqual(exit_code, 0)
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

    def test_invalid_json_fail_open(self):
        """Covers line 815: FAIL_CLOSED=False on bad JSON."""
        with patch.object(pre_tool_use, "FAIL_CLOSED", False):
            _, _, exit_code = self._run_main("not json")
            self.assertEqual(exit_code, 0)

    def test_uninstall_detected(self):
        stdout, _, exit_code = self._run_main({
            "tool_input": {"command": "./uninstall.sh"},
            "cwd": "/tmp"
        })
        self.assertEqual(exit_code, 0)
        data = json.loads(stdout)
        self.assertIn("REMOVAL", data["hookSpecificOutput"]["permissionDecisionReason"])

    def test_unknown_command_goes_to_llm(self):
        with patch.object(pre_tool_use, "ask_claude", return_value=("ALLOW", "looks fine")):
            _, _, exit_code = self._run_main({
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
            data = json.loads(stdout)
            self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_dangerous_with_session_tracker_error(self):
        """Covers lines 867-869: session tracker error for dangerous command."""
        mock_tracker = MagicMock()
        mock_tracker.record_block.side_effect = Exception("tracker error")

        with patch.object(pre_tool_use, "SESSION_TRACKER_AVAILABLE", True), \
             patch.object(pre_tool_use, "get_tracker", return_value=mock_tracker):
            stdout, stderr, exit_code = self._run_main({
                "tool_input": {"command": "rm -rf ~/"},
                "cwd": "/tmp"
            })
            self.assertEqual(exit_code, 0)
            data = json.loads(stdout)
            self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")
            self.assertIn("tracker error", stderr)


class TestModuleLevelReload(TestCase):
    """Test module-level code paths via importlib.reload."""

    def test_import_fallback_pattern_loader(self):
        """Covers lines 33-34: ImportError for pattern_loader."""
        orig_modules = {}
        for mod_name in ['pattern_loader', 'pre_tool_use']:
            if mod_name in sys.modules:
                orig_modules[mod_name] = sys.modules[mod_name]

        try:
            sys.modules['pattern_loader'] = None
            if 'pre_tool_use' in sys.modules:
                del sys.modules['pre_tool_use']

            import pre_tool_use as reloaded
            self.assertFalse(reloaded.PATTERN_LOADER_AVAILABLE)
        finally:
            for mod_name, mod in orig_modules.items():
                sys.modules[mod_name] = mod
            if 'pattern_loader' not in orig_modules and 'pattern_loader' in sys.modules:
                del sys.modules['pattern_loader']
            if 'pre_tool_use' in sys.modules:
                del sys.modules['pre_tool_use']
            import pre_tool_use  # noqa: F811

    def test_import_fallback_session_tracker(self):
        """Covers lines 40-41: ImportError for session_tracker."""
        orig_modules = {}
        for mod_name in ['session_tracker', 'pre_tool_use']:
            if mod_name in sys.modules:
                orig_modules[mod_name] = sys.modules[mod_name]

        try:
            sys.modules['session_tracker'] = None
            if 'pre_tool_use' in sys.modules:
                del sys.modules['pre_tool_use']

            import pre_tool_use as reloaded
            self.assertFalse(reloaded.SESSION_TRACKER_AVAILABLE)
        finally:
            for mod_name, mod in orig_modules.items():
                sys.modules[mod_name] = mod
            if 'session_tracker' not in orig_modules and 'session_tracker' in sys.modules:
                del sys.modules['session_tracker']
            if 'pre_tool_use' in sys.modules:
                del sys.modules['pre_tool_use']
            import pre_tool_use  # noqa: F811

    def test_debug_file_write_error_at_import(self):
        """Covers lines 49-50: bare except during debug file write at import."""
        orig_modules = {}
        if 'pre_tool_use' in sys.modules:
            orig_modules['pre_tool_use'] = sys.modules['pre_tool_use']

        try:
            if 'pre_tool_use' in sys.modules:
                del sys.modules['pre_tool_use']

            with patch("pathlib.Path.mkdir", side_effect=OSError("no dir")):
                import pre_tool_use as reloaded  # noqa: F811
                self.assertTrue(hasattr(reloaded, 'main'))
        finally:
            for mod_name, mod in orig_modules.items():
                sys.modules[mod_name] = mod
            if 'pre_tool_use' in sys.modules:
                del sys.modules['pre_tool_use']
            import pre_tool_use  # noqa: F811


class TestNameMainGuard(TestCase):
    """Test __name__ == '__main__' guard."""

    def test_runpy_covers_name_guard(self):
        """Covers line 891."""
        hook_path = str(Path(__file__).parent.parent / "hooks" / "pre_tool_use.py")
        input_data = json.dumps({
            "tool_input": {"command": "ls"},
            "cwd": "/tmp"
        })

        with patch("sys.stdin", StringIO(input_data)), \
             patch("sys.stdout", StringIO()), \
             patch("sys.stderr", StringIO()):
            try:
                runpy.run_path(hook_path, run_name="__main__")
            except SystemExit:
                pass


if __name__ == "__main__":
    unittest_main()
