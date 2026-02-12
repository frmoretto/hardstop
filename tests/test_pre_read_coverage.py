#!/usr/bin/env python3
"""
Unit tests for uncovered code paths in pre_read.py.

Targets: log_decision, block, warn, block_error, get_skip_count,
decrement_skip, main(), pattern loading fallbacks, session tracker
integration, import fallbacks, module-level side effects.
"""

import sys
import os
import json
import tempfile
import shutil
import importlib
import runpy
from pathlib import Path
from unittest import TestCase, main as unittest_main
from unittest.mock import patch, MagicMock, mock_open
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
        """Logging failure should not raise (covers lines 269-270)."""
        with patch("builtins.open", side_effect=OSError("disk full")):
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

    def test_unlink_io_error(self):
        """Covers lines 389-390: IOError during SKIP_FILE.unlink()."""
        pre_read.SKIP_FILE.write_text("1")
        with patch.object(Path, "unlink", side_effect=OSError("permission denied")):
            was_skipped, remaining = pre_read.decrement_skip()
            self.assertTrue(was_skipped)
            self.assertEqual(remaining, 0)

    def test_read_io_error(self):
        """Covers lines 396-397: IOError during read_text()."""
        pre_read.SKIP_FILE.write_text("1")
        with patch.object(Path, "read_text", side_effect=OSError("read error")):
            was_skipped, remaining = pre_read.decrement_skip()
            self.assertFalse(was_skipped)
            self.assertEqual(remaining, 0)


class TestPatternLoadingFallbacks(TestCase):
    """Test pattern loading when pattern_loader is unavailable."""

    def test_load_dangerous_patterns_unavailable(self):
        """Covers lines 75-76."""
        orig = pre_read.PATTERN_LOADER_AVAILABLE
        try:
            pre_read.PATTERN_LOADER_AVAILABLE = False
            result = pre_read._load_dangerous_read_patterns()
            self.assertEqual(result, [])
        finally:
            pre_read.PATTERN_LOADER_AVAILABLE = orig

    def test_load_sensitive_patterns_unavailable(self):
        """Covers lines 109-110."""
        orig = pre_read.PATTERN_LOADER_AVAILABLE
        try:
            pre_read.PATTERN_LOADER_AVAILABLE = False
            result = pre_read._load_sensitive_read_patterns()
            self.assertEqual(result, [])
        finally:
            pre_read.PATTERN_LOADER_AVAILABLE = orig

    def test_load_dangerous_patterns_exception(self):
        """Covers lines 91-93."""
        with patch.object(pre_read, "load_dangerous_reads", side_effect=Exception("yaml error")):
            orig = pre_read.PATTERN_LOADER_AVAILABLE
            try:
                pre_read.PATTERN_LOADER_AVAILABLE = True
                result = pre_read._load_dangerous_read_patterns()
                self.assertEqual(result, [])
            finally:
                pre_read.PATTERN_LOADER_AVAILABLE = orig

    def test_load_sensitive_patterns_exception(self):
        """Covers lines 125-127."""
        with patch.object(pre_read, "load_sensitive_reads", side_effect=Exception("yaml error")):
            orig = pre_read.PATTERN_LOADER_AVAILABLE
            try:
                pre_read.PATTERN_LOADER_AVAILABLE = True
                result = pre_read._load_sensitive_read_patterns()
                self.assertEqual(result, [])
            finally:
                pre_read.PATTERN_LOADER_AVAILABLE = orig


class TestPatternRegistryFallback(TestCase):
    """Test fallback dict when registry lookup fails."""

    def test_dangerous_registry_miss(self):
        """Covers line 316: fallback when pattern_id not in registry."""
        orig_patterns = pre_read.DANGEROUS_READ_PATTERNS
        orig_registry = pre_read._READ_PATTERN_REGISTRY.copy()
        try:
            # Add a pattern that matches but isn't in the registry
            pre_read.DANGEROUS_READ_PATTERNS = [("FAKE_MATCH", "NONEXISTENT-ID")]
            pre_read._READ_PATTERN_REGISTRY.clear()

            matched, data = pre_read.check_dangerous_patterns("FAKE_MATCH")
            self.assertTrue(matched)
            self.assertEqual(data["id"], "NONEXISTENT-ID")
            self.assertEqual(data["severity"], "medium")
        finally:
            pre_read.DANGEROUS_READ_PATTERNS = orig_patterns
            pre_read._READ_PATTERN_REGISTRY.update(orig_registry)

    def test_sensitive_registry_miss(self):
        """Covers line 340: fallback when pattern_id not in registry."""
        orig_patterns = pre_read.SENSITIVE_READ_PATTERNS
        orig_registry = pre_read._SENSITIVE_READ_REGISTRY.copy()
        try:
            pre_read.SENSITIVE_READ_PATTERNS = [("FAKE_MATCH", "NONEXISTENT-ID")]
            pre_read._SENSITIVE_READ_REGISTRY.clear()

            matched, data = pre_read.check_sensitive_patterns("FAKE_MATCH")
            self.assertTrue(matched)
            self.assertEqual(data["id"], "NONEXISTENT-ID")
            self.assertEqual(data["severity"], "low")
        finally:
            pre_read.SENSITIVE_READ_PATTERNS = orig_patterns
            pre_read._SENSITIVE_READ_REGISTRY.update(orig_registry)


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
        self.assertIn("skipped", stderr.lower())

    def test_multi_skip_decrements(self):
        pre_read.SKIP_FILE.write_text("2")
        stdout, stderr, exit_code = self._run_main({
            "tool_input": {"file_path": "~/.ssh/id_rsa"},
            "cwd": "/project"
        })
        self.assertEqual(exit_code, 0)
        self.assertIn("1 skip", stderr)
        self.assertTrue(pre_read.SKIP_FILE.exists())

    def test_invalid_json_blocks_fail_closed(self):
        stdout, _, exit_code = self._run_main("not valid json")
        self.assertEqual(exit_code, 0)
        data = json.loads(stdout)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_invalid_json_fail_open(self):
        """Covers line 475: sys.exit(0) when FAIL_CLOSED=False and JSONDecodeError."""
        with patch.object(pre_read, "FAIL_CLOSED", False):
            stdout, _, exit_code = self._run_main("not valid json")
            self.assertEqual(exit_code, 0)
            # Should exit cleanly without blocking (no JSON output)
            self.assertEqual(stdout.strip(), "")

    def test_stdin_read_exception_blocks_fail_closed(self):
        """Covers lines 476-478: generic Exception during stdin read, FAIL_CLOSED=True."""
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.read.side_effect = Exception("unexpected error")
            stdout = StringIO()
            with patch("sys.stdout", stdout), \
                 patch("sys.stderr", StringIO()):
                with self.assertRaises(SystemExit) as ctx:
                    pre_read.main()
                self.assertEqual(ctx.exception.code, 0)
                data = json.loads(stdout.getvalue())
                self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_stdin_read_exception_fail_open(self):
        """Covers line 479: sys.exit(0) when FAIL_CLOSED=False and Exception."""
        with patch("sys.stdin") as mock_stdin, \
             patch.object(pre_read, "FAIL_CLOSED", False):
            mock_stdin.read.side_effect = Exception("unexpected error")
            stdout = StringIO()
            with patch("sys.stdout", stdout), \
                 patch("sys.stderr", StringIO()):
                with self.assertRaises(SystemExit) as ctx:
                    pre_read.main()
                self.assertEqual(ctx.exception.code, 0)
                # Should exit cleanly without blocking
                self.assertEqual(stdout.getvalue().strip(), "")

    def test_debug_write_failure_in_main(self):
        """Covers lines 498-499: debug file write error in main."""
        pre_read.DEBUG_FILE = Path(self.temp_dir) / "nonexistent_subdir" / "debug.log"
        # Should not crash even if debug write fails
        stdout, _, exit_code = self._run_main({
            "tool_input": {"file_path": "main.py"},
            "cwd": "/project"
        })
        self.assertEqual(exit_code, 0)

    def test_unknown_file_allows(self):
        """Files matching no pattern should be allowed (default)."""
        stdout, _, exit_code = self._run_main({
            "tool_input": {"file_path": "random_binary.dat"},
            "cwd": "/project"
        })
        self.assertEqual(exit_code, 0)

    def test_dangerous_with_session_tracker_error(self):
        """Covers lines 535-537: session tracker exception during dangerous read."""
        mock_tracker = MagicMock()
        mock_tracker.record_block.side_effect = Exception("tracker error")

        with patch.object(pre_read, "SESSION_TRACKER_AVAILABLE", True), \
             patch.object(pre_read, "get_tracker", return_value=mock_tracker):
            stdout, stderr, exit_code = self._run_main({
                "tool_input": {"file_path": "~/.ssh/id_rsa"},
                "cwd": "/project"
            })
            self.assertEqual(exit_code, 0)
            # Should still block despite tracker error
            data = json.loads(stdout)
            self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")
            self.assertIn("tracker error", stderr)

    def test_sensitive_with_critical_severity_adjustment(self):
        """Covers line 557: severity adjustment critical -> high."""
        mock_tracker = MagicMock()
        mock_tracker.get_risk_score.return_value = 10
        mock_tracker.get_risk_level.return_value = "low"

        # Use a sensitive pattern with critical severity
        orig_patterns = pre_read.SENSITIVE_READ_PATTERNS
        orig_registry = pre_read._SENSITIVE_READ_REGISTRY.copy()
        try:
            pre_read.SENSITIVE_READ_PATTERNS = [("config\\.json", "SENS-001")]
            pre_read._SENSITIVE_READ_REGISTRY["SENS-001"] = {
                "id": "SENS-001",
                "regex": "config\\.json",
                "message": "Sensitive config",
                "severity": "critical",
                "category": "config",
            }

            with patch.object(pre_read, "SESSION_TRACKER_AVAILABLE", True), \
                 patch.object(pre_read, "get_tracker", return_value=mock_tracker):
                stdout, stderr, exit_code = self._run_main({
                    "tool_input": {"file_path": "config.json"},
                    "cwd": "/project"
                })

            # Verify severity was adjusted in tracker call
            call_args = mock_tracker.record_block.call_args
            tracking_data = call_args[0][1]
            self.assertEqual(tracking_data["severity"], "high")
            self.assertEqual(tracking_data["original_severity"], "critical")
        finally:
            pre_read.SENSITIVE_READ_PATTERNS = orig_patterns
            pre_read._SENSITIVE_READ_REGISTRY.clear()
            pre_read._SENSITIVE_READ_REGISTRY.update(orig_registry)

    def test_sensitive_with_low_severity_passthrough(self):
        """Covers line 561: severity passthrough for non-critical/high."""
        mock_tracker = MagicMock()
        mock_tracker.get_risk_score.return_value = 5
        mock_tracker.get_risk_level.return_value = "low"

        orig_patterns = pre_read.SENSITIVE_READ_PATTERNS
        orig_registry = pre_read._SENSITIVE_READ_REGISTRY.copy()
        try:
            pre_read.SENSITIVE_READ_PATTERNS = [("config\\.json", "SENS-002")]
            pre_read._SENSITIVE_READ_REGISTRY["SENS-002"] = {
                "id": "SENS-002",
                "regex": "config\\.json",
                "message": "Sensitive config",
                "severity": "low",
                "category": "config",
            }

            with patch.object(pre_read, "SESSION_TRACKER_AVAILABLE", True), \
                 patch.object(pre_read, "get_tracker", return_value=mock_tracker):
                self._run_main({
                    "tool_input": {"file_path": "config.json"},
                    "cwd": "/project"
                })

            call_args = mock_tracker.record_block.call_args
            tracking_data = call_args[0][1]
            self.assertEqual(tracking_data["severity"], "low")
        finally:
            pre_read.SENSITIVE_READ_PATTERNS = orig_patterns
            pre_read._SENSITIVE_READ_REGISTRY.clear()
            pre_read._SENSITIVE_READ_REGISTRY.update(orig_registry)

    def test_sensitive_with_tracker_error(self):
        """Covers lines 575-577: session tracker error during sensitive read."""
        mock_tracker = MagicMock()
        mock_tracker.record_block.side_effect = Exception("tracker broke")

        orig_patterns = pre_read.SENSITIVE_READ_PATTERNS
        orig_registry = pre_read._SENSITIVE_READ_REGISTRY.copy()
        try:
            pre_read.SENSITIVE_READ_PATTERNS = [("config\\.json", "SENS-003")]
            pre_read._SENSITIVE_READ_REGISTRY["SENS-003"] = {
                "id": "SENS-003",
                "regex": "config\\.json",
                "message": "Config file",
                "severity": "medium",
                "category": "config",
            }

            with patch.object(pre_read, "SESSION_TRACKER_AVAILABLE", True), \
                 patch.object(pre_read, "get_tracker", return_value=mock_tracker):
                stdout, stderr, exit_code = self._run_main({
                    "tool_input": {"file_path": "config.json"},
                    "cwd": "/project"
                })

            self.assertIn("tracker broke", stderr)
            self.assertEqual(exit_code, 0)
        finally:
            pre_read.SENSITIVE_READ_PATTERNS = orig_patterns
            pre_read._SENSITIVE_READ_REGISTRY.clear()
            pre_read._SENSITIVE_READ_REGISTRY.update(orig_registry)

    def test_sensitive_with_high_severity_adjustment(self):
        """Covers high -> medium severity adjustment."""
        mock_tracker = MagicMock()
        mock_tracker.get_risk_score.return_value = 10
        mock_tracker.get_risk_level.return_value = "low"

        orig_patterns = pre_read.SENSITIVE_READ_PATTERNS
        orig_registry = pre_read._SENSITIVE_READ_REGISTRY.copy()
        try:
            pre_read.SENSITIVE_READ_PATTERNS = [("config\\.json", "SENS-004")]
            pre_read._SENSITIVE_READ_REGISTRY["SENS-004"] = {
                "id": "SENS-004",
                "regex": "config\\.json",
                "message": "Sensitive",
                "severity": "high",
                "category": "config",
            }

            with patch.object(pre_read, "SESSION_TRACKER_AVAILABLE", True), \
                 patch.object(pre_read, "get_tracker", return_value=mock_tracker):
                self._run_main({
                    "tool_input": {"file_path": "config.json"},
                    "cwd": "/project"
                })

            call_args = mock_tracker.record_block.call_args
            tracking_data = call_args[0][1]
            self.assertEqual(tracking_data["severity"], "medium")
        finally:
            pre_read.SENSITIVE_READ_PATTERNS = orig_patterns
            pre_read._SENSITIVE_READ_REGISTRY.clear()
            pre_read._SENSITIVE_READ_REGISTRY.update(orig_registry)


class TestModuleLevelReload(TestCase):
    """Test module-level code paths via importlib.reload."""

    def test_import_fallback_pattern_loader(self):
        """Covers lines 28-29: ImportError for pattern_loader."""
        orig_modules = {}
        for mod_name in ['pattern_loader', 'pre_read']:
            if mod_name in sys.modules:
                orig_modules[mod_name] = sys.modules[mod_name]

        try:
            # Remove pattern_loader from modules, add sentinel to block import
            sys.modules['pattern_loader'] = None  # Causes ImportError
            if 'pre_read' in sys.modules:
                del sys.modules['pre_read']

            # Re-import pre_read
            import pre_read as reloaded
            self.assertFalse(reloaded.PATTERN_LOADER_AVAILABLE)
        finally:
            # Restore
            for mod_name, mod in orig_modules.items():
                sys.modules[mod_name] = mod
            if 'pattern_loader' not in orig_modules and 'pattern_loader' in sys.modules:
                del sys.modules['pattern_loader']
            # Re-import original
            if 'pre_read' in sys.modules:
                del sys.modules['pre_read']
            import pre_read  # noqa: F811

    def test_import_fallback_session_tracker(self):
        """Covers lines 35-36: ImportError for session_tracker."""
        orig_modules = {}
        for mod_name in ['session_tracker', 'pre_read']:
            if mod_name in sys.modules:
                orig_modules[mod_name] = sys.modules[mod_name]

        try:
            sys.modules['session_tracker'] = None  # Causes ImportError
            if 'pre_read' in sys.modules:
                del sys.modules['pre_read']

            import pre_read as reloaded
            self.assertFalse(reloaded.SESSION_TRACKER_AVAILABLE)
        finally:
            for mod_name, mod in orig_modules.items():
                sys.modules[mod_name] = mod
            if 'session_tracker' not in orig_modules and 'session_tracker' in sys.modules:
                del sys.modules['session_tracker']
            if 'pre_read' in sys.modules:
                del sys.modules['pre_read']
            import pre_read  # noqa: F811

    def test_debug_file_write_error_at_import(self):
        """Covers lines 54-55: bare except during debug file write at import."""
        orig_modules = {}
        if 'pre_read' in sys.modules:
            orig_modules['pre_read'] = sys.modules['pre_read']

        try:
            if 'pre_read' in sys.modules:
                del sys.modules['pre_read']

            # Mock STATE_DIR.mkdir and open to fail
            with patch("pathlib.Path.mkdir", side_effect=OSError("no dir")):
                import pre_read as reloaded  # noqa: F811
                # Module should load despite debug write failure
                self.assertTrue(hasattr(reloaded, 'main'))
        finally:
            for mod_name, mod in orig_modules.items():
                sys.modules[mod_name] = mod
            if 'pre_read' in sys.modules:
                del sys.modules['pre_read']
            import pre_read  # noqa: F811


class TestNameMainGuard(TestCase):
    """Test __name__ == '__main__' guard."""

    def test_runpy_covers_name_guard(self):
        """Covers line 590."""
        hook_path = str(Path(__file__).parent.parent / "hooks" / "pre_read.py")
        input_data = json.dumps({
            "tool_input": {"file_path": "main.py"},
            "cwd": "/project"
        })

        with patch("sys.stdin", StringIO(input_data)), \
             patch("sys.stdout", StringIO()), \
             patch("sys.stderr", StringIO()):
            try:
                runpy.run_path(hook_path, run_name="__main__")
            except SystemExit:
                pass  # Expected


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
