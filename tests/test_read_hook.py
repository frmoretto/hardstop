#!/usr/bin/env python3
"""
Integration tests for Hardstop Read Hook v1.3.x

Tests the Read tool protection: credential detection, path normalization,
pattern matching, and skip mechanism.

Note: As of v1.3.1, blocked reads return exit code 0 with JSON output
containing permissionDecision: "deny" (instead of exit code 2).

Run: python -m pytest tests/test_read_hook.py -v
Or:  python tests/test_read_hook.py
"""

import sys
import os
import json
import tempfile
import subprocess
from pathlib import Path
from typing import Tuple
from unittest import TestCase, main as unittest_main
from unittest.mock import patch

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

from pre_read import (
    check_dangerous_patterns,
    check_sensitive_patterns,
    check_safe_patterns,
    normalize_path,
    is_skip_enabled,
    STATE_DIR,
    SKIP_FILE,
    DANGEROUS_READ_PATTERNS,
    SENSITIVE_READ_PATTERNS,
    SAFE_READ_PATTERNS,
)


class TestDangerousPatterns(TestCase):
    """Test detection of dangerous credential files."""

    def test_ssh_private_key_rsa(self):
        is_dangerous, pattern_data = check_dangerous_patterns("/home/user/.ssh/id_rsa")
        self.assertTrue(is_dangerous)
        self.assertIsNotNone(pattern_data)
        self.assertIn("SSH", pattern_data['message'])

    def test_ssh_private_key_ed25519(self):
        is_dangerous, pattern_data = check_dangerous_patterns("/home/user/.ssh/id_ed25519")
        self.assertTrue(is_dangerous)
        self.assertIsNotNone(pattern_data)
        self.assertIn("SSH", pattern_data['message'])

    def test_ssh_pem_file(self):
        is_dangerous, reason = check_dangerous_patterns("/home/user/.ssh/mykey.pem")
        self.assertTrue(is_dangerous)

    def test_ssh_config(self):
        is_dangerous, reason = check_dangerous_patterns("/home/user/.ssh/config")
        self.assertTrue(is_dangerous)

    def test_aws_credentials(self):
        is_dangerous, pattern_data = check_dangerous_patterns("/home/user/.aws/credentials")
        self.assertTrue(is_dangerous)
        self.assertIsNotNone(pattern_data)
        self.assertIn("AWS", pattern_data['message'])

    def test_aws_config(self):
        is_dangerous, reason = check_dangerous_patterns("/home/user/.aws/config")
        self.assertTrue(is_dangerous)

    def test_env_file(self):
        is_dangerous, pattern_data = check_dangerous_patterns("/project/.env")
        self.assertTrue(is_dangerous)
        self.assertIsNotNone(pattern_data)
        self.assertIn("Environment", pattern_data['message'])

    def test_env_production(self):
        is_dangerous, reason = check_dangerous_patterns("/project/.env.production")
        self.assertTrue(is_dangerous)

    def test_env_local(self):
        is_dangerous, reason = check_dangerous_patterns("/project/.env.local")
        self.assertTrue(is_dangerous)

    def test_kube_config(self):
        is_dangerous, pattern_data = check_dangerous_patterns("/home/user/.kube/config")
        self.assertTrue(is_dangerous)
        self.assertIsNotNone(pattern_data)
        self.assertIn("Kubernetes", pattern_data['message'])

    def test_docker_config(self):
        is_dangerous, reason = check_dangerous_patterns("/home/user/.docker/config.json")
        self.assertTrue(is_dangerous)

    def test_netrc(self):
        is_dangerous, reason = check_dangerous_patterns("/home/user/.netrc")
        self.assertTrue(is_dangerous)

    def test_npmrc(self):
        is_dangerous, reason = check_dangerous_patterns("/home/user/.npmrc")
        self.assertTrue(is_dangerous)

    def test_pypirc(self):
        is_dangerous, reason = check_dangerous_patterns("/home/user/.pypirc")
        self.assertTrue(is_dangerous)

    def test_credentials_json(self):
        is_dangerous, reason = check_dangerous_patterns("/project/credentials.json")
        self.assertTrue(is_dangerous)

    def test_secrets_yaml(self):
        is_dangerous, reason = check_dangerous_patterns("/project/secrets.yaml")
        self.assertTrue(is_dangerous)

    def test_gitconfig(self):
        is_dangerous, reason = check_dangerous_patterns("/home/user/.gitconfig")
        self.assertTrue(is_dangerous)

    def test_git_credentials(self):
        is_dangerous, reason = check_dangerous_patterns("/home/user/.git-credentials")
        self.assertTrue(is_dangerous)

    def test_pgpass(self):
        is_dangerous, reason = check_dangerous_patterns("/home/user/.pgpass")
        self.assertTrue(is_dangerous)

    def test_gcloud_credentials(self):
        is_dangerous, reason = check_dangerous_patterns("/home/user/.config/gcloud/credentials.db")
        self.assertTrue(is_dangerous)

    def test_azure_credentials(self):
        is_dangerous, reason = check_dangerous_patterns("/home/user/.azure/credentials")
        self.assertTrue(is_dangerous)


class TestSafePatterns(TestCase):
    """Test that safe files are allowed."""

    def test_python_file(self):
        self.assertTrue(check_safe_patterns("/project/main.py"))

    def test_javascript_file(self):
        self.assertTrue(check_safe_patterns("/project/index.js"))

    def test_typescript_file(self):
        self.assertTrue(check_safe_patterns("/project/app.ts"))

    def test_readme(self):
        self.assertTrue(check_safe_patterns("/project/README.md"))

    def test_package_json(self):
        self.assertTrue(check_safe_patterns("/project/package.json"))

    def test_requirements_txt(self):
        self.assertTrue(check_safe_patterns("/project/requirements.txt"))

    def test_env_example(self):
        # .env.example should be safe (it's a template)
        self.assertTrue(check_safe_patterns("/project/.env.example"))

    def test_env_template(self):
        self.assertTrue(check_safe_patterns("/project/.env.template"))

    def test_env_sample(self):
        self.assertTrue(check_safe_patterns("/project/.env.sample"))

    def test_dockerfile(self):
        self.assertTrue(check_safe_patterns("/project/Dockerfile"))

    def test_gitignore(self):
        self.assertTrue(check_safe_patterns("/project/.gitignore"))

    def test_html_file(self):
        self.assertTrue(check_safe_patterns("/project/index.html"))

    def test_css_file(self):
        self.assertTrue(check_safe_patterns("/project/styles.css"))

    def test_makefile(self):
        self.assertTrue(check_safe_patterns("/project/Makefile"))

    def test_cargo_toml(self):
        self.assertTrue(check_safe_patterns("/project/Cargo.toml"))

    def test_go_mod(self):
        self.assertTrue(check_safe_patterns("/project/go.mod"))


class TestSensitivePatterns(TestCase):
    """Test detection of sensitive (but not blocked) files."""

    def test_config_json(self):
        is_sensitive, reason = check_sensitive_patterns("/project/config.json")
        self.assertTrue(is_sensitive)

    def test_config_yaml(self):
        is_sensitive, reason = check_sensitive_patterns("/project/config.yaml")
        self.assertTrue(is_sensitive)

    def test_settings_json(self):
        is_sensitive, reason = check_sensitive_patterns("/project/settings.json")
        self.assertTrue(is_sensitive)

    def test_env_backup(self):
        is_sensitive, reason = check_sensitive_patterns("/project/.env.bak")
        self.assertTrue(is_sensitive)

    def test_file_with_password_in_name(self):
        is_sensitive, reason = check_sensitive_patterns("/project/database_password.txt")
        self.assertTrue(is_sensitive)

    def test_file_with_secret_in_name(self):
        is_sensitive, reason = check_sensitive_patterns("/project/my_secret_file.txt")
        self.assertTrue(is_sensitive)


class TestPathNormalization(TestCase):
    """Test path normalization for cross-platform matching."""

    def test_tilde_expansion(self):
        normalized = normalize_path("~/.ssh/id_rsa", "/")
        self.assertIn(".ssh", normalized)
        self.assertNotIn("~", normalized)

    def test_relative_path(self):
        normalized = normalize_path("config.json", "/home/user/project")
        self.assertIn("project", normalized)
        self.assertIn("config.json", normalized)

    def test_forward_slashes(self):
        # Windows paths should be normalized to forward slashes
        normalized = normalize_path("C:\\Users\\john\\.aws\\credentials", "C:\\")
        self.assertIn("/", normalized)
        # Should not contain backslashes
        self.assertNotIn("\\", normalized)

    def test_double_dots_resolved(self):
        normalized = normalize_path("/project/subdir/../config.json", "/")
        # .. should be resolved
        self.assertNotIn("..", normalized)


class TestWindowsPaths(TestCase):
    """Test Windows-specific path patterns."""

    def test_windows_aws_credentials(self):
        is_dangerous, _ = check_dangerous_patterns("C:/Users/john/.aws/credentials")
        self.assertTrue(is_dangerous)

    def test_windows_ssh_key(self):
        is_dangerous, _ = check_dangerous_patterns("C:/Users/john/.ssh/id_rsa")
        self.assertTrue(is_dangerous)

    def test_windows_env_file(self):
        is_dangerous, _ = check_dangerous_patterns("C:/Projects/myapp/.env")
        self.assertTrue(is_dangerous)

    def test_windows_kube_config(self):
        is_dangerous, _ = check_dangerous_patterns("C:/Users/john/.kube/config")
        self.assertTrue(is_dangerous)


class TestNonMatchingFiles(TestCase):
    """Test that normal files are not flagged."""

    def test_random_text_file(self):
        is_dangerous, _ = check_dangerous_patterns("/project/notes.txt")
        self.assertFalse(is_dangerous)

    def test_image_file(self):
        is_dangerous, _ = check_dangerous_patterns("/project/logo.png")
        self.assertFalse(is_dangerous)

    def test_data_csv(self):
        is_dangerous, _ = check_dangerous_patterns("/project/data.csv")
        self.assertFalse(is_dangerous)

    def test_sql_file(self):
        is_dangerous, _ = check_dangerous_patterns("/project/schema.sql")
        self.assertFalse(is_dangerous)

    def test_lock_file(self):
        is_dangerous, _ = check_dangerous_patterns("/project/package-lock.json")
        self.assertFalse(is_dangerous)


class TestSkipMechanism(TestCase):
    """Test the skip_next bypass mechanism.

    Note: As of v1.3.2, is_skip_enabled() is a read-only check.
    The skip file is consumed by the hook main() during command execution,
    not by the is_skip_enabled() check itself (multi-skip support).
    """

    def setUp(self):
        # Ensure clean state
        if SKIP_FILE.exists():
            SKIP_FILE.unlink()

    def tearDown(self):
        # Clean up
        if SKIP_FILE.exists():
            SKIP_FILE.unlink()

    def test_skip_not_enabled_by_default(self):
        self.assertFalse(is_skip_enabled())

    def test_skip_enabled_when_file_exists(self):
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        SKIP_FILE.touch()
        self.assertTrue(is_skip_enabled())

    def test_is_skip_enabled_is_read_only(self):
        """is_skip_enabled() should NOT consume the file (v1.3.2+ behavior)."""
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        SKIP_FILE.touch()
        is_skip_enabled()  # Read-only check
        # File should still exist (consumption happens in hook main())
        self.assertTrue(SKIP_FILE.exists())

    def test_skip_persists_across_checks(self):
        """Multiple is_skip_enabled() calls should return True."""
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        SKIP_FILE.touch()
        self.assertTrue(is_skip_enabled())
        self.assertTrue(is_skip_enabled())  # Still True (read-only)


class TestIntegration(TestCase):
    """Integration tests running the actual hook script.

    Note: As of v1.3.1, the hook uses JSON output with permissionDecision
    instead of exit codes to signal blocking.
    """

    @classmethod
    def setUpClass(cls):
        cls.hook_script = Path(__file__).parent.parent / "hooks" / "pre_read.py"

    def parse_hook_response(self, stdout: str) -> dict:
        """Parse hook JSON response and extract decision info."""
        try:
            response = json.loads(stdout)
            hook_output = response.get("hookSpecificOutput", {})
            decision = hook_output.get("permissionDecision", "")
            reason = hook_output.get("permissionDecisionReason", "")
            return {
                "blocked": decision == "deny",
                "reason": reason
            }
        except (json.JSONDecodeError, TypeError):
            return {"blocked": False, "reason": ""}

    def run_hook(self, file_path: str, cwd: str = "/project") -> Tuple[int, str, str]:
        """Run the hook script and return (exit_code, stdout, stderr)."""
        input_data = json.dumps({
            "tool_name": "Read",
            "tool_input": {"file_path": file_path},
            "cwd": cwd
        })

        result = subprocess.run(
            [sys.executable, str(self.hook_script)],
            input=input_data,
            capture_output=True,
            text=True
        )

        return result.returncode, result.stdout, result.stderr

    def test_blocks_ssh_key(self):
        exit_code, stdout, stderr = self.run_hook("~/.ssh/id_rsa")
        self.assertEqual(exit_code, 0)
        result = self.parse_hook_response(stdout)
        self.assertTrue(result["blocked"], f"SSH key should be blocked. stdout: {stdout}")
        self.assertIn("BLOCKED", result["reason"])

    def test_blocks_aws_credentials(self):
        exit_code, stdout, stderr = self.run_hook("~/.aws/credentials")
        self.assertEqual(exit_code, 0)
        result = self.parse_hook_response(stdout)
        self.assertTrue(result["blocked"], f"AWS credentials should be blocked. stdout: {stdout}")
        self.assertIn("BLOCKED", result["reason"])

    def test_blocks_env_file(self):
        exit_code, stdout, stderr = self.run_hook(".env")
        self.assertEqual(exit_code, 0)
        result = self.parse_hook_response(stdout)
        self.assertTrue(result["blocked"], f".env should be blocked. stdout: {stdout}")
        self.assertIn("BLOCKED", result["reason"])

    def test_allows_python_file(self):
        exit_code, stdout, stderr = self.run_hook("main.py")
        self.assertEqual(exit_code, 0)
        result = self.parse_hook_response(stdout)
        self.assertFalse(result["blocked"], "Python file should be allowed")

    def test_allows_readme(self):
        exit_code, stdout, stderr = self.run_hook("README.md")
        self.assertEqual(exit_code, 0)
        result = self.parse_hook_response(stdout)
        self.assertFalse(result["blocked"], "README should be allowed")

    def test_allows_package_json(self):
        exit_code, stdout, stderr = self.run_hook("package.json")
        self.assertEqual(exit_code, 0)
        result = self.parse_hook_response(stdout)
        self.assertFalse(result["blocked"], "package.json should be allowed")

    def test_allows_env_example(self):
        exit_code, stdout, stderr = self.run_hook(".env.example")
        self.assertEqual(exit_code, 0)
        result = self.parse_hook_response(stdout)
        self.assertFalse(result["blocked"], ".env.example should be allowed")


class TestPatternCounts(TestCase):
    """Verify pattern counts for documentation."""

    def test_dangerous_pattern_count(self):
        # Should have ~35 dangerous patterns
        self.assertGreater(len(DANGEROUS_READ_PATTERNS), 30)

    def test_sensitive_pattern_count(self):
        # Should have ~15 sensitive patterns
        self.assertGreater(len(SENSITIVE_READ_PATTERNS), 10)

    def test_safe_pattern_count(self):
        # Should have ~25 safe patterns
        self.assertGreater(len(SAFE_READ_PATTERNS), 20)


if __name__ == "__main__":
    unittest_main()
