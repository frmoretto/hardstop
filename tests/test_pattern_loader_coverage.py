#!/usr/bin/env python3
"""
Unit tests for uncovered code paths in pattern_loader.py.

Targets: cache hit, missing file, exception handling,
convenience functions, clear_cache, get_all_patterns,
get_pattern_count, get_total_count.
"""

import sys
import tempfile
import shutil
from pathlib import Path
from unittest import TestCase, main as unittest_main
from unittest.mock import patch

# Add hooks to path
sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

import pattern_loader
from pattern_loader import PatternLoader


class TestPatternLoaderCache(TestCase):
    """Test caching behavior."""

    def test_cache_hit(self):
        loader = PatternLoader()
        # First load populates cache
        result1 = loader.load_dangerous_commands()
        # Second load should hit cache
        result2 = loader.load_dangerous_commands()
        self.assertEqual(result1, result2)
        self.assertIn("dangerous_commands.yaml", loader._cache)

    def test_clear_cache(self):
        loader = PatternLoader()
        loader.load_dangerous_commands()
        self.assertTrue(len(loader._cache) > 0)
        loader.clear_cache()
        self.assertEqual(len(loader._cache), 0)


class TestPatternLoaderMissingFile(TestCase):
    """Test behavior with missing pattern files."""

    def test_missing_file_returns_empty(self):
        loader = PatternLoader(patterns_dir=Path("/nonexistent/dir"))
        result = loader.load_patterns("missing.yaml")
        self.assertEqual(result, [])

    def test_missing_dir_returns_empty(self):
        loader = PatternLoader(patterns_dir=Path("/nonexistent"))
        result = loader.load_dangerous_commands()
        self.assertEqual(result, [])


class TestPatternLoaderExceptionHandling(TestCase):
    """Test error handling during YAML loading."""

    def test_invalid_yaml_returns_empty(self):
        temp_dir = tempfile.mkdtemp()
        try:
            # Write invalid YAML
            bad_file = Path(temp_dir) / "bad.yaml"
            bad_file.write_text(": : : invalid yaml {{{")
            loader = PatternLoader(patterns_dir=Path(temp_dir))
            result = loader.load_patterns("bad.yaml")
            # yaml.safe_load might parse this or raise - either way shouldn't crash
            self.assertIsInstance(result, list)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_yaml_without_patterns_key(self):
        temp_dir = tempfile.mkdtemp()
        try:
            f = Path(temp_dir) / "no_patterns.yaml"
            f.write_text("key: value\n")
            loader = PatternLoader(patterns_dir=Path(temp_dir))
            result = loader.load_patterns("no_patterns.yaml")
            self.assertEqual(result, [])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_empty_yaml_file(self):
        temp_dir = tempfile.mkdtemp()
        try:
            f = Path(temp_dir) / "empty.yaml"
            f.write_text("")
            loader = PatternLoader(patterns_dir=Path(temp_dir))
            result = loader.load_patterns("empty.yaml")
            self.assertEqual(result, [])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestPatternLoaderConvenienceFunctions(TestCase):
    """Test module-level convenience functions."""

    def test_load_safe_commands(self):
        result = pattern_loader.load_safe_commands()
        self.assertIsInstance(result, list)

    def test_load_safe_reads(self):
        result = pattern_loader.load_safe_reads()
        self.assertIsInstance(result, list)

    def test_get_pattern_count(self):
        counts = pattern_loader.get_pattern_count()
        self.assertIsInstance(counts, dict)
        self.assertIn("dangerous_commands", counts)
        self.assertIn("dangerous_reads", counts)
        self.assertIn("sensitive_reads", counts)

    def test_get_total_count(self):
        total = pattern_loader.get_total_count()
        self.assertIsInstance(total, int)
        self.assertGreater(total, 0)


class TestPatternLoaderMethods(TestCase):
    """Test PatternLoader instance methods."""

    def test_load_safe_commands_method(self):
        loader = PatternLoader()
        result = loader.load_safe_commands()
        self.assertIsInstance(result, list)

    def test_load_safe_reads_method(self):
        loader = PatternLoader()
        result = loader.load_safe_reads()
        self.assertIsInstance(result, list)

    def test_get_all_patterns(self):
        loader = PatternLoader()
        all_patterns = loader.get_all_patterns()
        self.assertIn("dangerous_commands", all_patterns)
        self.assertIn("dangerous_reads", all_patterns)
        self.assertIn("sensitive_reads", all_patterns)
        self.assertIn("safe_commands", all_patterns)
        self.assertIn("safe_reads", all_patterns)

    def test_get_pattern_count_method(self):
        loader = PatternLoader()
        counts = loader.get_pattern_count()
        self.assertIn("dangerous_commands", counts)
        for key, value in counts.items():
            self.assertIsInstance(value, int)

    def test_get_total_count_method(self):
        loader = PatternLoader()
        total = loader.get_total_count()
        self.assertGreater(total, 0)

    def test_custom_patterns_dir(self):
        loader = PatternLoader(patterns_dir=Path(__file__).parent.parent / "patterns")
        result = loader.load_dangerous_commands()
        self.assertGreater(len(result), 0)


class TestGetLoader(TestCase):
    """Test the singleton get_loader() function."""

    def test_returns_same_instance(self):
        # Reset singleton
        pattern_loader._default_loader = None
        loader1 = pattern_loader.get_loader()
        loader2 = pattern_loader.get_loader()
        self.assertIs(loader1, loader2)


if __name__ == "__main__":
    unittest_main()
