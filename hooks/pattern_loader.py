#!/usr/bin/env python3
"""
Pattern Loader for Hardstop v1.4.0
Loads security patterns from YAML files with caching support.
"""

import yaml
from pathlib import Path
from typing import Dict, List, Optional


class PatternLoader:
    """Loads and manages security patterns from YAML files."""

    def __init__(self, patterns_dir: Optional[Path] = None):
        """
        Initialize pattern loader.

        Args:
            patterns_dir: Directory containing pattern YAML files.
                         Defaults to ../patterns relative to this file.
        """
        if patterns_dir is None:
            patterns_dir = Path(__file__).parent.parent / "patterns"

        self.patterns_dir = Path(patterns_dir)
        self._cache: Dict[str, List[dict]] = {}

    def load_patterns(self, filename: str) -> List[dict]:
        """
        Load patterns from a YAML file.

        Args:
            filename: Name of the YAML file (e.g., 'dangerous_commands.yaml')

        Returns:
            List of pattern dictionaries, each containing:
                - id: Unique pattern identifier
                - regex: Regular expression pattern
                - message: Human-readable description
                - severity: Severity level (critical, high, medium, low, info)
                - category: Pattern category (credential, network, filesystem, etc.)
        """
        # Check cache first
        if filename in self._cache:
            return self._cache[filename]

        file_path = self.patterns_dir / filename

        # Handle missing files gracefully
        if not file_path.exists():
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            patterns = data.get('patterns', []) if data else []

            # Cache the results
            self._cache[filename] = patterns

            return patterns

        except Exception as e:
            # Log error but don't crash - return empty list
            print(f"Warning: Failed to load {filename}: {e}")
            return []

    def load_dangerous_commands(self) -> List[dict]:
        """Load dangerous command patterns."""
        return self.load_patterns('dangerous_commands.yaml')

    def load_dangerous_reads(self) -> List[dict]:
        """Load dangerous read patterns."""
        return self.load_patterns('dangerous_reads.yaml')

    def load_sensitive_reads(self) -> List[dict]:
        """Load sensitive read patterns."""
        return self.load_patterns('sensitive_reads.yaml')

    def load_safe_commands(self) -> List[dict]:
        """Load safe command patterns (currently empty by design)."""
        return self.load_patterns('safe_commands.yaml')

    def load_safe_reads(self) -> List[dict]:
        """Load safe read patterns (currently empty by design)."""
        return self.load_patterns('safe_reads.yaml')

    def get_all_patterns(self) -> Dict[str, List[dict]]:
        """
        Load all pattern files.

        Returns:
            Dictionary mapping category names to pattern lists:
                - dangerous_commands: 180 patterns
                - dangerous_reads: 71 patterns
                - sensitive_reads: 11 patterns
                - safe_commands: 0 patterns (empty by design)
                - safe_reads: 0 patterns (empty by design)
        """
        return {
            'dangerous_commands': self.load_dangerous_commands(),
            'dangerous_reads': self.load_dangerous_reads(),
            'sensitive_reads': self.load_sensitive_reads(),
            'safe_commands': self.load_safe_commands(),
            'safe_reads': self.load_safe_reads(),
        }

    def get_pattern_count(self) -> Dict[str, int]:
        """
        Get count of patterns in each category.

        Returns:
            Dictionary mapping category names to pattern counts.
        """
        all_patterns = self.get_all_patterns()
        return {category: len(patterns) for category, patterns in all_patterns.items()}

    def get_total_count(self) -> int:
        """
        Get total count of all loaded patterns.

        Returns:
            Total number of patterns across all categories.
        """
        counts = self.get_pattern_count()
        return sum(counts.values())

    def clear_cache(self):
        """Clear the pattern cache. Useful for testing or live reloading."""
        self._cache.clear()


# Singleton instance for convenience
_default_loader: Optional[PatternLoader] = None


def get_loader() -> PatternLoader:
    """Get the default pattern loader instance."""
    global _default_loader
    if _default_loader is None:
        _default_loader = PatternLoader()
    return _default_loader


# Convenience functions for direct access
def load_dangerous_commands() -> List[dict]:
    """Load dangerous command patterns."""
    return get_loader().load_dangerous_commands()


def load_dangerous_reads() -> List[dict]:
    """Load dangerous read patterns."""
    return get_loader().load_dangerous_reads()


def load_sensitive_reads() -> List[dict]:
    """Load sensitive read patterns."""
    return get_loader().load_sensitive_reads()


def load_safe_commands() -> List[dict]:
    """Load safe command patterns."""
    return get_loader().load_safe_commands()


def load_safe_reads() -> List[dict]:
    """Load safe read patterns."""
    return get_loader().load_safe_reads()


def get_pattern_count() -> Dict[str, int]:
    """Get count of patterns in each category."""
    return get_loader().get_pattern_count()


def get_total_count() -> int:
    """Get total count of all loaded patterns."""
    return get_loader().get_total_count()
