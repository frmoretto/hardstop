#!/usr/bin/env python3
"""
Test suite for risk scoring system.
"""

import pytest
import sys
from pathlib import Path

# Add hooks directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

from risk_scoring import (
    SEVERITY_WEIGHTS,
    RISK_THRESHOLDS,
    calculate_risk_level,
    get_severity_weight,
    get_risk_color,
    format_risk_display,
    get_risk_description,
)


class TestSeverityWeights:
    """Test severity weight definitions."""

    def test_all_severities_defined(self):
        """Verify all expected severity levels have weights."""
        expected_severities = ["critical", "high", "medium", "low", "info"]
        for severity in expected_severities:
            assert severity in SEVERITY_WEIGHTS, f"Missing weight for {severity}"

    def test_weights_are_positive(self):
        """Verify all weights are positive integers."""
        for severity, weight in SEVERITY_WEIGHTS.items():
            assert isinstance(weight, int), f"{severity} weight is not an integer"
            assert weight > 0, f"{severity} weight is not positive"

    def test_weights_ordered_correctly(self):
        """Verify weights decrease from critical to info."""
        assert SEVERITY_WEIGHTS["critical"] > SEVERITY_WEIGHTS["high"]
        assert SEVERITY_WEIGHTS["high"] > SEVERITY_WEIGHTS["medium"]
        assert SEVERITY_WEIGHTS["medium"] > SEVERITY_WEIGHTS["low"]
        assert SEVERITY_WEIGHTS["low"] > SEVERITY_WEIGHTS["info"]


class TestRiskThresholds:
    """Test risk threshold definitions."""

    def test_all_levels_defined(self):
        """Verify all expected risk levels have thresholds."""
        expected_levels = ["low", "moderate", "high", "critical"]
        for level in expected_levels:
            assert level in RISK_THRESHOLDS, f"Missing threshold for {level}"

    def test_thresholds_are_contiguous(self):
        """Verify thresholds cover all scores without gaps."""
        # Low: 0-24
        assert RISK_THRESHOLDS["low"] == (0, 24)
        # Moderate: 25-49
        assert RISK_THRESHOLDS["moderate"] == (25, 49)
        # High: 50-74
        assert RISK_THRESHOLDS["high"] == (50, 74)
        # Critical: 75+
        assert RISK_THRESHOLDS["critical"][0] == 75

    def test_no_overlap(self):
        """Verify thresholds don't overlap."""
        levels = list(RISK_THRESHOLDS.items())
        for i in range(len(levels) - 1):
            current_max = levels[i][1][1]
            next_min = levels[i + 1][1][0]
            # If not infinity, verify next starts after current ends
            if current_max != float('inf'):
                assert next_min == current_max + 1, \
                    f"Gap or overlap between {levels[i][0]} and {levels[i+1][0]}"


class TestCalculateRiskLevel:
    """Test risk level calculation."""

    def test_low_risk(self):
        """Test scores in low risk range."""
        assert calculate_risk_level(0) == "low"
        assert calculate_risk_level(10) == "low"
        assert calculate_risk_level(24) == "low"

    def test_moderate_risk(self):
        """Test scores in moderate risk range."""
        assert calculate_risk_level(25) == "moderate"
        assert calculate_risk_level(35) == "moderate"
        assert calculate_risk_level(49) == "moderate"

    def test_high_risk(self):
        """Test scores in high risk range."""
        assert calculate_risk_level(50) == "high"
        assert calculate_risk_level(60) == "high"
        assert calculate_risk_level(74) == "high"

    def test_critical_risk(self):
        """Test scores in critical risk range."""
        assert calculate_risk_level(75) == "critical"
        assert calculate_risk_level(100) == "critical"
        assert calculate_risk_level(1000) == "critical"

    def test_boundary_values(self):
        """Test boundary values between risk levels."""
        assert calculate_risk_level(24) == "low"
        assert calculate_risk_level(25) == "moderate"
        assert calculate_risk_level(49) == "moderate"
        assert calculate_risk_level(50) == "high"
        assert calculate_risk_level(74) == "high"
        assert calculate_risk_level(75) == "critical"


class TestGetSeverityWeight:
    """Test severity weight retrieval."""

    def test_valid_severities(self):
        """Test getting weights for valid severities."""
        assert get_severity_weight("critical") == 25
        assert get_severity_weight("high") == 15
        assert get_severity_weight("medium") == 10
        assert get_severity_weight("low") == 5
        assert get_severity_weight("info") == 1

    def test_case_insensitive(self):
        """Test that severity lookup is case-insensitive."""
        assert get_severity_weight("CRITICAL") == 25
        assert get_severity_weight("High") == 15
        assert get_severity_weight("MeDiUm") == 10

    def test_invalid_severity(self):
        """Test that invalid severity returns 0."""
        assert get_severity_weight("invalid") == 0
        assert get_severity_weight("") == 0
        assert get_severity_weight("unknown") == 0


class TestGetRiskColor:
    """Test risk level color codes."""

    def test_all_levels_have_colors(self):
        """Test that all risk levels have color codes."""
        levels = ["low", "moderate", "high", "critical"]
        for level in levels:
            color = get_risk_color(level)
            assert color.startswith("\033["), f"Invalid color code for {level}"

    def test_different_colors(self):
        """Test that each level has a different color."""
        colors = [
            get_risk_color("low"),
            get_risk_color("moderate"),
            get_risk_color("high"),
            get_risk_color("critical"),
        ]
        # All colors should be unique
        assert len(colors) == len(set(colors)), "Risk levels have duplicate colors"


class TestFormatRiskDisplay:
    """Test risk display formatting."""

    def test_format_includes_score(self):
        """Test that formatted string includes score."""
        result = format_risk_display(35, "moderate")
        assert "35" in result, "Score not in formatted output"

    def test_format_includes_level(self):
        """Test that formatted string includes level."""
        result = format_risk_display(35, "moderate")
        assert "MODERATE" in result.upper(), "Level not in formatted output"

    def test_format_includes_color(self):
        """Test that formatted string includes ANSI color codes."""
        result = format_risk_display(35, "moderate")
        assert "\033[" in result, "No ANSI color codes in output"


class TestGetRiskDescription:
    """Test risk level descriptions."""

    def test_all_levels_have_descriptions(self):
        """Test that all risk levels have descriptions."""
        levels = ["low", "moderate", "high", "critical"]
        for level in levels:
            desc = get_risk_description(level)
            assert desc, f"No description for {level}"
            assert len(desc) > 10, f"Description for {level} is too short"

    def test_descriptions_are_different(self):
        """Test that each level has a unique description."""
        descriptions = [
            get_risk_description("low"),
            get_risk_description("moderate"),
            get_risk_description("high"),
            get_risk_description("critical"),
        ]
        assert len(descriptions) == len(set(descriptions)), \
            "Risk levels have duplicate descriptions"


class TestRiskScoreCalculations:
    """Test practical risk score calculations."""

    def test_single_critical_command(self):
        """Test that a single critical command gives low risk."""
        score = get_severity_weight("critical")
        level = calculate_risk_level(score)
        # 25 points = moderate
        assert level == "moderate"

    def test_two_critical_commands(self):
        """Test that two critical commands give moderate/high risk."""
        score = get_severity_weight("critical") * 2
        level = calculate_risk_level(score)
        # 50 points = high
        assert level == "high"

    def test_three_critical_commands(self):
        """Test that three critical commands give critical risk."""
        score = get_severity_weight("critical") * 3
        level = calculate_risk_level(score)
        # 75 points = critical
        assert level == "critical"

    def test_mixed_severities(self):
        """Test risk score with mixed severity commands."""
        score = (
            get_severity_weight("critical") +  # 25
            get_severity_weight("high") +      # 15
            get_severity_weight("medium")      # 10
        )  # Total: 50
        level = calculate_risk_level(score)
        assert level == "high"

    def test_many_low_commands(self):
        """Test that many low severity commands accumulate risk."""
        score = get_severity_weight("low") * 10  # 50 points
        level = calculate_risk_level(score)
        assert level == "high"
