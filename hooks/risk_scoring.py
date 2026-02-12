#!/usr/bin/env python3
"""
Risk scoring system for command execution safety.

Tracks cumulative risk score per session based on blocked commands.
Each blocked command contributes to a session risk score based on its severity.

Part of Hardstop v1.4.0 - Phase 2.3: Risk Scoring System
"""

from typing import Dict, Tuple

# Severity weights: points added to risk score when command is blocked
SEVERITY_WEIGHTS = {
    "critical": 25,  # Fork bomb, rm -rf /, credential theft
    "high": 15,      # Reverse shell, sudo abuse, network exfiltration
    "medium": 10,    # Config changes, overly permissive permissions
    "low": 5,        # Suspicious but likely benign
    "info": 1,       # Logged but not concerning
}

# Risk thresholds: ranges that define overall session risk level
RISK_THRESHOLDS = {
    "low": (0, 24),           # 0-24: minimal risk
    "moderate": (25, 49),     # 25-49: some concerning patterns
    "high": (50, 74),         # 50-74: multiple dangerous attempts
    "critical": (75, float('inf')),  # 75+: sustained attack pattern
}


def calculate_risk_level(score: int) -> str:
    """
    Calculate risk level from numeric score.

    Args:
        score: Cumulative risk score (sum of severity weights)

    Returns:
        Risk level: "low", "moderate", "high", or "critical"

    Examples:
        >>> calculate_risk_level(10)
        'low'
        >>> calculate_risk_level(30)
        'moderate'
        >>> calculate_risk_level(60)
        'high'
        >>> calculate_risk_level(100)
        'critical'
    """
    for level, (min_score, max_score) in RISK_THRESHOLDS.items():
        if min_score <= score <= max_score:
            return level
    return "unknown"


def get_severity_weight(severity: str) -> int:
    """
    Get numeric weight for a severity level.

    Args:
        severity: Severity level string

    Returns:
        Weight (points to add to risk score)

    Examples:
        >>> get_severity_weight("critical")
        25
        >>> get_severity_weight("high")
        15
        >>> get_severity_weight("invalid")
        0
    """
    return SEVERITY_WEIGHTS.get(severity.lower(), 0)


def get_risk_color(level: str) -> str:
    """
    Get ANSI color code for risk level.

    Args:
        level: Risk level string

    Returns:
        ANSI color code

    Examples:
        >>> get_risk_color("critical")
        '\\033[91m'
        >>> get_risk_color("low")
        '\\033[92m'
    """
    colors = {
        "low": "\033[92m",      # Green
        "moderate": "\033[93m",  # Yellow
        "high": "\033[91m",      # Red
        "critical": "\033[95m",  # Magenta
    }
    return colors.get(level.lower(), "\033[0m")


def format_risk_display(score: int, level: str) -> str:
    """
    Format risk score and level for display.

    Args:
        score: Numeric risk score
        level: Risk level string

    Returns:
        Formatted string with color

    Examples:
        >>> format_risk_display(35, "moderate")
        '\\033[93mMODERATE\\033[0m (35 points)'
    """
    color = get_risk_color(level)
    reset = "\033[0m"
    return f"{color}{level.upper()}{reset} ({score} points)"


def get_risk_description(level: str) -> str:
    """
    Get human-readable description of risk level.

    Args:
        level: Risk level string

    Returns:
        Description of what this risk level means
    """
    descriptions = {
        "low": "Minimal risk detected. Normal usage patterns.",
        "moderate": "Some concerning patterns detected. Review blocked commands.",
        "high": "Multiple dangerous attempts detected. Potential security threat.",
        "critical": "Sustained attack pattern detected. Immediate review recommended.",
    }
    return descriptions.get(level.lower(), "Unknown risk level.")


# Export all public functions
__all__ = [
    'SEVERITY_WEIGHTS',
    'RISK_THRESHOLDS',
    'calculate_risk_level',
    'get_severity_weight',
    'get_risk_color',
    'format_risk_display',
    'get_risk_description',
]
