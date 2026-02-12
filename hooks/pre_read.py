#!/usr/bin/env python3
"""
Hardstop Plugin — PreToolUse Hook (Read)

Blocks reading of sensitive credential files to prevent secrets exposure.

Exit codes:
  0 = Success (uses JSON output for allow/deny decision)

Blocking uses permissionDecision: "deny" in JSON output instead of exit code 2.
This ensures consistent behavior between CLI and VS Code extension.

Design principle: Fail-closed. If safety check fails, block the read.
"""

import sys
import json
import re
import os
from pathlib import Path
from datetime import datetime
from typing import Tuple, Optional, List, Dict

# Import pattern loader for YAML-based patterns
try:
    from pattern_loader import load_dangerous_reads, load_sensitive_reads
    PATTERN_LOADER_AVAILABLE = True
except ImportError:
    PATTERN_LOADER_AVAILABLE = False

# Import session tracker for risk scoring (v1.4.0+)
try:
    from session_tracker import get_tracker
    SESSION_TRACKER_AVAILABLE = True
except ImportError:
    SESSION_TRACKER_AVAILABLE = False

# === CONFIGURATION ===

STATE_DIR = Path.home() / ".hardstop"
SKIP_FILE = STATE_DIR / "skip_next"
LOG_FILE = STATE_DIR / "audit.log"
DEBUG_FILE = STATE_DIR / "hook_debug.log"

# Fail-closed: if True, errors during safety check block the read
FAIL_CLOSED = True

# === DEBUG LOGGING ===

try:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(DEBUG_FILE, "a") as f:
        f.write(f"[{datetime.now().isoformat()}] Read hook invoked\n")
except:
    pass

# === DANGEROUS READ PATTERNS ===
# These paths contain secrets that should never be read by AI

# Pattern registries: store full pattern metadata for risk scoring
_READ_PATTERN_REGISTRY: Dict[str, Dict] = {}
_SENSITIVE_READ_REGISTRY: Dict[str, Dict] = {}

# Load patterns from YAML files (v1.4.0+) or use fallback
def _load_dangerous_read_patterns() -> List[Tuple[str, str]]:
    """
    Load dangerous read patterns from YAML files.
    Returns list of (regex, pattern_id) tuples.
    Builds _READ_PATTERN_REGISTRY with full metadata.
    Falls back to empty list if pattern loader unavailable.
    """
    global _READ_PATTERN_REGISTRY

    if not PATTERN_LOADER_AVAILABLE:
        print("Warning: pattern_loader not available, using empty dangerous read patterns list", file=sys.stderr)
        return []

    try:
        yaml_patterns = load_dangerous_reads()

        # Build registry with full pattern data
        _READ_PATTERN_REGISTRY.clear()
        for pattern in yaml_patterns:
            pattern_id = pattern.get('id', 'UNKNOWN')
            _READ_PATTERN_REGISTRY[pattern_id] = pattern

        # Return matching list: (regex, pattern_id)
        return [(p['regex'], p.get('id', 'UNKNOWN')) for p in yaml_patterns
                if 'regex' in p]

    except Exception as e:
        print(f"Warning: Failed to load dangerous read patterns: {e}", file=sys.stderr)
        return []


DANGEROUS_READ_PATTERNS = _load_dangerous_read_patterns()


def _load_sensitive_read_patterns() -> List[Tuple[str, str]]:
    """
    Load sensitive read patterns from YAML files.
    Returns list of (regex, pattern_id) tuples.
    Builds _SENSITIVE_READ_REGISTRY with full metadata.
    Falls back to empty list if pattern loader unavailable.
    """
    global _SENSITIVE_READ_REGISTRY

    if not PATTERN_LOADER_AVAILABLE:
        print("Warning: pattern_loader not available, using empty sensitive read patterns list", file=sys.stderr)
        return []

    try:
        yaml_patterns = load_sensitive_reads()

        # Build registry with full pattern data
        _SENSITIVE_READ_REGISTRY.clear()
        for pattern in yaml_patterns:
            pattern_id = pattern.get('id', 'UNKNOWN')
            _SENSITIVE_READ_REGISTRY[pattern_id] = pattern

        # Return matching list: (regex, pattern_id)
        return [(p['regex'], p.get('id', 'UNKNOWN')) for p in yaml_patterns
                if 'regex' in p]

    except Exception as e:
        print(f"Warning: Failed to load sensitive read patterns: {e}", file=sys.stderr)
        return []


SENSITIVE_READ_PATTERNS = _load_sensitive_read_patterns()

# Note: Legacy hardcoded patterns removed in v1.4.0 (now in patterns/sensitive_reads.yaml)

# === SAFE READ PATTERNS ===
# Explicit allowlist for common safe reads

SAFE_READ_PATTERNS = [
    # Documentation
    r"README\.md$",
    r"README\.rst$",
    r"README\.txt$",
    r"README$",
    r"CHANGELOG\.md$",
    r"CHANGELOG$",
    r"HISTORY\.md$",
    r"LICENSE$",
    r"LICENSE\.md$",
    r"LICENSE\.txt$",
    r"CONTRIBUTING\.md$",
    r"CODE_OF_CONDUCT\.md$",
    r"\.md$",
    r"\.rst$",
    r"\.txt$",

    # Source code
    r"\.py$",
    r"\.pyi$",
    r"\.js$",
    r"\.mjs$",
    r"\.cjs$",
    r"\.ts$",
    r"\.tsx$",
    r"\.jsx$",
    r"\.go$",
    r"\.rs$",
    r"\.java$",
    r"\.kt$",
    r"\.scala$",
    r"\.c$",
    r"\.cpp$",
    r"\.cc$",
    r"\.h$",
    r"\.hpp$",
    r"\.cs$",
    r"\.rb$",
    r"\.php$",
    r"\.swift$",
    r"\.m$",
    r"\.mm$",
    r"\.lua$",
    r"\.pl$",
    r"\.sh$",
    r"\.bash$",
    r"\.zsh$",
    r"\.fish$",
    r"\.ps1$",
    r"\.bat$",
    r"\.cmd$",
    r"\.sql$",
    r"\.graphql$",
    r"\.gql$",

    # Config (Non-Sensitive)
    r"package\.json$",
    r"package-lock\.json$",
    r"yarn\.lock$",
    r"pnpm-lock\.yaml$",
    r"tsconfig\.json$",
    r"jsconfig\.json$",
    r"pyproject\.toml$",
    r"setup\.py$",
    r"setup\.cfg$",
    r"Cargo\.toml$",
    r"Cargo\.lock$",
    r"go\.mod$",
    r"go\.sum$",
    r"requirements\.txt$",
    r"Pipfile$",
    r"Pipfile\.lock$",
    r"Gemfile$",
    r"Gemfile\.lock$",
    r"composer\.json$",
    r"composer\.lock$",
    r"Makefile$",
    r"CMakeLists\.txt$",
    r"\.gitignore$",
    r"\.dockerignore$",
    r"Dockerfile$",
    r"docker-compose\.yml$",
    r"docker-compose\.yaml$",

    # Example/Template Files (safe versions of .env)
    r"\.env\.example$",
    r"\.env\.template$",
    r"\.env\.sample$",
    r"\.env\.dist$",
    r"example\.",
    r"sample\.",
    r"template\.",

    # Web assets
    r"\.html$",
    r"\.css$",
    r"\.scss$",
    r"\.sass$",
    r"\.less$",
    r"\.svg$",

    # Data formats (generic - but config.json handled by SENSITIVE)
    r"\.xml$",
]


# === LOGGING ===

def log_decision(file_path: str, verdict: str, reason: str, layer: str, pattern_data: Optional[Dict] = None, risk_score: int = 0, risk_level: str = "unknown"):
    """Log security decision to audit file."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now().isoformat(),
            "tool": "Read",
            "file_path": file_path[:500],  # Truncate very long paths
            "verdict": verdict,
            "reason": reason,
            "layer": layer
        }

        # Add risk scoring data if available (v1.4.0+)
        if pattern_data:
            entry["pattern_id"] = pattern_data.get('id')
            entry["severity"] = pattern_data.get('severity')
            entry["category"] = pattern_data.get('category')
            entry["risk_score"] = risk_score
            entry["risk_level"] = risk_level

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except (IOError, OSError) as e:
        print(f"Warning: Could not write to audit log: {e}", file=sys.stderr)


# === PATH NORMALIZATION ===

def normalize_path(file_path: str, cwd: str) -> str:
    """
    Expand ~ and environment variables, resolve relative paths.
    Normalize to forward slashes for consistent pattern matching.
    """
    # Expand ~ to home directory
    expanded = os.path.expanduser(file_path)

    # Expand environment variables
    expanded = os.path.expandvars(expanded)

    # Resolve relative paths
    if not os.path.isabs(expanded):
        expanded = os.path.join(cwd, expanded)

    # Normalize path (resolve .., etc.)
    normalized = os.path.normpath(expanded)

    # Convert to forward slashes for consistent pattern matching
    normalized = normalized.replace("\\", "/")

    return normalized


# === PATTERN CHECKING ===

def check_dangerous_patterns(file_path: str) -> Tuple[bool, Optional[Dict]]:
    """
    Check if file_path matches any dangerous pattern.

    Returns:
        (matched, pattern_dict) where pattern_dict contains full metadata
    """
    for regex, pattern_id in DANGEROUS_READ_PATTERNS:
        if re.search(regex, file_path, re.IGNORECASE):
            # Retrieve full pattern metadata from registry
            pattern_data = _READ_PATTERN_REGISTRY.get(pattern_id)
            if pattern_data:
                return True, pattern_data
            else:
                # Fallback if registry lookup fails
                return True, {
                    'id': pattern_id,
                    'message': 'Dangerous read pattern detected',
                    'severity': 'medium',
                    'category': 'unknown',
                }
    return False, None


def check_sensitive_patterns(file_path: str) -> Tuple[bool, Optional[Dict]]:
    """
    Check if file_path matches any sensitive pattern.

    Returns:
        (matched, pattern_dict) where pattern_dict contains full metadata
    """
    for regex, pattern_id in SENSITIVE_READ_PATTERNS:
        if re.search(regex, file_path, re.IGNORECASE):
            # Retrieve full pattern metadata from registry
            pattern_data = _SENSITIVE_READ_REGISTRY.get(pattern_id)
            if pattern_data:
                return True, pattern_data
            else:
                # Fallback if registry lookup fails
                return True, {
                    'id': pattern_id,
                    'message': 'Sensitive read pattern detected',
                    'severity': 'low',
                    'category': 'unknown',
                }
    return False, None


def check_safe_patterns(file_path: str) -> bool:
    """Check if file_path matches any safe pattern."""
    for pattern in SAFE_READ_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            return True
    return False


# === SKIP MECHANISM ===

def get_skip_count() -> int:
    """Get current skip count (0 if no skips remaining)."""
    if not SKIP_FILE.exists():
        return 0
    try:
        content = SKIP_FILE.read_text().strip()
        return int(content)
    except (ValueError, IOError, OSError):
        return 1  # Old format or error = treat as 1


def decrement_skip() -> Tuple[bool, int]:
    """
    Decrement the skip counter. Returns (was_skipped, remaining_count).
    Supports both old format (file exists = 1 skip) and new format (file contains count).
    """
    if not SKIP_FILE.exists():
        return False, 0

    try:
        content = SKIP_FILE.read_text().strip()
        try:
            count = int(content)
        except ValueError:
            count = 1  # Old format or invalid = treat as 1

        if count <= 1:
            # Last skip, remove the file
            try:
                SKIP_FILE.unlink()
            except (IOError, OSError):
                pass
            return True, 0
        else:
            # Decrement and save
            SKIP_FILE.write_text(str(count - 1))
            return True, count - 1
    except (IOError, OSError):
        return False, 0


def is_skip_enabled() -> bool:
    """Check if skip_next flag is set (legacy function, kept for compatibility)."""
    return SKIP_FILE.exists()


# === OUTPUT FUNCTIONS ===

def block(reason: str, file_path: str, pattern: str = "", pattern_data: Optional[Dict] = None, risk_score: int = 0, risk_level: str = "unknown", blocked_count: int = 0):
    """
    Block a read using Claude Code's structured JSON output.

    Uses exit code 0 with permissionDecision: "deny" instead of exit code 2.
    This ensures consistent behavior between CLI and VS Code extension.
    """
    # Build the block reason message
    msg = f"🛑 BLOCKED: {reason}\nFile: {file_path}"
    if pattern:
        msg += f"\nPattern: {pattern}"
    msg += "\nUse '/hs skip' to bypass."

    # Output structured JSON for Claude Code to parse
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": msg
        }
    }

    # Add risk scoring data if available (v1.4.0+)
    if risk_score > 0:
        output["risk_score"] = risk_score
        output["risk_level"] = risk_level
        output["session_stats"] = {
            "total_blocked": blocked_count,
            "risk_score": risk_score,
            "risk_level": risk_level,
        }

    print(json.dumps(output))
    sys.exit(0)


def warn(reason: str, file_path: str):
    """Output warning message (currently just logs, doesn't block)."""
    print(f"\n⚠️  WARNING: {reason}", file=sys.stderr)
    print(f"File: {file_path}", file=sys.stderr)
    print("Proceeding with read...\n", file=sys.stderr)
    # In v1.3, warnings don't block - they just log


# === MAIN ===

def block_error(reason: str):
    """Block due to an error (fail-closed behavior) using JSON output."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"🛑 BLOCKED (fail-closed): {reason}\nUse '/hs skip' to bypass."
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def main():
    """Main hook logic."""
    # Read hook input from stdin
    try:
        input_text = sys.stdin.read()
        input_data = json.loads(input_text)
    except json.JSONDecodeError as e:
        if FAIL_CLOSED:
            block_error(f"Failed to parse hook input: {e}")
        sys.exit(0)
    except Exception as e:
        if FAIL_CLOSED:
            block_error(f"Failed to read hook input: {e}")
        sys.exit(0)

    # Extract file path from tool input
    tool_input = input_data.get("tool_input", {})
    file_path = tool_input.get("file_path", "")
    cwd = input_data.get("cwd", os.getcwd())

    # No path = allow (shouldn't happen, but defensive)
    if not file_path:
        sys.exit(0)

    # Normalize path for consistent matching
    normalized_path = normalize_path(file_path, cwd)

    # Debug log
    try:
        with open(DEBUG_FILE, "a") as f:
            f.write(f"  Original: {file_path}\n")
            f.write(f"  Normalized: {normalized_path}\n")
    except:
        pass

    # Check skip flag first
    if SKIP_FILE.exists():
        was_skipped, remaining = decrement_skip()
        if was_skipped:
            log_decision(normalized_path, "ALLOW", f"Skip (remaining: {remaining})", "skip")
            if remaining > 0:
                print(f"⏭️  Read check skipped ({remaining} skip{'s' if remaining > 1 else ''} remaining)", file=sys.stderr)
            else:
                print("⏭️  Read check skipped (last skip, protection resumed)", file=sys.stderr)
            sys.exit(0)

    # Check SAFE patterns first (fast path for common files)
    if check_safe_patterns(normalized_path):
        # Don't log safe reads to reduce noise
        sys.exit(0)

    # Check DANGEROUS patterns
    is_dangerous, pattern_data = check_dangerous_patterns(normalized_path)
    if is_dangerous:
        # Record to session tracker for risk scoring (v1.4.0+)
        risk_score = 0
        risk_level = "unknown"
        blocked_count = 0

        if SESSION_TRACKER_AVAILABLE and pattern_data:
            try:
                tracker = get_tracker()
                tracker.record_block(normalized_path, pattern_data)

                # Get updated risk metrics
                risk_score = tracker.get_risk_score()
                risk_level = tracker.get_risk_level()
                blocked_count = tracker.get_blocked_count()

            except Exception as e:
                # Don't fail the hook if tracker has issues
                print(f"Warning: Session tracker error: {e}", file=sys.stderr)

        # Extract message from pattern data
        reason = pattern_data.get('message', 'Dangerous read pattern detected') if pattern_data else 'Dangerous read pattern detected'
        log_decision(normalized_path, "BLOCK", reason, "pattern", pattern_data, risk_score, risk_level)
        block(reason, file_path, reason, pattern_data, risk_score, risk_level, blocked_count)

    # Check SENSITIVE patterns (warn only)
    is_sensitive, pattern_data = check_sensitive_patterns(normalized_path)
    if is_sensitive:
        # Record to session tracker with downgraded severity (v1.4.0+)
        # Warnings get lower risk weight than blocks
        risk_score = 0
        risk_level = "unknown"

        if SESSION_TRACKER_AVAILABLE and pattern_data:
            try:
                # Downgrade severity for sensitive reads (warning vs. block)
                original_severity = pattern_data.get('severity', 'medium')
                if original_severity == 'critical':
                    adjusted_severity = 'high'
                elif original_severity == 'high':
                    adjusted_severity = 'medium'
                else:
                    adjusted_severity = original_severity

                # Create adjusted pattern data for tracking
                tracking_data = pattern_data.copy()
                tracking_data['severity'] = adjusted_severity
                tracking_data['original_severity'] = original_severity

                tracker = get_tracker()
                tracker.record_block(normalized_path, tracking_data)

                # Get updated risk metrics
                risk_score = tracker.get_risk_score()
                risk_level = tracker.get_risk_level()

            except Exception as e:
                # Don't fail the hook if tracker has issues
                print(f"Warning: Session tracker error: {e}", file=sys.stderr)

        # Extract message from pattern data
        reason = pattern_data.get('message', 'Sensitive read pattern detected') if pattern_data else 'Sensitive read pattern detected'
        log_decision(normalized_path, "WARN", reason, "pattern", pattern_data, risk_score, risk_level)
        warn(reason, file_path)
        sys.exit(0)  # Allow after warning

    # Default: allow reads not matching any pattern
    sys.exit(0)


if __name__ == "__main__":
    main()
