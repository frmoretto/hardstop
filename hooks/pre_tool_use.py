#!/usr/bin/env python3
"""
Hardstop Plugin — PreToolUse Hook (Bash)

Two-layer protection:
  Layer 1: Pattern matching (instant)
  Layer 2: Claude CLI analysis (within subscription)

Exit codes:
  0 = Success (uses JSON output for allow/deny decision)

Blocking uses permissionDecision: "deny" in JSON output instead of exit code 2.
This ensures consistent behavior between CLI and VS Code extension.

Design principle: Fail-closed. If safety check fails, block the command.
"""

import sys
import json
import re
import subprocess
import os
import shlex
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Tuple, Optional, List, Dict

# Import pattern loader for YAML-based patterns
try:
    from pattern_loader import load_dangerous_commands
    PATTERN_LOADER_AVAILABLE = True
except ImportError:
    PATTERN_LOADER_AVAILABLE = False

# Import session tracker for risk scoring (v1.4.0+)
try:
    from session_tracker import get_tracker
    SESSION_TRACKER_AVAILABLE = True
except ImportError:
    SESSION_TRACKER_AVAILABLE = False

# DEBUG: Write to file to confirm hook is being invoked
DEBUG_FILE = Path.home() / ".hardstop" / "hook_debug.log"
try:
    DEBUG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(DEBUG_FILE, "a") as f:
        f.write(f"[{datetime.now().isoformat()}] Hook invoked\n")
except:
    pass

# === CONFIGURATION ===

STATE_DIR = Path.home() / ".hardstop"
STATE_FILE = STATE_DIR / "state.json"
SKIP_FILE = STATE_DIR / "skip_next"
LOG_FILE = STATE_DIR / "audit.log"

# Fail-closed: if True, errors during safety check block the command
FAIL_CLOSED = True

# === PATTERNS ===

# Pattern registry: stores full pattern metadata for risk scoring
_PATTERN_REGISTRY: Dict[str, Dict] = {}

# Load patterns from YAML files (v1.4.0+) or use fallback
def _load_dangerous_patterns() -> List[Tuple[str, str]]:
    """
    Load dangerous command patterns from YAML files.
    Returns list of (regex, pattern_id) tuples.
    Builds _PATTERN_REGISTRY with full metadata.
    Falls back to empty list if pattern loader unavailable.
    """
    global _PATTERN_REGISTRY

    if not PATTERN_LOADER_AVAILABLE:
        print("Warning: pattern_loader not available, using empty dangerous patterns list", file=sys.stderr)
        return []

    try:
        yaml_patterns = load_dangerous_commands()

        # Build registry with full pattern data
        _PATTERN_REGISTRY.clear()
        for pattern in yaml_patterns:
            pattern_id = pattern.get('id', 'UNKNOWN')
            _PATTERN_REGISTRY[pattern_id] = pattern

        # Return matching list: (regex, pattern_id)
        # Only include patterns that have both regex and id
        return [(p['regex'], p.get('id', 'UNKNOWN')) for p in yaml_patterns
                if 'regex' in p]

    except Exception as e:
        print(f"Warning: Failed to load dangerous patterns: {e}", file=sys.stderr)
        return []


# Load patterns at module import time
DANGEROUS_PATTERNS = _load_dangerous_patterns()

# Note: Legacy hardcoded patterns removed in v1.4.0 (now in patterns/dangerous_commands.yaml)

SAFE_PATTERNS = [
    # Hardstop's own operations (must be able to manage itself)
    r"^python\s+.*[/\\]\.claude[/\\]plugins[/\\]hs[/\\].*\.py(?:\s+.*)?$",
    r"^python\s+.*\.hardstop.*$",
    r"^cat\s+.*\.hardstop[/\\].*$",
    r"^cat\s+.*\.claude[/\\]plugins[/\\]hs[/\\].*$",
    r"^rm\s+(-f\s+)?.*\.hardstop[/\\](skip_next|hook_debug\.log)$",
    r"^grep\s+.*\.claude[/\\]plugins[/\\]hs[/\\].*$",

    # Read-only operations
    r"^ls(?:\s+.*)?$",
    # cd with path - blocks command substitution $() and backticks
    # Allows: cd, cd /path, cd "path", cd 'path', cd ~/dir, cd ..
    # Blocks: cd $(cmd), cd `cmd`, cd ${var}$(cmd)
    r"^cd(?:\s+(?:\"[^`$()]*\"|'[^']*'|[^\s`$()]+))?$",
    # cat: allow reading files, but NOT credential paths (those are caught by DANGEROUS first)
    r"^cat\s+(?!.*(\.ssh/id_|\.aws/credentials|\.kube/config|\.docker/config\.json|\.npmrc|\.netrc|\.gnupg/|\.git-credentials|/etc/shadow|\.env$|\.env\s)).+$",
    r"^head\s+.+$",
    r"^tail\s+.+$",
    r"^less\s+.+$",
    r"^more\s+.+$",
    r"^pwd\s*$",
    r"^which\s+.+$",
    r"^type\s+.+$",
    r"^file\s+.+$",
    r"^wc\s+.+$",
    r"^grep\s+.+$",
    r"^find\s+.*\s-name\s+.*$",  # find with -name (read-only)
    r"^echo(?:\s+.*)?$",
    r"^date\s*$",
    r"^whoami\s*$",
    r"^hostname\s*$",
    r"^uname(?:\s+.*)?$",
    r"^env\s*$",
    r"^printenv(?:\s+.*)?$",
    
    # Git read operations
    r"^git\s+(status|log|diff|show|remote|describe|shortlog|whatchanged|rev-parse|rev-list|cat-file|ls-tree)(?:\s+.*)?$",
    r"^git\s+ls-[^\s]+(?:\s+.*)?$",

    # Git standard workflow (recoverable via reflog)
    # Excludes: reset (--hard loses uncommitted work), clean (deletes untracked), rebase --exec (runs shell)
    r"^git\s+(add|commit|push|pull|fetch|clone|stash|checkout|switch|restore|merge|cherry-pick|branch|tag|init|config|am|apply|bisect|blame|bundle|format-patch|gc|mv|notes|reflog|revert|rm|submodule|worktree)(?:[\s\S]+)?$",
    r"^git\s+rebase(?!\s+.*--exec)(?:[\s\S]+)?$",  # rebase allowed, but not with --exec
    
    # Regeneratable cleanup
    r"^rm\s+(-[^\s]*\s+)*node_modules/?\s*$",
    r"^rm\s+(-[^\s]*\s+)*__pycache__/?\s*$",
    r"^rm\s+(-[^\s]*\s+)*\.venv/?\s*$",
    r"^rm\s+(-[^\s]*\s+)*venv/?\s*$",
    r"^rm\s+(-[^\s]*\s+)*\.pytest_cache/?\s*$",
    r"^rm\s+(-[^\s]*\s+)*dist/?\s*$",
    r"^rm\s+(-[^\s]*\s+)*build/?\s*$",
    r"^rm\s+(-[^\s]*\s+)*\.next/?\s*$",
    r"^rm\s+(-[^\s]*\s+)*\.nuxt/?\s*$",
    r"^rm\s+(-[^\s]*\s+)*coverage/?\s*$",
    r"^rm\s+(-[^\s]*\s+)*(/tmp/|\$TMPDIR)\s*$",
    
    # Package managers (read/lock operations)
    r"^npm\s+(list|ls|outdated|audit|view)(?:\s+.*)?$",
    r"^pip\s+(list|show|freeze)(?:\s+.*)?$",
    r"^yarn\s+(list|outdated|why)(?:\s+.*)?$",

    # ============================================================
    # WINDOWS-SPECIFIC SAFE PATTERNS
    # ============================================================

    # Windows read-only operations
    r"^dir(?:\s+.*)?$",
    r"^type\s+.+$",
    r"^more\s+.+$",
    r"^where\s+.+$",
    r"^hostname\s*$",
    r"^whoami\s*$",
    r"^systeminfo\s*$",
    r"^ver\s*$",
    r"^set\s*$",  # Show environment variables

    # PowerShell read-only
    r"^Get-Content\s+.+$",
    r"^Get-ChildItem(?:\s+.*)?$",
    r"^Get-Location\s*$",
    r"^Get-Item\s+.+$",
    r"^Get-Process\s*$",
    r"^Get-Service\s*$",
    r"^\$PWD\s*$",

    # Windows cleanup (regeneratable)
    r"^rd\s+(/s|/q|\s)+\s*node_modules\s*$",
    r"^rd\s+(/s|/q|\s)+\s*__pycache__\s*$",
    r"^rd\s+(/s|/q|\s)+\s*\.venv\s*$",
    r"^rd\s+(/s|/q|\s)+\s*dist\s*$",
    r"^rd\s+(/s|/q|\s)+\s*build\s*$",
    r"^rmdir\s+(/s|/q|\s)+\s*node_modules\s*$",

    # ============================================================
    # MACOS-SPECIFIC SAFE PATTERNS (v1.3.6)
    # ============================================================

    # macOS read-only operations
    r"^diskutil\s+list\s*$",
    r"^diskutil\s+info\s+.+$",
    r"^system_profiler\s+.+$",
    r"^sw_vers\s*$",
    r"^defaults\s+read\s+.+$",
    r"^security\s+find-certificate\s+.+$",
    r"^tmutil\s+listbackups\s*$",
    r"^tmutil\s+status\s*$",
    r"^launchctl\s+list\s*$",
    r"^dscl\s+\.\s+-read\s+.+$",
    r"^spctl\s+--status\s*$",
]

# === LLM PROMPT ===

LLM_PROMPT = '''You are a security analyzer for a development environment. Assess command safety.

RESPOND WITH JSON ONLY — no markdown, no prose:
{{"verdict": "ALLOW" | "BLOCK", "reason": "one line explanation"}}

BLOCK if the command:
- Deletes user data (not regeneratable caches like node_modules, dist, build)
- Reads/exfiltrates credentials (.ssh keys, .aws, .env, API keys)
- Sends sensitive data externally (curl -d with credentials, scp ~/.ssh)
- Overwrites disk devices (dd of=/dev/*, format C:)
- Disables security (firewall off, antivirus disabled)
- Executes encoded payloads (base64 -d | sh, powershell -e)
- Creates persistence (cron jobs, registry Run keys, startup scripts)

ALLOW if the command:
- Git operations (push, pull, commit, fetch, clone, branch, tag, merge, rebase)
- Package managers (npm, pip, cargo, yarn, go, gem, composer)
- Build/test tools (make, pytest, jest, cargo build, tsc, webpack)
- Directory navigation (cd to any path)
- File operations in project directories
- Docker/container operations
- Read-only system queries (ls, cat, grep, find, ps, env)

IMPORTANT: This is a development assistant. Standard development workflows should be
ALLOWED unless they match a specific BLOCK criterion. Prefer ALLOW for recognized dev tools.

Command: {command}
Working directory: {cwd}

JSON response:'''


# === LOGGING ===

def log_decision(command: str, verdict: str, reason: str, layer: str, cwd: str, pattern_data: Optional[Dict] = None, risk_score: int = 0, risk_level: str = "unknown"):
    """Log security decision to audit file."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now().isoformat(),
            "tool": "Bash",
            "command": command[:500],  # Truncate very long commands
            "cwd": cwd,
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
        # Logging failure shouldn't block operation
        print(f"Warning: Could not write to audit log: {e}", file=sys.stderr)


# === STATE MANAGEMENT ===

def load_state() -> dict:
    """Load plugin state. Returns default if file missing or corrupted."""
    default_state = {"enabled": True}
    try:
        if STATE_FILE.exists():
            content = STATE_FILE.read_text()
            state = json.loads(content)
            # Validate expected fields exist and have correct types
            if not isinstance(state.get("enabled"), bool):
                state["enabled"] = True
            # Back-compat: older versions stored skip_next in state.json.
            # skip_next is now tracked via SKIP_FILE for atomicity.
            return {"enabled": state.get("enabled", True)}
    except json.JSONDecodeError as e:
        print(f"Warning: Corrupted state file, using defaults: {e}", file=sys.stderr)
    except (IOError, OSError) as e:
        print(f"Warning: Could not read state file: {e}", file=sys.stderr)
    return default_state


def save_state(state: dict):
    """Save plugin state."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        # Only persist durable state (enabled). skip is tracked via SKIP_FILE.
        payload = json.dumps({"enabled": bool(state.get("enabled", True))}, indent=2)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=str(STATE_DIR),
            prefix="state.",
            suffix=".tmp",
        ) as tf:
            tf.write(payload)
            tmp_path = tf.name
        os.replace(tmp_path, STATE_FILE)
    except (IOError, OSError) as e:
        print(f"Warning: Could not save state: {e}", file=sys.stderr)


def decrement_skip() -> bool:
    """
    Decrement the skip counter. Returns True if skip was consumed.
    Supports both old format (file exists = 1 skip) and new format (file contains count).
    """
    if not SKIP_FILE.exists():
        return False

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
        else:
            # Decrement and save
            SKIP_FILE.write_text(str(count - 1))

        return True
    except (IOError, OSError):
        return False


def get_skip_count() -> int:
    """Get current skip count (0 if no skips remaining)."""
    if not SKIP_FILE.exists():
        return 0
    try:
        content = SKIP_FILE.read_text().strip()
        return int(content)
    except (ValueError, IOError, OSError):
        return 1  # Old format or error = treat as 1


def clear_skip():
    """Clear all skip flags (legacy function, kept for compatibility)."""
    try:
        SKIP_FILE.unlink(missing_ok=True)
    except TypeError:
        # Python < 3.8 compatibility for missing_ok
        try:
            if SKIP_FILE.exists():
                SKIP_FILE.unlink()
        except (IOError, OSError):
            pass
    except (IOError, OSError):
        pass


# === COMMAND PARSING ===

def split_chained_commands(command: str) -> List[str]:
    """
    Split a command string into individual commands for separate analysis.
    Handles &&, ||, ;, and | (pipes).

    Note: This is a simplified parser. Complex shell constructs may not be
    perfectly handled, which is intentional — unknown constructs should be
    analyzed more carefully, not less.
    """
    # First, try to identify obvious chaining patterns
    # We handle: cmd1 && cmd2, cmd1 || cmd2, cmd1 ; cmd2, cmd1 | cmd2

    commands = []
    current = ""
    i = 0
    in_quotes = False
    quote_char = None

    while i < len(command):
        char = command[i]

        # Track quote state
        if char in ('"', "'") and (i == 0 or command[i-1] != '\\'):
            if not in_quotes:
                in_quotes = True
                quote_char = char
            elif char == quote_char:
                in_quotes = False
                quote_char = None

        # Only split on operators outside quotes
        if not in_quotes:
            # Check for && or ||
            if i < len(command) - 1:
                two_char = command[i:i+2]
                if two_char in ('&&', '||'):
                    if current.strip():
                        commands.append(current.strip())
                    current = ""
                    i += 2
                    continue

            # Check for ; or |
            if char in (';', '|'):
                if current.strip():
                    commands.append(current.strip())
                current = ""
                i += 1
                continue

        current += char
        i += 1

    # Add final command
    if current.strip():
        commands.append(current.strip())

    return commands if commands else [command]


# === SELF-EXEMPTION ===

def _is_hardstop_command(command: str) -> bool:
    """Check if command is a HardStop self-management invocation.

    Detects python calls to hs_cmd.py (the HardStop control script).
    Rejects chained commands to prevent bypass attacks like:
        python evil.py && python hs_cmd.py skip
    """
    parts = split_chained_commands(command)
    if len(parts) != 1:
        return False
    cmd = parts[0].strip()
    tokens = cmd.split()
    if len(tokens) < 2:
        return False
    # First token must be a python executable
    if 'python' not in tokens[0].lower():
        return False
    # Must reference hs_cmd.py
    return any('hs_cmd.py' in t for t in tokens[1:])


# === PATTERN MATCHING ===

def check_dangerous(command: str) -> Tuple[bool, Optional[Dict]]:
    """
    Check against dangerous patterns.

    Returns:
        (matched, pattern_dict) where pattern_dict contains:
            - id: Pattern identifier
            - regex: Regular expression
            - message: Human-readable description
            - severity: Risk level (critical/high/medium/low/info)
            - category: Attack category
    """
    for regex, pattern_id in DANGEROUS_PATTERNS:
        try:
            if re.search(regex, command, re.IGNORECASE):
                # Retrieve full pattern metadata from registry
                pattern_data = _PATTERN_REGISTRY.get(pattern_id)
                if pattern_data:
                    return True, pattern_data
                else:
                    # Fallback if registry lookup fails
                    return True, {
                        'id': pattern_id,
                        'message': 'Dangerous pattern detected',
                        'severity': 'medium',
                        'category': 'unknown',
                    }
        except re.error as e:
            # Log regex errors but don't crash
            print(f"Warning: Invalid regex pattern '{regex}': {e}", file=sys.stderr)

    return False, None


def check_safe(command: str) -> bool:
    """Check against safe patterns."""
    command = command.strip()
    for pattern in SAFE_PATTERNS:
        try:
            # Conservative: safe patterns must match the ENTIRE command string
            # (prevents substring-based bypasses).
            if re.fullmatch(pattern, command, re.IGNORECASE):
                return True
        except re.error as e:
            print(f"Warning: Invalid regex pattern '{pattern}': {e}", file=sys.stderr)
    return False


def _build_claude_exec(claude_path: str, args: List[str]) -> List[str]:
    """Build an executable command for claude CLI across platforms."""
    import platform

    if platform.system() == "Windows":
        lower = claude_path.lower()
        if lower.endswith((".cmd", ".bat")):
            return ["cmd", "/c", claude_path, *args]
    return [claude_path, *args]


def check_all_commands(command: str) -> Tuple[bool, Optional[Dict]]:
    """
    Check a potentially chained command.
    Splits on &&, ||, ;, | and checks each part.
    Returns (is_dangerous, pattern_dict) - dangerous if ANY part is dangerous.
    """
    parts = split_chained_commands(command)

    for part in parts:
        is_dangerous, pattern_data = check_dangerous(part)
        if is_dangerous:
            # Add note about chained command to the pattern data
            if pattern_data:
                pattern_data = pattern_data.copy()
                original_message = pattern_data.get('message', 'Dangerous pattern detected')
                pattern_data['message'] = f"{original_message} (in chained command)"
            return True, pattern_data

    return False, None


def is_all_safe(command: str) -> bool:
    """
    Check if ALL parts of a chained command are safe.
    Returns True only if every part matches a safe pattern.

    v1.3.4: Now splits chained commands and checks each part individually.
    This allows safe chains like "cd /tmp && git push" to fast-path.
    """
    stripped = command.strip()
    if not stripped:
        return True

    # Split into parts and check each one
    parts = split_chained_commands(stripped)

    # All parts must match a safe pattern
    for part in parts:
        if not check_safe(part):
            return False

    return True


# === LLM ANALYSIS ===

def find_claude_cli() -> Optional[str]:
    """Find claude CLI executable."""
    import shutil
    import platform

    # First check if 'claude' is in PATH (safest, uses system resolution)
    claude_in_path = shutil.which("claude")
    if claude_in_path:
        return claude_in_path

    # Check common installation locations as fallback
    candidates = []

    if platform.system() == "Windows":
        # Windows paths
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        candidates = [
            str(Path.home() / "AppData" / "Roaming" / "npm" / "claude.cmd"),
            str(Path.home() / "AppData" / "Local" / "npm" / "claude.cmd"),
            str(Path.home() / ".npm-global" / "claude.cmd"),
            str(Path(appdata) / "npm" / "claude.cmd") if appdata else "",
            str(Path(localappdata) / "npm" / "claude.cmd") if localappdata else "",
            # Scoop installation
            str(Path.home() / "scoop" / "shims" / "claude.cmd"),
        ]
        candidates = [c for c in candidates if c]  # Filter empty
    else:
        # Unix paths (macOS/Linux)
        candidates = [
            "/usr/local/bin/claude",
            str(Path.home() / ".local/bin/claude"),
            str(Path.home() / ".npm-global/bin/claude"),
            # Homebrew on macOS
            "/opt/homebrew/bin/claude",
        ]

    for candidate in candidates:
        try:
            candidate_path = Path(candidate)
            if candidate_path.exists() and candidate_path.is_file():
                result = subprocess.run(
                    _build_claude_exec(candidate, ["--version"]),
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return candidate
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
            continue

    return None


def parse_llm_response(response: str) -> Tuple[str, str]:
    """
    Parse LLM response, handling various formats.
    Returns (verdict, reason).
    """
    response = response.strip()

    # Try to extract JSON, handling markdown fencing
    json_str = response

    # Remove markdown code fences if present
    if "```" in response:
        # Try to find JSON block
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            # Try to find any JSON object (handles nested braces)
            brace_count = 0
            start_idx = None
            for i, char in enumerate(response):
                if char == '{':
                    if start_idx is None:
                        start_idx = i
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0 and start_idx is not None:
                        json_str = response[start_idx:i+1]
                        break

    try:
        data = json.loads(json_str)
        verdict = str(data.get("verdict", "")).upper()
        reason = str(data.get("reason", ""))

        if verdict in ("ALLOW", "BLOCK"):
            return verdict, reason
    except json.JSONDecodeError:
        pass

    # JSON parsing failed — use keyword detection
    # In fail-closed mode, unknown = BLOCK
    upper = response.upper()
    if "BLOCK" in upper:
        return "BLOCK", "Flagged as dangerous (keyword match)"
    elif "ALLOW" in upper:
        return "ALLOW", "Permitted (keyword match)"

    # Could not determine verdict
    return "UNKNOWN", "Could not parse response"


def ask_claude(command: str, cwd: str) -> Tuple[str, str]:
    """
    Ask Claude to analyze command. Returns (verdict, reason).

    FAIL-CLOSED DESIGN:
    - If CLI unavailable: BLOCK (not ALLOW)
    - If timeout: BLOCK (not ALLOW)
    - If parse error: BLOCK (not ALLOW)

    This ensures safety check failures don't silently allow dangerous commands.
    """
    claude_path = find_claude_cli()

    if not claude_path:
        if FAIL_CLOSED:
            return "BLOCK", "Safety CLI unavailable — blocking for safety (use /hs skip to bypass)"
        else:
            return "ALLOW", "(CLI unavailable, pattern-only mode)"

    prompt = LLM_PROMPT.format(command=command, cwd=cwd)

    try:
        result = subprocess.run(
            _build_claude_exec(claude_path, ["--print", "--model", "haiku"]),
            input=prompt,
            capture_output=True,
            text=True,
            timeout=15,
            shell=False
        )

        if result.returncode != 0:
            if FAIL_CLOSED:
                return "BLOCK", f"Safety CLI error (exit {result.returncode}) — blocking for safety"
            else:
                return "ALLOW", f"(CLI error {result.returncode}, allowing)"

        # Parse response
        verdict, reason = parse_llm_response(result.stdout)

        if verdict == "UNKNOWN":
            if FAIL_CLOSED:
                return "BLOCK", "Could not verify safety — blocking (use /hs skip to bypass)"
            else:
                return "ALLOW", "(Unparseable response, allowing)"

        return verdict, reason

    except subprocess.TimeoutExpired:
        if FAIL_CLOSED:
            return "BLOCK", "Safety check timed out — blocking for safety (use /hs skip to bypass)"
        else:
            return "ALLOW", "(Timeout, allowing)"

    except subprocess.SubprocessError as e:
        if FAIL_CLOSED:
            return "BLOCK", f"Safety check failed ({type(e).__name__}) — blocking for safety"
        else:
            return "ALLOW", f"(Error: {type(e).__name__}, allowing)"

    except OSError as e:
        if FAIL_CLOSED:
            return "BLOCK", f"Cannot run safety check ({e}) — blocking for safety"
        else:
            return "ALLOW", f"(OS Error: {e}, allowing)"


# === MAIN ===

def block_command(message: str, command: str, layer: str, cwd: str, pattern_data: Optional[Dict] = None, risk_score: int = 0, risk_level: str = "unknown", blocked_count: int = 0):
    """
    Block a command using Claude Code's structured JSON output.

    Uses exit code 0 with permissionDecision: "deny" instead of exit code 2.
    This ensures consistent behavior between CLI and VS Code extension.
    Exit code 2 causes VS Code to treat it as a session error and restart the chat.
    """
    log_decision(command, "BLOCK", message, layer, cwd, pattern_data, risk_score, risk_level)

    # Build the block reason message
    truncated_cmd = command[:100] + ('...' if len(command) > 100 else '')
    reason = f"🛑 BLOCKED: {message}\nCommand: {truncated_cmd}\nUse '/hs skip' to bypass."

    # Output structured JSON for Claude Code to parse
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
            "suggestedAction": {
                "workflow": "bypass",
                "command": "/hs skip",
                "thenRetry": True,
                "userPrompt": "This command was blocked for safety. Should I bypass the check with /hs skip and retry?"
            }
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

    # Show first-block message (once per installation)
    first_block_file = STATE_DIR / "first_block_shown"
    if not first_block_file.exists():
        try:
            print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", file=sys.stderr)
            print("🎉 Hardstop just protected you from a dangerous command!", file=sys.stderr)
            print("⭐ Enjoying it? Star us: https://github.com/frmoretto/hardstop", file=sys.stderr)
            print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", file=sys.stderr)
            first_block_file.touch()
        except:
            pass  # Don't fail if we can't write

    sys.exit(0)


def check_uninstall_script(command: str) -> bool:
    """
    Check if this is the Hardstop removal script.
    Returns True if blocked (shows custom message), False otherwise.
    """
    # Detect removal script execution
    removal_patterns = [
        r"uninstall\.ps1",
        r"uninstall\.sh",
    ]

    for pattern in removal_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            reason = (
                "🗑️ HARDSTOP REMOVAL DETECTED\n"
                "You are about to remove Hardstop.\n"
                "This will remove: Plugin files, Skill config, Hooks\n"
                "To confirm: Run '/hs skip' then retry."
            )
            output = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                    "suggestedAction": {
                        "workflow": "uninstall",
                        "command": "/hs skip",
                        "thenRetry": True,
                        "userPrompt": "You're about to uninstall Hardstop. Are you sure? I can run /hs skip to proceed."
                    }
                }
            }
            print(json.dumps(output))
            sys.exit(0)

    return False


def allow_command(reason: str, command: str, layer: str, cwd: str, silent: bool = False):
    """Allow a command and exit with code 0."""
    log_decision(command, "ALLOW", reason, layer, cwd)
    if not silent and reason and not reason.startswith("("):
        print(f"ℹ️  {reason}", file=sys.stderr)
    sys.exit(0)


def main():
    # Parse stdin from Claude Code
    try:
        context = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        if FAIL_CLOSED:
            print(f"\n🛑 BLOCKED: Could not parse command context ({e})\n", file=sys.stderr)
            print("Safety check cannot proceed. Use '/hs skip' if needed.\n", file=sys.stderr)
            sys.exit(2)
        else:
            sys.exit(0)

    tool_input = context.get("tool_input", {})
    command = tool_input.get("command", "")
    cwd = context.get("cwd", os.getcwd())

    if not command.strip():
        sys.exit(0)

    # Check state
    state = load_state()

    if not state.get("enabled", True):
        log_decision(command, "ALLOW", "Hardstop disabled", "disabled", cwd)
        sys.exit(0)

    if SKIP_FILE.exists():
        remaining = get_skip_count()
        decrement_skip()
        new_remaining = remaining - 1
        log_decision(command, "ALLOW", f"Skip ({remaining} -> {new_remaining} remaining)", "skip", cwd)
        if new_remaining > 0:
            print(f"⏭️  Safety check skipped ({new_remaining} skip{'s' if new_remaining > 1 else ''} remaining)", file=sys.stderr)
        else:
            print("⏭️  Safety check skipped (last skip, protection resumed)", file=sys.stderr)
        sys.exit(0)

    # === SELF-EXEMPTION: HardStop's own commands always pass ===
    if _is_hardstop_command(command):
        log_decision(command, "ALLOW", "HardStop self-management", "self", cwd)
        allow_command("HardStop self-management", command, "self", cwd, silent=True)

    # === SPECIAL CASE: Uninstall script detection ===
    # Show friendly confirmation message before generic blocking
    check_uninstall_script(command)

    # === LAYER 1: Pattern matching (instant) ===
    # Uses chained command detection to check ALL parts of piped/chained commands

    # Check dangerous patterns first (any part dangerous = block whole command)
    is_dangerous, pattern_data = check_all_commands(command)
    if is_dangerous:
        # Record to session tracker for risk scoring (v1.4.0+)
        risk_score = 0
        risk_level = "unknown"
        blocked_count = 0

        if SESSION_TRACKER_AVAILABLE and pattern_data:
            try:
                tracker = get_tracker()
                tracker.record_block(command, pattern_data)

                # Get updated risk metrics
                risk_score = tracker.get_risk_score()
                risk_level = tracker.get_risk_level()
                blocked_count = tracker.get_blocked_count()

            except Exception as e:
                # Don't fail the hook if tracker has issues
                print(f"Warning: Session tracker error: {e}", file=sys.stderr)

        # Extract message from pattern data
        danger_message = pattern_data.get('message', 'Dangerous pattern detected') if pattern_data else 'Dangerous pattern detected'
        block_command(danger_message, command, "pattern", cwd, pattern_data, risk_score, risk_level, blocked_count)

    # Check if ALL parts are safe patterns
    if is_all_safe(command):
        allow_command("Safe pattern match", command, "pattern", cwd, silent=True)

    # === LAYER 2: LLM analysis (unknown patterns) ===

    verdict, reason = ask_claude(command, cwd)

    if verdict == "BLOCK":
        block_command(reason, command, "llm", cwd)

    # ALLOW
    allow_command(reason, command, "llm", cwd)


if __name__ == "__main__":
    main()
