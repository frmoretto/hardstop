#!/usr/bin/env python3
"""
Hardstop Plugin — Slash Command Handler

Commands:
  /hs on        Enable protection (default)
  /hs off       Disable protection
  /hs skip [n]  Skip next n commands (default: 1)
  /hs status    Show current state
  /hs log       Show recent audit log entries
  /hs help      Show this help
"""

import sys
import io
import json
from pathlib import Path
from datetime import datetime
import os
import tempfile

# Fix Windows console encoding for Unicode output
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

STATE_DIR = Path.home() / ".hardstop"
STATE_FILE = STATE_DIR / "state.json"
SKIP_FILE = STATE_DIR / "skip_next"
LOG_FILE = STATE_DIR / "audit.log"
PLUGIN_DIR = Path.home() / ".claude" / "plugins" / "hs"


def get_version() -> str:
    """Read version from plugin.json (single source of truth)."""
    plugin_json = PLUGIN_DIR / ".claude-plugin" / "plugin.json"
    try:
        if plugin_json.exists():
            data = json.loads(plugin_json.read_text())
            return data.get("version", "unknown")
    except (json.JSONDecodeError, IOError):
        pass
    return "unknown"


def load_state() -> dict:
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
    except json.JSONDecodeError:
        pass
    except (IOError, OSError):
        pass
    return {"enabled": True}


def save_state(state: dict):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
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
    except Exception as e:
        print(f"Error saving state: {e}", file=sys.stderr)


def cmd_on():
    state = load_state()
    state["enabled"] = True
    save_state(state)
    print("✅ Hardstop enabled")


def cmd_off():
    state = load_state()
    state["enabled"] = False
    save_state(state)
    print("⚠️  Hardstop disabled")
    print("   Dangerous commands will NOT be blocked.")
    print("   Note: Credential file protection (Read hook) remains active.")
    print("   Use '/hs on' to re-enable, or '/hs skip' to bypass read protection.")


def cmd_skip(count: int = 1):
    """Set skip counter for next N commands."""
    if count < 1:
        print("❌ Skip count must be at least 1")
        return
    if count > 10:
        print("❌ Skip count cannot exceed 10 (safety limit)")
        return

    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        SKIP_FILE.write_text(str(count))
    except Exception as e:
        print(f"Error setting skip flag: {e}", file=sys.stderr)
        return

    if count == 1:
        print("⏭️  Next command will skip safety check")
        print("   One-time bypass — protection resumes after.")
    else:
        print(f"⏭️  Next {count} commands will skip safety check")
        print("   Multi-skip bypass — protection resumes after.")


def cmd_status():
    state = load_state()
    enabled = state.get("enabled", True)

    # Check skip count
    skip_count = 0
    if SKIP_FILE.exists():
        try:
            skip_count = int(SKIP_FILE.read_text().strip())
        except (ValueError, IOError):
            skip_count = 1  # Fallback for old format

    print(f"Hardstop v{get_version()}")
    print()
    print(f"  Status:      {'🟢 Enabled' if enabled else '🔴 Disabled'}")
    if skip_count > 0:
        print(f"  Skip next:   {skip_count} command{'s' if skip_count > 1 else ''}")
    else:
        print(f"  Skip next:   No")
    print(f"  Fail mode:   Fail-closed (errors block commands)")
    print()
    print(f"  State file:  {STATE_FILE}")
    print(f"  Skip file:   {SKIP_FILE}")
    print(f"  Audit log:   {LOG_FILE}")

    # Show recent stats if log exists
    if LOG_FILE.exists():
        try:
            lines = LOG_FILE.read_text().strip().split('\n')
            recent = lines[-100:]  # Last 100 entries
            blocks = sum(1 for l in recent if '"verdict": "BLOCK"' in l)
            allows = sum(1 for l in recent if '"verdict": "ALLOW"' in l)
            print()
            print(f"  Recent stats (last {len(recent)} commands):")
            print(f"    Blocked: {blocks}")
            print(f"    Allowed: {allows}")
        except Exception:
            pass

    # GitHub star CTA
    print()
    print("  ⭐ Enjoying Hardstop? Star us on GitHub!")
    print("     https://github.com/frmoretto/hardstop")


def cmd_log():
    """Show recent audit log entries."""
    if not LOG_FILE.exists():
        print("No audit log found yet.")
        print(f"Log will be created at: {LOG_FILE}")
        return

    try:
        lines = LOG_FILE.read_text().strip().split('\n')
        recent = lines[-20:]  # Last 20 entries

        print(f"Hardstop Audit Log (last {len(recent)} entries)")
        print("=" * 60)

        for line in recent:
            try:
                entry = json.loads(line)
                ts = entry.get("timestamp", "")[:19]  # Trim microseconds
                verdict = entry.get("verdict", "?")
                layer = entry.get("layer", "?")
                cmd = entry.get("command", "")[:50]
                reason = entry.get("reason", "")[:30]

                icon = "🛑" if verdict == "BLOCK" else "✅"
                print(f"{ts} {icon} [{layer:7}] {cmd}")
                if reason:
                    print(f"                         └─ {reason}")
            except json.JSONDecodeError:
                continue

        print()
        print(f"Full log: {LOG_FILE}")

    except Exception as e:
        print(f"Error reading log: {e}")


def cmd_help():
    print(f"""
Hardstop v{get_version()}
The mechanical brake for AI-generated commands

Commands:
  /hs on        Enable protection (default)
  /hs off       Disable protection temporarily
  /hs skip [n]  Skip safety check for next n commands (default: 1)
  /hs status    Show current state and stats
  /hs log       Show recent audit log entries
  /hs help      Show this help

Aliases: /hardstop, /hard, /hs

What it catches:
  🛑 Instant block: rm -rf ~/, fork bombs, reverse shells, credential exfil
  🤖 LLM analysis: Obfuscated commands, novel attacks, context-dependent risks

Design:
  • Fail-closed: If safety check fails, command is blocked (not allowed)
  • Command chaining: Analyzes all parts of piped/chained commands
  • Audit logging: All decisions logged to ~/.hardstop/audit.log

Works independently — no skill required.
""")


def main():
    # Parse command
    if len(sys.argv) < 2:
        cmd_help()
        return

    subcommand = sys.argv[1].lower()

    # Handle skip with optional count argument
    if subcommand in ("skip", "bypass"):
        count = 1
        if len(sys.argv) >= 3:
            try:
                count = int(sys.argv[2])
            except ValueError:
                print(f"❌ Invalid skip count: {sys.argv[2]}")
                print("   Usage: /hs skip [count]")
                return
        cmd_skip(count)
        return

    commands = {
        "on": cmd_on,
        "enable": cmd_on,
        "off": cmd_off,
        "disable": cmd_off,
        "status": cmd_status,
        "state": cmd_status,
        "log": cmd_log,
        "logs": cmd_log,
        "audit": cmd_log,
        "help": cmd_help,
        "-h": cmd_help,
        "--help": cmd_help,
    }

    handler = commands.get(subcommand)
    if handler:
        handler()
    else:
        print(f"Unknown command: {subcommand}")
        print("Use '/hs help' for available commands.")


if __name__ == "__main__":
    main()
