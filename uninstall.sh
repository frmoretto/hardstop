#!/bin/bash
# Hardstop uninstaller for macOS/Linux
# Removes: plugin, skill, hooks from settings.json, and optionally state

set -e

CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
CLAUDE_DIR="${CLAUDE_DIR%/}"
PLUGIN_DEST="$CLAUDE_DIR/plugins/hs"
SKILL_DEST="$CLAUDE_DIR/skills/hs"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"
STATE_DIR="$HOME/.hardstop"

echo "=== Hardstop Uninstaller ==="
echo ""

# Step 1: Remove plugin
echo "[1/4] Removing plugin from: $PLUGIN_DEST"
if [ -d "$PLUGIN_DEST" ]; then
    rm -rf "$PLUGIN_DEST"
    echo "      Plugin removed."
else
    echo "      Plugin not found, skipping."
fi

# Step 2: Remove skill
echo "[2/4] Removing skill from: $SKILL_DEST"
if [ -d "$SKILL_DEST" ]; then
    rm -rf "$SKILL_DEST"
    echo "      Skill removed."
else
    echo "      Skill not found, skipping."
fi

# Step 3: Remove hooks from settings.json
echo "[3/4] Removing hooks from: $SETTINGS_FILE"
if [ -f "$SETTINGS_FILE" ]; then
    if grep -qE "pre_tool_use.py|pre_read.py" "$SETTINGS_FILE" 2>/dev/null; then
        cp "$SETTINGS_FILE" "${SETTINGS_FILE}.backup"
        echo "      Backed up settings to ${SETTINGS_FILE}.backup"

        if command -v python3 &> /dev/null; then
            python3 -c "
import json

settings_file = '$SETTINGS_FILE'
with open(settings_file, 'r') as f:
    settings = json.load(f)

if 'hooks' in settings and 'PreToolUse' in settings['hooks']:
    # Filter out Hardstop hooks (Bash + Read)
    settings['hooks']['PreToolUse'] = [
        hook for hook in settings['hooks']['PreToolUse']
        if not any(
            'pre_tool_use.py' in h.get('command', '') or
            'pre_read.py' in h.get('command', '')
            for h in hook.get('hooks', [])
        )
    ]
    # Clean up empty arrays
    if not settings['hooks']['PreToolUse']:
        del settings['hooks']['PreToolUse']
    if not settings['hooks']:
        del settings['hooks']

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)
"
            echo "      Hooks removed from settings."
        else
            echo "      WARNING: Python not found. Remove hooks manually from $SETTINGS_FILE"
        fi
    else
        echo "      No Hardstop hooks found, skipping."
    fi
else
    echo "      Settings file not found, skipping."
fi

# Step 4: Ask about state removal
echo "[4/4] State directory: $STATE_DIR"
if [ -d "$STATE_DIR" ]; then
    echo "      Found state directory containing audit logs."
    read -p "      Remove state and audit logs? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$STATE_DIR"
        echo "      State removed."
    else
        echo "      State preserved."
    fi
else
    echo "      State directory not found, skipping."
fi

echo ""
echo "=== Uninstallation Complete ==="
echo ""
echo "============================================================"
echo "  IMPORTANT: You MUST restart Claude Code to complete"
echo "  the uninstallation. Old hooks remain active until restart."
echo ""
echo "  WARNING: Until you restart, Hardstop hooks will FAIL"
echo "  because the plugin files have been removed!"
echo ""
echo "  How to restart:"
echo "  - VS Code: Cmd+Shift+P > 'Developer: Reload Window'"
echo "           (or Ctrl+Shift+P on Linux)"
echo "  - CLI: Exit and run 'claude' again"
echo "  - Cowork: Close and reopen Claude Desktop app"
echo "============================================================"
echo ""
