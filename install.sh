#!/bin/bash
# Hardstop installer for macOS/Linux
# Installs: plugin, skill, and hooks configuration

set -e

CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
CLAUDE_DIR="${CLAUDE_DIR%/}"
PLUGIN_DEST="$CLAUDE_DIR/plugins/hs"
SKILL_DEST="$CLAUDE_DIR/skills/hs"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"
SOURCE="$(cd "$(dirname "$0")" && pwd)"

echo "=== Hardstop Installer ==="
echo ""

# Step 1: Install plugin
echo "[1/3] Installing plugin to: $PLUGIN_DEST"
mkdir -p "$PLUGIN_DEST"
rsync -av --exclude='.git' --exclude='.venv' --exclude='.pytest_cache' --exclude='__pycache__' --exclude='install.sh' --exclude='install.ps1' "$SOURCE/" "$PLUGIN_DEST/"
echo "      Plugin installed."

# Step 2: Create skill
echo "[2/3] Creating skill at: $SKILL_DEST"
mkdir -p "$SKILL_DEST"
cat > "$SKILL_DEST/SKILL.md" << EOF
---
name: hs
version: 1.0.0
description: >
  Hardstop - Pre-execution safety layer control. Use this skill when the user wants to
  enable, disable, check status, skip, or view logs for the Hardstop safety system.
author: Francesco Marinoni Moretto
license: CC-BY-4.0
triggers:
  - hs
  - hs on
  - hs off
  - hs status
  - hs skip
  - hs log
---

# Hardstop Control

**Purpose:** Control the Hardstop pre-execution safety layer that blocks dangerous shell commands.

When the user invokes \`/hs\` (with optional subcommands), run the appropriate Python command:

- \`/hs\` or \`/hs status\`: \`python $PLUGIN_DEST/commands/hs_cmd.py status\`
- \`/hs on\`: \`python $PLUGIN_DEST/commands/hs_cmd.py on\`
- \`/hs off\`: \`python $PLUGIN_DEST/commands/hs_cmd.py off\`
- \`/hs skip\`: \`python $PLUGIN_DEST/commands/hs_cmd.py skip\`
- \`/hs log\`: \`python $PLUGIN_DEST/commands/hs_cmd.py log\`
EOF
echo "      Skill created."

# Step 3: Add hooks to settings.json
echo "[3/3] Configuring hooks in: $SETTINGS_FILE"
mkdir -p "$(dirname "$SETTINGS_FILE")"

if [ -f "$SETTINGS_FILE" ] && [ -s "$SETTINGS_FILE" ]; then
    if grep -q "pre_tool_use.py" "$SETTINGS_FILE" 2>/dev/null; then
        echo "      Hooks already configured, skipping."
    else
        cp "$SETTINGS_FILE" "${SETTINGS_FILE}.backup"
        echo "      Backed up existing settings."

        if command -v python3 &> /dev/null; then
            python3 -c "
import json
settings_file = '$SETTINGS_FILE'
with open(settings_file, 'r') as f:
    settings = json.load(f)
if 'hooks' not in settings:
    settings['hooks'] = {}
if 'PreToolUse' not in settings['hooks']:
    settings['hooks']['PreToolUse'] = []
# Add Bash hook
settings['hooks']['PreToolUse'].append({
    'matcher': 'Bash',
    'hooks': [{'type': 'command', 'command': 'python $PLUGIN_DEST/hooks/pre_tool_use.py', 'timeout': 30}]
})
# Add Read hook (v1.3 - secrets protection)
settings['hooks']['PreToolUse'].append({
    'matcher': 'Read',
    'hooks': [{'type': 'command', 'command': 'python $PLUGIN_DEST/hooks/pre_read.py', 'timeout': 30}]
})
with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)
"
            echo "      Hooks configured (Bash + Read)."
        else
            echo "      WARNING: Python not found. Add hooks manually (see INSTALLATION.md)"
        fi
    fi
else
    cat > "$SETTINGS_FILE" << EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python $PLUGIN_DEST/hooks/pre_tool_use.py",
            "timeout": 30
          }
        ]
      },
      {
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "python $PLUGIN_DEST/hooks/pre_read.py",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
EOF
    echo "      Settings created with hooks (Bash + Read)."
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "============================================================"
echo "  IMPORTANT: You MUST restart Claude Code for Hardstop"
echo "  to take effect. Hooks are loaded at session start."
echo ""
echo "  How to restart:"
echo "  - VS Code: Cmd+Shift+P > 'Developer: Reload Window'"
echo "           (or Ctrl+Shift+P on Linux)"
echo "  - CLI: Exit and run 'claude' again"
echo "  - Cowork: Close and reopen Claude Desktop app"
echo "============================================================"
echo ""
echo "After restart, verify with: /hs status"
echo ""
