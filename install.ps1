# Hardstop installer for Windows
# Installs: plugin, skill, and hooks configuration

$ErrorActionPreference = "Stop"

$ClaudeDir = if ($env:CLAUDE_CONFIG_DIR) { $env:CLAUDE_CONFIG_DIR.TrimEnd('\', '/') } else { Join-Path $env:USERPROFILE '.claude' }
$PluginDest = Join-Path $ClaudeDir 'plugins\hs'
$SkillDest = Join-Path $ClaudeDir 'skills\hs'
$SettingsFile = Join-Path $ClaudeDir 'settings.json'
$Source = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== Hardstop Installer ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Install plugin
Write-Host "[1/3] Installing plugin to: $PluginDest"
if (-not (Test-Path $PluginDest)) {
    New-Item -ItemType Directory -Force -Path $PluginDest | Out-Null
}
Copy-Item -Path "$Source\*" -Destination $PluginDest -Recurse -Force -Exclude '.venv','.git','.pytest_cache','install.ps1','install.sh'
Write-Host "      Plugin installed." -ForegroundColor Green

# Step 2: Create skill
Write-Host "[2/3] Creating skill at: $SkillDest"
if (-not (Test-Path $SkillDest)) {
    New-Item -ItemType Directory -Force -Path $SkillDest | Out-Null
}

$SkillContent = @"
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

When the user invokes ``/hs`` (with optional subcommands), run the appropriate Python command:

- ``/hs`` or ``/hs status``: ``python $PluginDest/commands/hs_cmd.py status``
- ``/hs on``: ``python $PluginDest/commands/hs_cmd.py on``
- ``/hs off``: ``python $PluginDest/commands/hs_cmd.py off``
- ``/hs skip``: ``python $PluginDest/commands/hs_cmd.py skip``
- ``/hs log``: ``python $PluginDest/commands/hs_cmd.py log``
"@

$SkillContent | Out-File -FilePath (Join-Path $SkillDest "SKILL.md") -Encoding utf8
Write-Host "      Skill created." -ForegroundColor Green

# Step 3: Add hooks to settings.json
Write-Host "[3/3] Configuring hooks in: $SettingsFile"

# Ensure config directory exists
if (-not (Test-Path $ClaudeDir)) {
    New-Item -ItemType Directory -Force -Path $ClaudeDir | Out-Null
}

if (Test-Path $SettingsFile) {
    $content = Get-Content $SettingsFile -Raw
    if ($content -match "pre_tool_use.py") {
        Write-Host "      Hooks already configured, skipping." -ForegroundColor Yellow
    } else {
        # Backup existing settings
        Copy-Item $SettingsFile "${SettingsFile}.backup"
        Write-Host "      Backed up existing settings."

        # Use Python for reliable JSON manipulation
        $pythonScript = @"
import json
import sys

settings_file = sys.argv[1]
plugin_dest = sys.argv[2]

try:
    with open(settings_file, 'r', encoding='utf-8-sig') as f:
        content = f.read().strip()
        settings = json.loads(content) if content else {}
except:
    settings = {}

if 'hooks' not in settings:
    settings['hooks'] = {}
if 'PreToolUse' not in settings['hooks']:
    settings['hooks']['PreToolUse'] = []

import os
hook_base = os.path.join(plugin_dest, 'hooks')
bash_hook = os.path.join(hook_base, 'pre_tool_use.py').replace('\\', '/')
read_hook = os.path.join(hook_base, 'pre_read.py').replace('\\', '/')

# Add Bash hook
settings['hooks']['PreToolUse'].append({
    'matcher': 'Bash',
    'hooks': [{
        'type': 'command',
        'command': f'python {bash_hook}',
        'timeout': 30
    }]
})
# Add Read hook (v1.3 - secrets protection)
settings['hooks']['PreToolUse'].append({
    'matcher': 'Read',
    'hooks': [{
        'type': 'command',
        'command': f'python {read_hook}',
        'timeout': 30
    }]
})

with open(settings_file, 'w', encoding='utf-8') as f:
    json.dump(settings, f, indent=2)
"@
        $pythonScript | python - "$SettingsFile" "$PluginDest"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "      Hooks configured (Bash + Read)." -ForegroundColor Green
        } else {
            Write-Host "      WARNING: Could not configure hooks. Add manually." -ForegroundColor Yellow
        }
    }
} else {
    # Create new settings.json with hooks using Python
    $pythonScript = @"
import json
import os
import sys

settings_file = sys.argv[1]
plugin_dest = sys.argv[2]
hook_base = os.path.join(plugin_dest, 'hooks')
bash_hook = os.path.join(hook_base, 'pre_tool_use.py').replace('\\', '/')
read_hook = os.path.join(hook_base, 'pre_read.py').replace('\\', '/')

settings = {
    'hooks': {
        'PreToolUse': [
            {
                'matcher': 'Bash',
                'hooks': [{
                    'type': 'command',
                    'command': f'python {bash_hook}',
                    'timeout': 30
                }]
            },
            {
                'matcher': 'Read',
                'hooks': [{
                    'type': 'command',
                    'command': f'python {read_hook}',
                    'timeout': 30
                }]
            }
        ]
    }
}

with open(settings_file, 'w', encoding='utf-8') as f:
    json.dump(settings, f, indent=2)
"@
    $pythonScript | python - "$SettingsFile" "$PluginDest"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "      Settings created with hooks (Bash + Read)." -ForegroundColor Green
    } else {
        Write-Host "      WARNING: Could not create settings. Add manually." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== Installation Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Files installed:" -ForegroundColor Cyan
Write-Host "  Plugin: $PluginDest"
Write-Host "  Skill:  $SkillDest\SKILL.md"
Write-Host "  Hooks:  $SettingsFile"
Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "  IMPORTANT: You MUST restart Claude Code for Hardstop" -ForegroundColor Red
Write-Host "  to take effect. Hooks are loaded at session start." -ForegroundColor Red
Write-Host "" -ForegroundColor Red
Write-Host "  How to restart:" -ForegroundColor Yellow
Write-Host "  - VS Code: Ctrl+Shift+P > 'Developer: Reload Window'" -ForegroundColor Yellow
Write-Host "           (or Cmd+Shift+P on Mac)" -ForegroundColor Yellow
Write-Host "  - CLI: Exit and run 'claude' again" -ForegroundColor Yellow
Write-Host "  - Cowork: Close and reopen Claude Desktop app" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""
Write-Host "After restart, verify with: /hs status" -ForegroundColor Green
Write-Host ""
