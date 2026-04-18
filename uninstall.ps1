# Hardstop uninstaller for Windows
# Removes: plugin, skill, hooks from settings.json, and optionally state

$ErrorActionPreference = "Stop"

$ClaudeDir = if ($env:CLAUDE_CONFIG_DIR) { $env:CLAUDE_CONFIG_DIR.TrimEnd('\', '/') } else { Join-Path $env:USERPROFILE '.claude' }
$PluginDest = Join-Path $ClaudeDir 'plugins\hs'
$SkillDest = Join-Path $ClaudeDir 'skills\hs'
$SettingsFile = Join-Path $ClaudeDir 'settings.json'
$StateDir = Join-Path $env:USERPROFILE '.hardstop'

Write-Host "=== Hardstop Uninstaller ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Remove plugin
Write-Host "[1/4] Removing plugin from: $PluginDest"
if (Test-Path $PluginDest) {
    Remove-Item -Recurse -Force $PluginDest
    Write-Host "      Plugin removed." -ForegroundColor Green
} else {
    Write-Host "      Plugin not found, skipping." -ForegroundColor Yellow
}

# Step 2: Remove skill
Write-Host "[2/4] Removing skill from: $SkillDest"
if (Test-Path $SkillDest) {
    Remove-Item -Recurse -Force $SkillDest
    Write-Host "      Skill removed." -ForegroundColor Green
} else {
    Write-Host "      Skill not found, skipping." -ForegroundColor Yellow
}

# Step 3: Remove hooks from settings.json
Write-Host "[3/4] Removing hooks from: $SettingsFile"
if (Test-Path $SettingsFile) {
    $content = Get-Content $SettingsFile -Raw
    if ($content -match "pre_tool_use.py|pre_read.py") {
        Copy-Item $SettingsFile "${SettingsFile}.backup"
        Write-Host "      Backed up settings to ${SettingsFile}.backup"

        # Use Python for reliable JSON manipulation
        $pythonScript = @"
import json
import sys

settings_file = sys.argv[1]

try:
    with open(settings_file, 'r', encoding='utf-8-sig') as f:
        settings = json.load(f)
except:
    print("Could not read settings file")
    sys.exit(1)

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

with open(settings_file, 'w', encoding='utf-8') as f:
    json.dump(settings, f, indent=2)
"@
        $pythonScript | python - "$SettingsFile"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "      Hooks removed from settings." -ForegroundColor Green
        } else {
            Write-Host "      WARNING: Could not remove hooks. Edit manually." -ForegroundColor Yellow
        }
    } else {
        Write-Host "      No Hardstop hooks found, skipping." -ForegroundColor Yellow
    }
} else {
    Write-Host "      Settings file not found, skipping." -ForegroundColor Yellow
}

# Step 4: Ask about state removal
Write-Host "[4/4] State directory: $StateDir"
if (Test-Path $StateDir) {
    Write-Host "      Found state directory containing audit logs."
    $response = Read-Host "      Remove state and audit logs? [y/N]"
    if ($response -eq 'y' -or $response -eq 'Y') {
        Remove-Item -Recurse -Force $StateDir
        Write-Host "      State removed." -ForegroundColor Green
    } else {
        Write-Host "      State preserved." -ForegroundColor Yellow
    }
} else {
    Write-Host "      State directory not found, skipping." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Uninstallation Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "  IMPORTANT: You MUST restart Claude Code to complete" -ForegroundColor Red
Write-Host "  the uninstallation. Old hooks remain active until restart." -ForegroundColor Red
Write-Host "" -ForegroundColor Red
Write-Host "  WARNING: Until you restart, Hardstop hooks will FAIL" -ForegroundColor Yellow
Write-Host "  because the plugin files have been removed!" -ForegroundColor Yellow
Write-Host "" -ForegroundColor Red
Write-Host "  How to restart:" -ForegroundColor Yellow
Write-Host "  - VS Code: Ctrl+Shift+P > 'Developer: Reload Window'" -ForegroundColor Yellow
Write-Host "           (or Cmd+Shift+P on Mac)" -ForegroundColor Yellow
Write-Host "  - CLI: Exit and run 'claude' again" -ForegroundColor Yellow
Write-Host "  - Cowork: Close and reopen Claude Desktop app" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""
