#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');

const PLUGIN_NAME = 'hs';
let CLAUDE_DIR = process.env.CLAUDE_CONFIG_DIR || '';
if (CLAUDE_DIR === '~') {
  CLAUDE_DIR = os.homedir();
} else if (CLAUDE_DIR.startsWith('~/')) {
  CLAUDE_DIR = path.join(os.homedir(), CLAUDE_DIR.slice(2));
}
CLAUDE_DIR = CLAUDE_DIR.replace(/\/+$/, '');
if (!CLAUDE_DIR) {
  CLAUDE_DIR = path.join(os.homedir(), '.claude');
}
const PLUGINS_DIR = path.join(CLAUDE_DIR, 'plugins');
const PLUGIN_DIR = path.join(PLUGINS_DIR, PLUGIN_NAME);
const SKILLS_DIR = path.join(CLAUDE_DIR, 'skills');
const SKILL_DIR = path.join(SKILLS_DIR, PLUGIN_NAME);
const SETTINGS_FILE = path.join(CLAUDE_DIR, 'settings.json');

function detectClaude() {
  // Check if Claude Code is installed
  // Check for settings.json or config.json
  const settingsFile = path.join(CLAUDE_DIR, 'settings.json');
  const configFile = path.join(CLAUDE_DIR, 'config.json');

  if (!fs.existsSync(settingsFile) && !fs.existsSync(configFile)) {
    console.error('❌ Claude Code not found. Please install Claude Code first.');
    console.error('   Visit: https://claude.ai/code');
    process.exit(1);
  }
  console.log('✅ Claude Code detected');
}

function createPluginDirectory() {
  if (!fs.existsSync(PLUGINS_DIR)) {
    fs.mkdirSync(PLUGINS_DIR, { recursive: true });
  }

  if (fs.existsSync(PLUGIN_DIR)) {
    console.log('⚠️  Hardstop already installed. Updating...');
    fs.rmSync(PLUGIN_DIR, { recursive: true, force: true });
  }

  fs.mkdirSync(PLUGIN_DIR, { recursive: true });
  console.log('✅ Plugin directory created');
}

function copyPluginFiles() {
  // Determine source directory
  // When installed via npm, __dirname points to node_modules/hardstop/bin
  // When run from repo, __dirname points to repo/bin
  const sourceDir = path.dirname(__dirname);

  const filesToCopy = [
    { name: '.claude-plugin', type: 'dir' },
    { name: 'hooks', type: 'dir' },
    { name: 'commands', type: 'dir' },
    { name: 'patterns', type: 'dir' },
    { name: 'LICENSE', type: 'file' },
    { name: 'README.md', type: 'file' },
  ];

  for (const item of filesToCopy) {
    const source = path.join(sourceDir, item.name);
    const dest = path.join(PLUGIN_DIR, item.name);

    if (!fs.existsSync(source)) {
      console.log(`⚠️  Skipping ${item.name} (not found)`);
      continue;
    }

    if (item.type === 'dir') {
      fs.cpSync(source, dest, { recursive: true });
    } else {
      fs.copyFileSync(source, dest);
    }
    console.log(`✅ Copied ${item.name}`);
  }
}

function setExecutablePermissions() {
  if (os.platform() === 'win32') {
    console.log('ℹ️  Windows detected - skipping chmod');
    return;
  }

  const hookFiles = [
    path.join(PLUGIN_DIR, 'hooks', 'pre_tool_use.py'),
    path.join(PLUGIN_DIR, 'hooks', 'pre_read.py'),
  ];

  for (const file of hookFiles) {
    if (fs.existsSync(file)) {
      fs.chmodSync(file, '755');
    }
  }
  console.log('✅ Set executable permissions');
}

function createSkill() {
  if (!fs.existsSync(SKILLS_DIR)) {
    fs.mkdirSync(SKILLS_DIR, { recursive: true });
  }

  if (fs.existsSync(SKILL_DIR)) {
    fs.rmSync(SKILL_DIR, { recursive: true, force: true });
  }

  fs.mkdirSync(SKILL_DIR, { recursive: true });

  // Copy SKILL.md from source if available, otherwise generate inline
  const sourceDir = path.dirname(__dirname);
  const sourceSkill = path.join(sourceDir, 'skills', PLUGIN_NAME, 'SKILL.md');

  if (fs.existsSync(sourceSkill)) {
    // Replace hardcoded ~/.claude/plugins/hs/ paths with actual install location
    let content = fs.readFileSync(sourceSkill, 'utf8');
    content = content.replace(/~\/\.claude\/plugins\/hs\//g, PLUGIN_DIR + '/');
    fs.writeFileSync(path.join(SKILL_DIR, 'SKILL.md'), content, 'utf8');
  } else {
    // Fallback: generate a minimal skill file
    const skillContent = `---
name: hs
version: 1.0.0
description: >
  Hardstop - Pre-execution safety layer control. Use this skill when the user wants to
  enable, disable, check status, skip, or view logs for the Hardstop safety system.
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

- \`/hs\` or \`/hs status\`: \`python ${PLUGIN_DIR}/commands/hs_cmd.py status\`
- \`/hs on\`: \`python ${PLUGIN_DIR}/commands/hs_cmd.py on\`
- \`/hs off\`: \`python ${PLUGIN_DIR}/commands/hs_cmd.py off\`
- \`/hs skip\`: \`python ${PLUGIN_DIR}/commands/hs_cmd.py skip\`
- \`/hs log\`: \`python ${PLUGIN_DIR}/commands/hs_cmd.py log\`
`;
    fs.writeFileSync(path.join(SKILL_DIR, 'SKILL.md'), skillContent, 'utf8');
  }

  console.log('✅ Skill created');
}

function configureHooks() {
  let settings = {};

  if (fs.existsSync(SETTINGS_FILE)) {
    try {
      const content = fs.readFileSync(SETTINGS_FILE, 'utf8').trim();
      settings = content ? JSON.parse(content) : {};
    } catch (e) {
      settings = {};
    }

    // Check if hooks are already configured
    const raw = fs.readFileSync(SETTINGS_FILE, 'utf8');
    if (raw.includes('pre_tool_use.py') && raw.includes('pre_read.py')) {
      console.log('⚠️  Hooks already configured, skipping');
      return;
    }

    // Backup existing settings
    fs.copyFileSync(SETTINGS_FILE, SETTINGS_FILE + '.backup');
    console.log('ℹ️  Backed up settings.json');
  }

  if (!settings.hooks) {
    settings.hooks = {};
  }
  if (!settings.hooks.PreToolUse) {
    settings.hooks.PreToolUse = [];
  }

  const bashHook = path.join(PLUGIN_DIR, 'hooks', 'pre_tool_use.py').replace(/\\/g, '/');
  const readHook = path.join(PLUGIN_DIR, 'hooks', 'pre_read.py').replace(/\\/g, '/');

  settings.hooks.PreToolUse.push({
    matcher: 'Bash',
    hooks: [{
      type: 'command',
      command: `python ${bashHook}`,
      timeout: 30
    }]
  });

  settings.hooks.PreToolUse.push({
    matcher: 'Read',
    hooks: [{
      type: 'command',
      command: `python ${readHook}`,
      timeout: 30
    }]
  });

  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf8');
  console.log('✅ Hooks configured (Bash + Read)');
}

function verifyInstallation() {
  const requiredFiles = [
    '.claude-plugin/plugin.json',
    'hooks/hooks.json',
    'hooks/pre_tool_use.py',
    'hooks/pre_read.py',
    'patterns/dangerous_commands.yaml',
  ];

  let allPresent = true;
  for (const file of requiredFiles) {
    const fullPath = path.join(PLUGIN_DIR, file);
    if (!fs.existsSync(fullPath)) {
      console.error(`❌ Missing: ${file}`);
      allPresent = false;
    }
  }

  if (allPresent) {
    console.log('✅ Installation verified');
  } else {
    console.error('❌ Installation incomplete');
    process.exit(1);
  }
}

function printSuccess() {
  const version = getVersion();
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║  🛡️  Hardstop ${version} installed successfully!          ║
╚═══════════════════════════════════════════════════════════╝

Next steps:
  1. Restart Claude Code (if running)
  2. Test with: /hs status
  3. Read docs: ${PLUGIN_DIR}/README.md

Hardstop will now intercept dangerous commands before execution.
Use '/hs help' to see all available commands.

Features:
  • 262 patterns mapped to MITRE ATT&CK framework
  • Risk scoring system with session tracking
  • Command chain analysis (&&, ||, ;, |)
  • Read tool protection (credential files)
  • Fail-closed by default

Documentation:
  • https://github.com/frmoretto/hardstop
  • ${PLUGIN_DIR}/README.md
`);
}

function getVersion() {
  try {
    const pluginJson = path.join(PLUGIN_DIR, '.claude-plugin', 'plugin.json');
    if (fs.existsSync(pluginJson)) {
      const data = JSON.parse(fs.readFileSync(pluginJson, 'utf8'));
      return data.version || 'unknown';
    }
  } catch (e) {
    // Ignore errors
  }
  return 'v1.4.3';
}

// Main installation flow
function main() {
  // Check for help flag
  if (process.argv.includes('--help') || process.argv.includes('-h')) {
    console.log(`
Hardstop Installer

Usage:
  npx hardstop install    Install Hardstop plugin
  npx hardstop --help     Show this help

Installation:
  Installs Hardstop to: ${CLAUDE_DIR}/plugins/hs
  Requires: Claude Code installed

More info:
  https://github.com/frmoretto/hardstop
`);
    process.exit(0);
  }

  console.log('\n🚀 Installing Hardstop...\n');

  try {
    detectClaude();
    createPluginDirectory();
    copyPluginFiles();
    setExecutablePermissions();
    createSkill();
    configureHooks();
    verifyInstallation();
    printSuccess();
  } catch (error) {
    console.error('❌ Installation failed:', error.message);
    if (process.env.DEBUG) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

main();
