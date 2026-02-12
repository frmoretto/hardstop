# hardstop

> Pre-execution safety validation for AI coding agents. Blocks dangerous shell commands before they execute.

## OBJECTIVE

Install and activate HardStop as a safety layer for Claude Code, Claude Desktop, or Cowork. HardStop intercepts shell commands via PreToolUse hooks and validates them against 428 security patterns before execution.

## DONE WHEN

- Running `/hs status` in Claude Code returns protection status as enabled
- A test dangerous command like `rm -rf /` triggers a block response from HardStop
- The hook is registered in `~/.claude/settings.json` (or project-level `.claude/settings.json`)

## TODO

- [ ] Install HardStop for your platform
- [ ] Restart Claude Code / Claude Desktop / Cowork
- [ ] Verify protection is active
- [ ] Test that a dangerous command is caught and blocked

## Installation

### Option 1: npm (Recommended)

```bash
npx hardstop install
```

Or install globally:

```bash
npm install -g hardstop
hardstop install
```

### Option 2: Manual — macOS / Linux

```bash
git clone https://github.com/frmoretto/hardstop.git
cd hardstop
chmod +x install.sh
./install.sh
```

### Option 3: Manual — Windows (PowerShell)

```powershell
git clone https://github.com/frmoretto/hardstop.git
cd hardstop
powershell -ExecutionPolicy Bypass -File install.ps1
```

## What the installer does

1. Copies plugin files to `~/.claude/plugins/hs/`
2. Creates the `/hs` skill at `~/.claude/skills/hs/`
3. Registers PreToolUse and PreRead hooks in `~/.claude/settings.json`
4. Does NOT modify any system files or install system-wide packages

## Verification

After restarting Claude Code / Desktop / Cowork:

```
/hs status
```

Expected: HardStop reports as enabled with pattern count and version.

Test with a dangerous command — ask Claude to run `rm -rf /`. HardStop should intercept and block it before execution.

## Troubleshooting

- If `/hs status` is not recognized, restart Claude Code completely (VS Code: Cmd+Shift+P > "Developer: Reload Window")
- Ensure Python 3.9+ is available in PATH
- Check `~/.claude/settings.json` for hook entries pointing to `~/.claude/plugins/hs/hooks/`
- Check `~/.claude/plugins/hs/hooks/` contains `pre_tool_use.py` and `pre_read.py`

## Uninstall

macOS/Linux: `cd hardstop && ./uninstall.sh`
Windows: `cd hardstop && powershell -ExecutionPolicy Bypass -File uninstall.ps1`

## More information

- Repository: https://github.com/frmoretto/hardstop
- Pattern library (npm): https://www.npmjs.com/package/hardstop-patterns
- Issues: https://github.com/frmoretto/hardstop/issues
