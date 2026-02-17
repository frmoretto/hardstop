---
description: Hardstop - Pre-execution safety layer for shell commands. Shows status and help.
argument-hint: [on|off|skip|status|log|help]
allowed-tools: ["Bash"]
---

# Hardstop Command

Hardstop is a pre-execution safety layer that blocks dangerous shell commands using pattern matching + LLM analysis.

## Context

- State directory: `~/.hardstop/`
- State file: `~/.hardstop/state.json`
- Skip flag: `~/.hardstop/skip_next`
- Audit log: `~/.hardstop/audit.log`

## Your Task

Based on the argument provided (`$ARGUMENTS`), perform the appropriate action:

### If no argument or "help" or "status":
Run this command to show current status:
```bash
python "${CLAUDE_PLUGIN_ROOT}/commands/hs_cmd.py" status
```

### If argument is "on" or "enable":
Use `/on` command instead, or run:
```bash
python "${CLAUDE_PLUGIN_ROOT}/commands/hs_cmd.py" on
```

### If argument is "off" or "disable":
Use `/off` command instead, or run:
```bash
python "${CLAUDE_PLUGIN_ROOT}/commands/hs_cmd.py" off
```

### If argument is "skip" or "bypass":
Use `/skip` command instead, or run:
```bash
python "${CLAUDE_PLUGIN_ROOT}/commands/hs_cmd.py" $ARGUMENTS
```

### If argument is "log" or "logs" or "audit":
Use `/log` command instead, or run:
```bash
python "${CLAUDE_PLUGIN_ROOT}/commands/hs_cmd.py" log
```

## Available Commands

- `/hs` or `/hs status` - Show current status
- `/hs on` - Enable protection
- `/hs off` - Disable protection temporarily
- `/hs skip` - Skip safety check for next command only
- `/hs log` - Show recent audit log entries
- `/hs help` - Show this help

Or use the shorthand commands directly:
- `/on` - Enable protection
- `/off` - Disable protection
- `/skip` - Skip next command
- `/status` - Show status
- `/log` - Show audit log
