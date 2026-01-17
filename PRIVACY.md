# Privacy Policy

**Hardstop** is a local-only Claude Code plugin. This document describes what data it collects and how it's handled.

## Data Collection

### What Hardstop Collects

Hardstop only processes and stores data locally on your machine:

| Data | Purpose | Storage |
|------|---------|---------|
| Command text | Safety analysis | Logged to `~/.hardstop/audit.log` |
| Working directory | Context for analysis | Logged to audit.log |
| Verdict (ALLOW/BLOCK) | Decision record | Logged to audit.log |
| Timestamp | Audit trail | Logged to audit.log |

### What Hardstop Does NOT Collect

- No personal information
- No conversation history
- No API keys or credentials
- No telemetry or analytics
- No data sent to external servers

## Data Storage

All data is stored locally in `~/.hardstop/`:

```
~/.hardstop/
├── state.json    # Plugin enabled/disabled state
├── skip_next     # Temporary one-time bypass flag
└── audit.log     # Command decision log (JSON-lines)
```

## Data Transmission

**Hardstop sends no data to external servers.**

The only network activity is the optional LLM analysis layer, which uses the local Claude CLI (`claude --print`). This runs within your existing Claude subscription and is subject to Anthropic's privacy policy.

## Data Retention

- `audit.log` grows over time as commands are analyzed
- You can delete `~/.hardstop/` at any time to remove all stored data
- No automatic data expiration or cleanup

## Third-Party Services

Hardstop uses:
- **Claude CLI** (optional) — For LLM-based semantic analysis of edge cases
- No other third-party services

## Your Rights

You can:
- View all stored data: `cat ~/.hardstop/audit.log`
- Delete all data: `rm -rf ~/.hardstop/`
- Disable logging: Not currently supported (audit log is always written)

## Changes to This Policy

Updates will be documented in the repository changelog.

## Contact

For privacy questions: contact@clarity-gate.org

---

*Last updated: 2025-01-17*
