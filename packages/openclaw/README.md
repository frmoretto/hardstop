# Hardstop for OpenClaw

Pre-execution safety layer that blocks dangerous shell commands before they run.

> **Status:** In Development (feature branch)

## Overview

Hardstop provides two-layer defense for AI-generated shell commands:

1. **Layer 1: Pattern Matching** — 180+ regex patterns for instant detection (<1ms)
2. **Layer 2: LLM Analysis** — Semantic analysis for edge cases not covered by patterns

**Design Principle:** Fail-closed by default. When in doubt, block.

## Installation

```bash
npm install hardstop-openclaw
```

Add to your OpenClaw config:

```yaml
# ~/.openclaw/config.yaml
plugins:
  - name: hardstop
    package: "hardstop-openclaw"
```

## Configuration

```yaml
plugins:
  - name: hardstop
    package: "hardstop-openclaw"
    config:
      # Block unrecognized commands (fail-closed). Default: true
      strictMode: true

      # Use LLM to analyze edge cases. Default: true
      llmAnalysis: true

      # Maximum operations to skip with /hs skip. Default: 10
      maxSkip: 10

      # Log file location. Default: ~/.hardstop/audit.log
      logPath: "~/.hardstop/audit.log"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `strictMode` | boolean | `true` | Block commands not explicitly recognized as safe |
| `llmAnalysis` | boolean | `true` | Use LLM to analyze commands that don't match patterns |
| `maxSkip` | number | `10` | Maximum commands skippable with `/hs skip N` |
| `logPath` | string | `~/.hardstop/audit.log` | Path to the audit log file |

## Commands

| Command | Description |
|---------|-------------|
| `/hs status` | Show protection status, pattern counts, skip counter |
| `/hs on` | Enable command blocking |
| `/hs off` | Disable command blocking (credential protection remains active) |
| `/hs skip N` | Allow next N commands without checks (max 10) |
| `/hs log` | Show recent audit log entries |
| `/hs help` | Display help information |

## What Gets Blocked

Hardstop blocks 180+ dangerous patterns including:

- **Data Destruction**: `rm -rf /`, `mkfs`, `dd if=/dev/zero`
- **Credential Access**: Reading `.env`, `.ssh/`, AWS credentials
- **System Compromise**: Fork bombs, reverse shells, privilege escalation
- **Network Exfiltration**: Suspicious curl/wget to external hosts
- **macOS-Specific**: Keychain dump, diskutil erase, SIP disable
- **Windows**: `rd /s /q`, registry manipulation, encoded PowerShell
- **Cloud CLI**: AWS S3 delete, GCP project delete, terraform destroy

## Example Behavior

```
User: Delete the temp files
Agent: rm -rf /tmp/*
🛑 Hardstop: Blocked - Recursive delete with wildcard

User: /hs skip 1
✓ Next 1 command(s) will bypass checks

User: Delete the temp files
Agent: rm -rf /tmp/*
✓ Allowed (skip active)
```

## Why OpenClaw + Hardstop?

OpenClaw provides excellent infrastructure security (sandboxing, allowlists, approval workflows), but lacks **runtime pattern-based command blocking**. Hardstop fills this gap:

| OpenClaw Native | Hardstop Adds |
|-----------------|---------------|
| Binary allowlists | 180+ regex patterns |
| Manual approval | Automatic blocking |
| Sandbox isolation | Pre-execution inspection |
| — | LLM edge-case analysis |
| — | Audit logging |
| — | MITRE ATT&CK mapping |

## Skill-Only Mode (Alternative)

For quick setup without the full plugin, copy the skill file:

```bash
mkdir -p ~/.openclaw/workspace/skills/hardstop
cp skills/hardstop/SKILL.md ~/.openclaw/workspace/skills/hardstop/
```

⚠️ **Limitation:** Skill-only mode is advisory. The LLM must choose to follow the rules. For deterministic blocking, use the full plugin.

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Lint
npm run lint
```

## Links

- [Main Hardstop Repository](https://github.com/frmoretto/hardstop)
- [OpenClaw](https://github.com/openclaw/openclaw)
- [Security Audit](https://github.com/frmoretto/hardstop/blob/main/SECURITY.md)

## License

MIT
