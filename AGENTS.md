# AGENTS.md - Hardstop

> Universal discovery file for AI agents and coding assistants.

## What This Repository Does

**Hardstop** is a pre-execution safety system for AI-generated shell commands and file reads. It acts as a fail-closed verification layer, blocking dangerous patterns before they execute.

**Core Question:** "If this action goes wrong, can the user recover?"

**Three-layer defense:**
- **Pattern matching** — Instant regex-based detection of known dangerous patterns
- **LLM analysis** — Semantic analysis for edge cases and novel threats
- **Read protection** — Blocks reading credential files (.ssh, .aws, .env, etc.)

## Quick Start for Agents

### 1. Load the Skill

The main skill file is at: `skills/hs/SKILL.md`

```
Read: skills/hs/SKILL.md
```

### 2. Understand the Components

| Component | Purpose | Location |
|-----------|---------|----------|
| Safety Skill | Pre-execution checklist for LLMs | `skills/hs/SKILL.md` |
| Bash Hook | Deterministic command blocking | `hooks/pre_tool_use.py` |
| Read Hook | Credential file read blocking | `hooks/pre_read.py` |
| CLI Commands | Plugin control (`/hs on`, `/hs status`) | `commands/hs_cmd.py` |

### 3. Trigger Phrases

Use any of these to activate Hardstop awareness:
- "hardstop"
- "safety check"
- "pre-execution check"
- "is this command safe"
- "check command safety"

## Repository Structure

```
hardstop/
├── skills/hs/              # Canonical skill (agentskills.io compliant)
│   └── SKILL.md                  # v1.0 skill definition
├── .claude/skills/hs/      # Claude.ai format (minimal frontmatter)
│   └── SKILL.md
├── .codex/skills/hs/       # OpenAI Codex (agentskills.io format)
│   └── SKILL.md
├── .github/skills/hs/      # GitHub Copilot (agentskills.io format)
│   └── SKILL.md
├── hooks/                        # Plugin hooks
│   ├── pre_tool_use.py           # PreToolUse hook for command blocking
│   └── pre_read.py               # PreToolUse hook for read blocking
├── commands/                     # CLI command handlers
│   └── hs_cmd.py                 # /hs command implementation
├── .claude-plugin/               # Claude Code marketplace
│   └── marketplace.json
├── install.ps1                   # Windows installer
├── install.sh                    # Unix installer
├── AGENTS.md                     # This file
├── AUDIT.md                      # Security audit guide for reviewers
├── SECURITY.md                   # Security policy and design
└── README.md                     # User documentation
```

## Platform-Specific Locations

| Platform | Skill Location | Format |
|----------|----------------|--------|
| Claude Desktop/Code | `.claude/skills/hs/` | Minimal (`name`, `description` only) |
| OpenAI Codex | `.codex/skills/hs/` | agentskills.io (full) |
| GitHub Copilot | `.github/skills/hs/` | agentskills.io (full) |
| Universal (canonical) | `skills/hs/` | agentskills.io (full) |

## Key Concepts

### Instant Block Patterns

Commands that are blocked immediately, no exceptions:

**Unix/Linux/macOS:**
- `rm -rf ~/` — Home directory deletion
- `rm -rf /` — System destruction
- Fork bombs, reverse shells
- Credential exfiltration (`curl -d @~/.ssh/`)
- Disk destruction (`dd of=/dev/sda`, `mkfs`)

**Read Protection (v1.3):**
- SSH keys (`~/.ssh/id_rsa`, `~/.ssh/id_ed25519`)
- Cloud credentials (`~/.aws/credentials`, `~/.config/gcloud/`)
- Environment files (`.env`, `.env.local`, `.env.production`)
- Docker/Kubernetes configs (`~/.docker/config.json`, `~/.kube/config`)

**Windows:**
- `rd /s /q C:\` — Drive deletion
- `format C:` — Drive formatting
- Registry manipulation (`reg delete HKLM`)
- Encoded PowerShell payloads
- Credential theft tools (mimikatz)
- Privilege escalation (`net localgroup administrators /add`)

### Risk Levels

| Level | Action | Example |
|-------|--------|---------|
| SAFE | Proceed silently | `ls`, `git status`, `rm -rf node_modules` |
| RISKY | Explain + confirm | `rm -rf [dir]`, `pip install`, `git push --force` |
| DANGEROUS | Present options + wait | `sudo rm`, `~/.ssh` access, system paths |
| BLOCK | Immediate stop | Patterns in block list |

### Fail-Closed Design

If the safety check fails for any reason:
- CLI unavailable → BLOCK
- Timeout → BLOCK
- Parse error → BLOCK

This ensures safety check failures don't silently allow dangerous commands.

## Security Verification

For agents performing security assessments of this plugin:

| Document | Purpose |
|----------|---------|
| `AUDIT.md` | Step-by-step audit guide with grep commands and test cases |
| `SECURITY.md` | Security policy, LLM layer documentation, known limitations |
| `README.md#verify-before-you-trust` | GitIngest link and audit prompt |

**Key verification points:**
- No network calls except local `claude` CLI
- All state files in `~/.hardstop/` only
- `FAIL_CLOSED = True` in both hook files
- Skip mechanism bounded to max 10 operations

## For Plugin Users (Claude Code)

Install with:

**Windows:**
```powershell
git clone https://github.com/frmoretto/hardstop.git
cd hardstop
powershell -ExecutionPolicy Bypass -File install.ps1
```

**macOS/Linux:**
```bash
git clone https://github.com/frmoretto/hardstop.git && cd hardstop && ./install.sh
```

Then restart Claude Code and verify with `/hs status`.

## For Skill Users (Claude.ai/Desktop)

Copy `skills/hs/SKILL.md` (or `.claude/skills/hs/SKILL.md`) to your Project's knowledge base.

## Related Projects

| Project | Purpose | URL |
|---------|---------|-----|
| Clarity Gate | Pre-ingestion document verification | github.com/frmoretto/clarity-gate |
| Memory Trail | Decision tracking and confidence protocols | (coming soon) |

## License

CC-BY-4.0

## Author

Francesco Marinoni Moretto
