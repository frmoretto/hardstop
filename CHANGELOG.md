# Changelog

All notable changes to Hardstop will be documented in this file.

## [1.3.3] - 2026-01-31

### Fixed: Test Suite & Marketplace Sync

Synchronized test suite with v1.3.1 JSON output changes and updated marketplace.json.

### Changed
- **marketplace.json**: Updated version 1.0.0 → 1.3.2, added Read and PowerShell hooks
- **test_hook.py**: Tests now use JSON parsing instead of exit code 2 assertions
- **test_read_hook.py**: Tests updated for JSON output and read-only skip checks

### Technical Details
- Tests now check `permissionDecision: "deny"` in JSON instead of exit code 2
- `is_skip_enabled()` is now read-only (multi-skip compatibility)
- Test count: 158 tests, all passing

---

## [1.3.2] - 2026-01-21

### New Feature: Multi-Skip

Skip multiple commands at once with `/hs skip <count>`.

**Usage:**
- `/hs skip` — Skip 1 command (unchanged)
- `/hs skip 3` — Skip next 3 commands
- `/hs skip 10` — Skip next 10 commands (max: 100)

**Status output:**
```
Hardstop v1.3.2
  Status:      🟢 Enabled
  Skip next:   3 commands
```

### Changed
- `hs_cmd.py`: Accept optional count argument for skip command
- `pre_tool_use.py`: `decrement_skip()` and `get_skip_count()` functions
- `pre_read.py`: Same skip counter logic for Read tool
- Status command now shows remaining skip count
- Backward compatible with old skip file format

---

## [1.3.1] - 2026-01-21

### Fixed: VS Code Extension Chat Restart

Changed blocking mechanism from exit code 2 to JSON output with `permissionDecision: "deny"`.

**Problem:** Exit code 2 caused VS Code extension to treat blocks as session errors and restart the chat.

**Solution:** Use structured JSON output (Claude Code documented API):
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "🛑 BLOCKED: reason..."
  }
}
```

### Changed
- `pre_tool_use.py`: `block_command()`, `check_uninstall_script()` now use JSON output
- `pre_read.py`: `block()`, `block_error()` now use JSON output
- Both hooks now exit with code 0 (success) and use JSON for allow/deny decisions

---

## [1.3.0] - 2026-01-20

### New Feature: Read Tool Protection

Hardstop now monitors the Claude Code `Read` tool to prevent AI from accessing credential files.

**DANGEROUS (Blocked):**
- SSH keys: `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, etc.
- Cloud credentials: `~/.aws/credentials`, `~/.config/gcloud/credentials.db`, `~/.azure/credentials`
- Environment files: `.env`, `.env.local`, `.env.production`
- Docker/Kubernetes: `~/.docker/config.json`, `~/.kube/config`
- Database credentials: `~/.pgpass`, `~/.my.cnf`
- Package managers: `~/.npmrc`, `~/.pypirc`

**SENSITIVE (Warned):**
- Generic configs: `config.json`, `settings.json`
- Files with "password", "secret", "token", "apikey" in name

**SAFE (Allowed):**
- Source code: `.py`, `.js`, `.ts`, `.go`, etc.
- Documentation: `README.md`, `CHANGELOG.md`, `LICENSE`
- Config templates: `.env.example`, `.env.template`
- Package manifests: `package.json`, `pyproject.toml`

### Added
- `hooks/pre_read.py` — New hook for Read tool interception
- Read matcher in `hooks/hooks.json`
- Read hook configuration in install scripts (`install.sh`, `install.ps1`)
- Read hook removal in uninstall scripts (`uninstall.sh`, `uninstall.ps1`)
- Section 9 in SKILL.md documenting Read protection
- Updated Quick Reference Card with Read tool guidance
- Comprehensive test suite for Read protection (`tests/test_read_hook.py`)

### Fixed
- Uninstallers now remove both Bash and Read hooks (backward compatible with v1.0-v1.2)

### Changed
- Updated skill description to include "FILE READ" trigger
- Updated SKILL.md version to 1.3
- Updated plugin.json version to 1.3.0
- Updated pre_tool_use.py version to 1.3.0

---

## [1.2.0] - 2026-01-20

### New Patterns (~60 added)
- **Shell wrappers:** `bash -c`, `sh -c`, `sudo bash -c`, `xargs`, `find -exec`
- **Cloud CLI:** AWS (S3, EC2, RDS, CloudFormation), GCP (gcloud), Firebase, Kubernetes (kubectl, helm)
- **Infrastructure:** Terraform `destroy`, Pulumi `destroy`, Docker `prune`
- **Database CLI:** Redis (`FLUSHALL`), MongoDB (`dropDatabase`), PostgreSQL (`dropdb`), MySQL (`mysqladmin drop`)
- **Platform CLI:** Vercel, Netlify, Heroku, Fly.io, GitHub (`gh repo delete`), npm (`unpublish`)
- **SQL:** `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`, `DELETE FROM` without WHERE

### Fixed (False Positives)
- Removed alias patterns (blocked legitimate aliases like `alias ls='ls --color'`)
- Made `find -delete` path-specific (only blocks on `~`, `/home`, `/`, `/etc`, `/usr`, `/var`)

### Stats
- Total dangerous patterns: 137
- Total safe patterns: 66

---

## [1.1.0] - 2026-01-18

### Multi-Platform Skill Distribution
- Added skill files for Claude.ai Projects, Codex, GitHub Copilot
- Added `AGENTS.md` universal discovery file (LLM-readable agent capabilities)
- Added `marketplace.json` for plugin registry integration
- Added `dist/hardstop.skill` for Claude.ai upload

### Package Manager Safety
- Added Package Manager Force Operations to INSTANT BLOCK list
- Added new Section 4: Package Manager Safety with dpkg/rpm flag reference
- Added error suppression patterns (`2>/dev/null`, `|| true`) as risk escalators
- Added package info commands (`dpkg -l`, `apt list`) to SAFE list

---

## [1.0.0] - 2025-01-17

First public release.

### Core Features
- **Two-layer defense** — Pattern matching (instant) + LLM analysis (semantic)
- **Fail-closed design** — If safety check fails, command is blocked (not allowed)
- **Cross-platform** — Unix (Bash) + Windows (PowerShell) pattern detection
- **Command chaining** — Analyzes all parts of piped/chained commands (`&&`, `||`, `;`, `|`)
- **Audit logging** — All decisions logged to `~/.hardstop/audit.log`
- **Skill command** — `/hs` for status, on/off, skip, and log viewing

### Pattern Coverage
- Home/root deletion, fork bombs, reverse shells
- Credential exfiltration (`.ssh`, `.aws`, `.config`)
- Disk destruction, encoded payloads, pipe-to-shell
- Windows: Registry manipulation, LOLBins, PowerShell download cradles

### Installation
- `install.sh` for macOS/Linux
- `install.ps1` for Windows (uses Python for reliable JSON handling)
- `uninstall.sh` and `uninstall.ps1` for clean removal
- Automatic hook configuration in `~/.claude/settings.json`
- Skill installation to `~/.claude/skills/hs/`

### Reliability
- Atomic state writes (prevents corruption)
- Atomic skip flag (prevents race conditions)
- Windows CLI detection (`claude.cmd` via `cmd /c`)
- Full-command matching for safe patterns (prevents substring bypass)
- Path expansion at install time (fixes `~` not working on Windows)

---

## Development History (Pre-release)

The following documents the development process leading to v1.0.0.

### 2025-01-17 — Final Polish

**Bug Fixes:**
- Fixed PowerShell JSON handling (ConvertFrom-Json fails on nested objects; now uses Python)
- Fixed path expansion (`~` and `%USERPROFILE%` don't expand in Windows hook commands)
- Fixed skill directory name (`hs` not `hs-hardstop-plugin` — directory name = command name)
- Fixed double naming bug (`hs-hardstop-plugin-hardstop-plugin`)

**Improvements:**
- Added uninstall scripts (`uninstall.ps1`, `uninstall.sh`)
- Added uninstall detection in hook with friendly confirmation message
- Added strong restart warnings for VS Code, CLI, and Cowork users
- Added beta disclaimer and feedback call-to-action
- Cleaned up `/hardstop` and `/hard` alias references (kept only `/hs`)

**Lessons Learned:**
1. Directory name = skill command name (not the `name` field in SKILL.md)
2. `aliases` field in SKILL.md doesn't create additional slash commands
3. `~` doesn't expand in Windows hook commands — must use full paths
4. `%USERPROFILE%` also doesn't expand — use Python `os.path.expanduser()`
5. PowerShell's `ConvertFrom-Json | ConvertTo-Json` breaks nested objects
6. Hooks are snapshotted at startup — restart required after changes
7. Hardstop can block its own uninstall — need skip or custom detection

### 2025-01-16 — Structure Refactor

- Changed plugin name from "hardstop" to "hs" in plugin.json
- Improved Windows console encoding handling in hs_cmd.py
- Added debug logging for hook invocation
- Created command documentation files (`hs.md`, `on.md`, `off.md`, `skip.md`, `status.md`, `log.md`)
- Updated installation scripts for new structure

### 2025-01-15 — Initial Development

- Implemented two-layer defense (pattern + LLM)
- Created pattern databases for Unix and Windows
- Implemented fail-closed error handling
- Added command chaining analysis
- Created `/hs` skill interface
- Added audit logging system
- Wrote test suite (82 tests)

---

## License

CC BY 4.0 — Francesco Marinoni Moretto
