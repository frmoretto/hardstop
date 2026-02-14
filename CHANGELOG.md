# Changelog

All notable changes to Hardstop will be documented in this file.

## [1.4.3] - 2026-02-14

### Growth Features

Adds GitHub star calls-to-action at key user touchpoints.

### Added
- **bin/postinstall.js**: Post-install message with GitHub star CTA
  - Shows after `npm install hardstop`
  - Welcomes users and directs to quick start
- **hooks/pre_tool_use.py**: First-block celebration message
  - Shows once per installation after first blocked command
  - "🎉 Hardstop just protected you!" with star link
- **commands/hs_cmd.py**: GitHub star CTA in `/hs status` output
  - Reminds users to star when checking status
- **README.md**: GitHub stars badge and prominent CTA
  - Social proof badge showing current star count
  - "👉 Star on GitHub if Hardstop keeps you safe!"

---

## [1.4.2] - 2026-02-14

### UX Workflow Enhancement & Ecosystem Cross-Links

Improves the blocked command workflow and adds ecosystem discoverability.

### Added
- **hooks/pre_tool_use.py**: `suggestedAction` field in JSON output when blocking commands
  - Provides structured workflow guidance: `{workflow: "bypass", command: "/hs skip", thenRetry: true, userPrompt: "..."}`
  - Enables Claude to automatically suggest the bypass workflow when commands are blocked
- **skills/hs/SKILL.md**: "WHEN COMMANDS ARE BLOCKED" section with explicit 5-step workflow
  - STOP → EXPLAIN → ASK → IF YES: Run /hs skip first, then retry → IF NO: Suggest safer alternative
  - Trains Claude on the proper bypass workflow pattern
- **README.md, package.json**: Ecosystem cross-links to hardstop-patterns package
- **install.md**: Enhanced pattern library reference with both npm and GitHub links

### Fixed
- **hooks/pre_tool_use.py**: HardStop's own commands (`/hs skip`, `/hs status`, etc.) now bypass the safety hook (closes #2)
  - Prevents infinite recursion when Claude tries to run HardStop commands
  - Self-exemption via `_is_hardstop_command()` function

### Changed
- **Git tags**: Corrected v1.4.1 tag to point to actual npm 1.4.1 publish (fa06e22)
  - Previously pointed to ecosystem cross-links commit (bc31ba4)
  - Aligns git history with published npm package

---

## [1.4.1] - 2026-02-12

### Agent Discovery Enhancement

Adds install.md to npm package for better agent discoverability.

### Changed
- **package.json**: Added `install.md` to npm package files
  - Enables agent discovery systems to find installation instructions
  - Improves package metadata for AI-assisted discovery

---

## [1.4.0] - 2026-02-11

### Installation & Naming Standardization

Major update to streamline installation and standardize naming conventions.

### Changed
- **BREAKING**: Plugin and skill directories now use `hs` instead of `hardstop`
  - Plugin: `~/.claude/plugins/hs/` (was `~/.claude/plugins/hardstop/`)
  - Skill: `~/.claude/skills/hs/` (was `~/.claude/skills/hardstop/`)
  - Slash command remains `/hs` (unchanged)
- **bin/install.js**: Now handles complete installation (plugin + skill + hooks)
  - Previously only installed plugin files
  - Now also creates skill at `~/.claude/skills/hs/SKILL.md`
  - Now also configures hooks in `~/.claude/settings.json`
- **package.json**: Added `skills/` to npm package files
- All repository skill directories renamed: `.claude/skills/hs/`, `.codex/skills/hs/`, `.github/skills/hs/`, `skills/hs/`

### Migration
- Users upgrading from 1.3.x should uninstall first: `powershell .\uninstall.ps1` or `bash uninstall.sh`
- Then reinstall: `npx hardstop install`
- Or use the installer scripts: `powershell .\install.ps1` or `bash install.sh`

---

## [1.3.6] - 2026-01-31

### macOS Platform Coverage

Adds comprehensive macOS-specific dangerous patterns and safe patterns for better platform coverage.

### Added
- **pre_tool_use.py**: 35 macOS dangerous patterns
  - Disk utility operations (diskutil erase, partition, zeroDisk)
  - Keychain access (security delete-keychain, dump-keychain, find-*-password -w)
  - Time Machine manipulation (tmutil delete, disable, deletelocalsnapshots)
  - Directory services (dscl delete user/group, append admin)
  - System security (spctl --master-disable, csrutil disable, nvram)
  - Privacy database (TCC.db access, tccutil reset)
  - Persistence mechanisms (LaunchDaemons/LaunchAgents)
- **pre_tool_use.py**: 11 macOS safe patterns (diskutil list/info, sw_vers, defaults read, etc.)
- **pre_read.py**: 6 macOS credential path patterns (Keychains, TCC.db, Chrome/Firefox passwords, authorization, dslocal)
- **tests/test_macos_patterns.py**: 46 new tests for macOS patterns

### Technical Details
- Pattern count: 137 → ~180 patterns
- Test count: 167 → 213 tests

---

## [1.3.5] - 2026-01-31

### Phase 1 Security Audit Fixes

Addresses security audit requirements for "Safe to Install" rating.

### Added
- **AUDIT.md**: Comprehensive security audit guide for independent reviewers
- **README.md**: "Verify Before You Trust" section with GitIngest link and audit prompt
- **README.md**: "Known Limitations" section documenting pattern-based detection limits
- **README.md**: SKILL.md RAG integration warning
- **README.md**: Link to AUDIT.md for professional auditors
- **SECURITY.md**: LLM Analysis Layer documentation (prompt, parsing, fail-closed behavior)
- **SECURITY.md**: Updated supported versions table

### Changed
- **`/hs off`**: Now shows "Credential file protection (Read hook) remains active"
- **`/hs skip`**: Max reduced from 100 → 10 (hardened security)

### Technical Details
- Test count: 167 tests, all passing

---

## [1.3.4] - 2026-01-31

### Fixed: Chained Command Handling

Safe chained commands like `cd /tmp && git push` now fast-path through pattern matching instead of going to LLM analysis (which could incorrectly block them).

### Changed
- **is_all_safe()**: Now splits chained commands and checks each part individually
- **cd pattern**: Added to safe patterns with command substitution blocking
- **LLM prompt**: Improved to explicitly allow git, npm, docker and other dev tools

### Security
- Defense-in-depth: Added dangerous pattern for `cd` with command substitution
- `cd $(cmd)` and `cd \`cmd\`` are blocked by both safe pattern exclusion AND dangerous pattern detection

### Technical Details
- `cd "path" && git push` → fast-path ALLOW (both parts match safe patterns)
- `cd $(rm -rf /) && git push` → BLOCK (dangerous pattern catches command substitution)
- Test count: 166 tests, all passing

---

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
