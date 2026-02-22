# Hardstop - Claude Code Project Guide

Pre-execution safety layer for Claude Code. Blocks dangerous shell commands and credential file reads using pattern matching + LLM analysis. Fail-closed design.

## Project structure

```
hooks/              # Python hooks (core safety logic)
  pre_tool_use.py   #   Bash command interception
  pre_read.py       #   File read interception
  pattern_loader.py #   YAML pattern loading
  risk_scoring.py   #   MITRE ATT&CK risk scoring
  session_tracker.py#   Session state tracking
commands/           # Slash commands (markdown + Python)
  hs.md             #   Main /hs command router
  hs_cmd.py         #   Python backend for all commands
  skip.md           #   /skip bypass command
  on.md, off.md     #   Enable/disable commands
  status.md, log.md #   Status and audit log commands
patterns/           # YAML pattern definitions
  dangerous_commands.yaml
  dangerous_reads.yaml
  safe_commands.yaml
  safe_reads.yaml
  sensitive_reads.yaml
  schema.json       #   JSON schema for pattern validation
skills/hs/SKILL.md  # LLM-level safety skill (for platforms without hooks)
tests/              # pytest test suite
bin/                # npm install scripts
.claude-plugin/     # Claude plugin metadata
```

## Versioning

There are two independent version numbers:

- **Package version** (e.g. `1.4.4`) — the plugin/npm release. Uses semver with patch bumps. Lives in `package.json`, `plugin.json`, and `marketplace.json`. Bumped on every release.
- **Skill version** (e.g. `1.4`) — the LLM skill spec in `skills/hs/SKILL.md`. Uses major.minor only. Bumped only when the safety protocol, risk levels, or block lists change meaningfully. A patch-level bugfix in the plugin does NOT require a skill version bump.

### Skill file copies

The skill exists in 4 locations for different platforms:

| Path | Platform | Frontmatter |
|------|----------|-------------|
| `skills/hs/SKILL.md` | Canonical (agentskills.io) | Full: `name`, `version`, `description`, `author`, `license`, `triggers` |
| `.claude/skills/hs/SKILL.md` | Claude Desktop/Code | Reduced: `name`, `description` only |
| `.codex/skills/hs/SKILL.md` | OpenAI Codex (Claude Code) | Reduced: `name`, `description`, `license` |
| `.github/skills/hs/SKILL.md` | GitHub Copilot (Claude Code) | Reduced: `name`, `description`, `license` |

The body content is identical across all copies. When updating the skill, edit the canonical `skills/hs/SKILL.md` first, then sync to the other 3.

**Claude Code skill frontmatter constraints:** supported attributes are `argument-hint`, `compatibility`, `description`, `disable-model-invocation`, `license`, `metadata`, `name`, `user-invokable`. The fields `version`, `author`, and `triggers` are NOT supported and produce IDE warnings — omit them from all `.claude/`, `.codex/`, and `.github/` copies.

## Version bump checklist

**All 3 files must be updated together on every release:**

1. `package.json` — root (npm reads this for `npm publish`)
2. `.claude-plugin/plugin.json` — Claude plugin registry
3. `.claude-plugin/marketplace.json` — marketplace catalog

Also update:
4. `CHANGELOG.md` — add entry at top with `## [x.y.z] - YYYY-MM-DD`
5. Git tag — `git tag vX.Y.Z && git push origin vX.Y.Z`

## Running tests

```bash
# Activate venv first
.venv/Scripts/activate   # Windows
source .venv/bin/activate # Unix

# Run tests with coverage
pytest tests/ --cov=hooks --cov-report=term

# Run a specific test file
pytest tests/test_hook.py
```

Dependencies: `pip install -r requirements-dev.txt` (pytest, pytest-cov, pyyaml, jsonschema)

## CI

- **test.yml** — runs pytest on push to `main`/`develop` and PRs to `main`. Matrix: Python 3.9-3.12 on ubuntu, windows, macos.
- **version-check.yml** — validates version sync between `plugin.json` and `marketplace.json` on PRs. Note: does NOT check `package.json` (manual step).
- **release.yml** — triggers on `v*` tags. Creates GitHub Release with Sigstore build provenance attestation and attaches the npm tarball.

## Commit conventions

Follow conventional commits:
- `fix(scope):` for bug fixes
- `feat(scope):` for new features
- `chore:` for version bumps, maintenance
- `docs:` for documentation only

## Release workflow

1. Bump version in all 3 files (see checklist above)
2. Update `CHANGELOG.md`
3. Commit: `chore: bump vX.Y.Z`
4. Push: `git push origin main`
5. Publish to npm — **do this manually in a terminal** (not via Claude Code):
   - npm publish requires 2FA OTP; the easiest path is `npm publish` in your terminal with your authenticator app open, or publish via the npm website with your access token
   - Claude Code cannot interactively handle the OTP prompt
6. `git tag vX.Y.Z && git push origin vX.Y.Z` — this triggers `release.yml` which creates the GitHub Release automatically

## Key design decisions

- **Fail-closed**: if the hook errors, commands are blocked (not allowed)
- **Pattern-based + LLM**: YAML patterns for deterministic checks, LLM skill for awareness
- **State lives in `~/.hardstop/`**: state.json, skip_next, audit.log (not in repo)
- **Cross-platform**: hooks are Python, install scripts support bash + PowerShell

## Related files

- `AGENTS.md` — universal agent discovery file (for non-Claude AI agents)
- `AUDIT.md` — security audit guide for reviewers
- `SECURITY.md` — security policy and design docs
- `PRIVACY.md` — privacy policy

## Adding patterns

Pattern YAML files live in `patterns/`. Validated against `patterns/schema.json`.
After editing patterns, run `pytest tests/test_patterns.py` to verify.
