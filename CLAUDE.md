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

GitHub Actions runs tests on push to `main`/`develop` and on PRs to `main`.
Matrix: Python 3.9-3.12 on ubuntu, windows, macos.
See `.github/workflows/test.yml`.

## Commit conventions

Follow conventional commits:
- `fix(scope):` for bug fixes
- `feat(scope):` for new features
- `chore:` for version bumps, maintenance
- `docs:` for documentation only

## Publishing

```bash
npm publish
```

Publishes to npm as `hardstop`. Make sure version is bumped in all 3 files first (see checklist above).

## Key design decisions

- **Fail-closed**: if the hook errors, commands are blocked (not allowed)
- **Pattern-based + LLM**: YAML patterns for deterministic checks, LLM skill for awareness
- **State lives in `~/.hardstop/`**: state.json, skip_next, audit.log (not in repo)
- **Cross-platform**: hooks are Python, install scripts support bash + PowerShell
