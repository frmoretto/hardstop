# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Hardstop, please report it responsibly:

**Email:** security@clarity-gate.org

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

**Response time:** I aim to respond within 48 hours and will work with you to understand and address the issue.

## Security Design

Hardstop is designed with security as a core principle:

### Fail-Closed Architecture

If any part of the safety check fails (timeout, parse error, missing CLI), the command is **blocked**, not allowed. This ensures that broken installations don't silently permit dangerous operations.

### Local-Only Processing

- All pattern matching runs locally
- No external API calls (except optional Claude CLI)
- No data exfiltration possible
- No network dependencies for core functionality

### Minimal Permissions

Hardstop only:
- Reads command text from hook input
- Writes to `~/.hardstop/` directory
- Optionally invokes local Claude CLI

It does NOT:
- Execute arbitrary code
- Modify system files
- Access credentials
- Read conversation history

## LLM Analysis Layer (Layer 2)

When a command doesn't match known safe or dangerous patterns, Hardstop invokes Claude CLI for semantic analysis.

### How It Works

1. **Invocation:** `claude --print --model haiku` with the command and working directory
2. **Timeout:** 15 seconds (fail-closed on timeout)
3. **Response format:** JSON with `verdict` (ALLOW/BLOCK) and `reason`

### Prompt Structure

The exact prompt is in [`hooks/pre_tool_use.py`](hooks/pre_tool_use.py) (search for `LLM_PROMPT`). It instructs the LLM to:
- Block: credential access, data exfiltration, disk destruction, encoded payloads, persistence mechanisms
- Allow: git operations, package managers, build tools, read-only commands

### Fail-Closed Behavior

| Condition | Result |
|-----------|--------|
| Claude CLI not found | BLOCK |
| Timeout (>15s) | BLOCK |
| Invalid JSON response | BLOCK |
| CLI error (non-zero exit) | BLOCK |
| Unparseable verdict | BLOCK |

### Response Parsing

1. Try JSON extraction (handles markdown fencing)
2. Fallback to keyword detection ("BLOCK" or "ALLOW" in response)
3. If neither found: BLOCK (fail-closed)

---

## Known Limitations

1. **Pattern Evasion:** Sophisticated obfuscation may bypass regex patterns. The LLM layer provides defense-in-depth.

2. **LLM Dependency:** Layer 2 analysis requires Claude CLI. Without it, only pattern matching is available.

3. **No Confirmation Flow:** Hardstop provides binary ALLOW/BLOCK decisions, not "explain and confirm" dialogs.

4. **Secrets in Code:** API keys hardcoded in source files (`.py`, `.js`, etc.) are not detected—use environment variables instead.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.3.x   | ✅ Yes (current) |
| 1.2.x   | ⚠️ Security fixes only |
| 1.0.x-1.1.x | ❌ Upgrade recommended |

## Security Updates

Security fixes will be released as patch versions (e.g., 1.0.1) and documented in the changelog.
