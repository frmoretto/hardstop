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

## Known Limitations

1. **Pattern Evasion:** Sophisticated obfuscation may bypass regex patterns. The LLM layer provides defense-in-depth.

2. **LLM Dependency:** Layer 2 analysis requires Claude CLI. Without it, only pattern matching is available.

3. **No Confirmation Flow:** Hardstop provides binary ALLOW/BLOCK decisions, not "explain and confirm" dialogs.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Security Updates

Security fixes will be released as patch versions (e.g., 1.0.1) and documented in the changelog.
