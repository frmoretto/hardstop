/**
 * LLM-based command analysis for edge cases
 * Layer 2 of Hardstop's two-layer defense
 */

// Placeholder types until @openclaw/sdk is available
interface OpenClawAPI {
  completion: (opts: CompletionOpts) => Promise<string>;
  logger: { warn: (msg: string) => void };
}

interface CompletionOpts {
  model: string;
  prompt: string;
  maxTokens: number;
  timeout: number;
}

const ANALYSIS_PROMPT = `You are a security analyzer for shell commands. Evaluate the following command for safety.

Command: {command}

Analyze for these risks:
1. Data destruction (rm, dd, mkfs, format)
2. Credential access (.env, .ssh, .aws, passwords)
3. Network exfiltration (curl/wget with sensitive data)
4. Privilege escalation (sudo, chmod SUID)
5. System compromise (reverse shells, malware download)
6. Irreversible operations

Respond with ONLY valid JSON (no markdown, no explanation):
{
  "safe": true or false,
  "reason": "brief one-line explanation",
  "severity": "critical" or "high" or "medium" or "low" or "none"
}`;

export interface AnalysisResult {
  block: boolean;
  reason: string;
  severity?: string;
}

/**
 * Analyze a command using LLM for edge cases not covered by patterns
 * @param api OpenClaw API instance
 * @param command The command to analyze
 * @returns Analysis result with block decision and reason
 */
export async function analyzeWithLLM(
  api: OpenClawAPI,
  command: string
): Promise<AnalysisResult> {
  try {
    const response = await api.completion({
      model: "claude-3-haiku", // Fast, cheap for analysis
      prompt: ANALYSIS_PROMPT.replace("{command}", command),
      maxTokens: 150,
      timeout: 5000
    });

    // Parse JSON response
    const result = JSON.parse(response.trim());

    return {
      block: !result.safe,
      reason: result.reason || "LLM analysis flagged as unsafe",
      severity: result.severity
    };
  } catch (error) {
    // Fail closed - if LLM analysis fails, block the command
    api.logger.warn(`[hardstop] LLM analysis failed: ${error}`);
    return {
      block: true,
      reason: "LLM analysis failed - blocking for safety (fail-closed)"
    };
  }
}

/**
 * Analyze a command with custom prompt (for advanced use cases)
 * @param api OpenClaw API instance
 * @param command The command to analyze
 * @param customPrompt Custom analysis prompt
 * @returns Analysis result
 */
export async function analyzeWithCustomPrompt(
  api: OpenClawAPI,
  command: string,
  customPrompt: string
): Promise<AnalysisResult> {
  try {
    const response = await api.completion({
      model: "claude-3-haiku",
      prompt: customPrompt.replace("{command}", command),
      maxTokens: 150,
      timeout: 5000
    });

    const result = JSON.parse(response.trim());

    return {
      block: !result.safe,
      reason: result.reason || "Custom analysis flagged as unsafe",
      severity: result.severity
    };
  } catch (error) {
    return {
      block: true,
      reason: "Custom analysis failed - blocking for safety"
    };
  }
}
