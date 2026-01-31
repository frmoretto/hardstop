/**
 * Hardstop for OpenClaw
 * Pre-execution safety layer that blocks dangerous shell commands
 *
 * @packageDocumentation
 */

// TODO: Import from @openclaw/sdk when available
// import type { OpenClawPlugin, ToolCallEvent } from "@openclaw/sdk";

import { checkDangerousPatterns, checkSafePatterns, DANGEROUS_PATTERNS, SAFE_PATTERNS } from "./patterns";
import { analyzeWithLLM } from "./analyzer";
import { getState, setState, log } from "./state";

// Placeholder types until @openclaw/sdk is available
interface OpenClawPlugin {
  name: string;
  version: string;
  description: string;
  configSchema: object;
  setup: (api: OpenClawAPI) => Promise<void>;
}

interface OpenClawAPI {
  getConfig: () => HardstopConfig;
  on: (event: string, handler: (event: ToolCallEvent) => Promise<ToolCallEvent>, options?: { priority: number }) => void;
  registerCommand: (cmd: CommandDef) => void;
  logger: { info: (msg: string) => void; warn: (msg: string) => void; error: (msg: string) => void };
  completion: (opts: CompletionOpts) => Promise<string>;
}

interface ToolCallEvent {
  toolName: string;
  input?: { command?: string; code?: string };
}

interface CommandDef {
  name: string;
  description: string;
  handler: (ctx: CommandContext) => Promise<void> | void;
}

interface CommandContext {
  args: string[];
  reply: (msg: string) => void;
}

interface CompletionOpts {
  model: string;
  prompt: string;
  maxTokens: number;
  timeout: number;
}

interface HardstopConfig {
  strictMode: boolean;
  llmAnalysis: boolean;
  maxSkip: number;
  logPath: string;
}

/**
 * Hardstop plugin for OpenClaw
 */
const hardstopPlugin: OpenClawPlugin = {
  name: "hardstop",
  version: "0.1.0",
  description: "Pre-execution safety layer for shell commands",

  configSchema: {
    type: "object",
    properties: {
      strictMode: {
        type: "boolean",
        default: true,
        description: "Block unknown commands (fail-closed)"
      },
      llmAnalysis: {
        type: "boolean",
        default: true,
        description: "Use LLM for edge case analysis"
      },
      maxSkip: {
        type: "number",
        default: 10,
        description: "Maximum skip count"
      },
      logPath: {
        type: "string",
        default: "~/.hardstop/audit.log",
        description: "Audit log file path"
      }
    }
  },

  async setup(api: OpenClawAPI) {
    const config = api.getConfig();

    // Register before_tool_call hook with high priority
    api.on("before_tool_call", async (event: ToolCallEvent) => {
      // Only intercept shell execution tools
      if (!["exec", "bash", "shell"].includes(event.toolName)) {
        return event;
      }

      const command = event.input?.command || event.input?.code || "";
      const state = getState();

      // Check skip counter
      if (state.skipCount > 0) {
        setState({ ...state, skipCount: state.skipCount - 1 });
        log("ALLOW", command, "skip", "User skip active");
        return event;
      }

      // Check if disabled
      if (!state.enabled) {
        log("ALLOW", command, "disabled", "Protection disabled");
        return event;
      }

      // Layer 1: Pattern matching
      const dangerous = checkDangerousPatterns(command);
      if (dangerous) {
        log("BLOCK", command, "pattern", dangerous.message);
        throw new Error(`🛑 Hardstop: ${dangerous.message}`);
      }

      const safe = checkSafePatterns(command);
      if (safe) {
        log("ALLOW", command, "pattern", "Matched safe pattern");
        return event;
      }

      // Layer 2: LLM analysis (if enabled)
      if (config.llmAnalysis) {
        const analysis = await analyzeWithLLM(api, command);
        if (analysis.block) {
          log("BLOCK", command, "llm", analysis.reason);
          throw new Error(`🛑 Hardstop: ${analysis.reason}`);
        }
      }

      // Strict mode: block unknown
      if (config.strictMode) {
        log("BLOCK", command, "strict", "Unknown command in strict mode");
        throw new Error("🛑 Hardstop: Command not recognized as safe");
      }

      log("ALLOW", command, "default", "Passed all checks");
      return event;
    }, { priority: 100 }); // High priority = runs first

    // Register /hs command
    api.registerCommand({
      name: "hs",
      description: "Hardstop status and controls",
      handler: (ctx) => handleHsCommand(ctx, api)
    });

    api.logger.info(`[hardstop] Initialized with ${DANGEROUS_PATTERNS.length} dangerous patterns, ${SAFE_PATTERNS.length} safe patterns`);
  }
};

/**
 * Handle /hs subcommands
 */
function handleHsCommand(ctx: CommandContext, api: OpenClawAPI): void {
  const [subcommand, ...args] = ctx.args;
  const state = getState();
  const config = api.getConfig();

  switch (subcommand) {
    case "status":
      ctx.reply(`
🛡️ Hardstop Status
━━━━━━━━━━━━━━━━━━━
Protection: ${state.enabled ? "✅ ENABLED" : "❌ DISABLED"}
Skip counter: ${state.skipCount}
Strict mode: ${config.strictMode ? "Yes" : "No"}
LLM analysis: ${config.llmAnalysis ? "Yes" : "No"}
Patterns: ${DANGEROUS_PATTERNS.length} dangerous, ${SAFE_PATTERNS.length} safe
      `.trim());
      break;

    case "on":
      setState({ ...state, enabled: true });
      ctx.reply("✅ Hardstop protection ENABLED");
      break;

    case "off":
      setState({ ...state, enabled: false });
      ctx.reply("⚠️ Hardstop protection DISABLED (credential protection remains active)");
      break;

    case "skip":
      const count = Math.min(parseInt(args[0] || "1", 10), config.maxSkip);
      if (isNaN(count) || count < 1) {
        ctx.reply(`❌ Invalid skip count. Use: /hs skip [1-${config.maxSkip}]`);
        return;
      }
      setState({ ...state, skipCount: count });
      ctx.reply(`✅ Next ${count} command(s) will bypass checks`);
      break;

    case "log":
      // TODO: Implement log viewer
      ctx.reply("📋 Audit log: ~/.hardstop/audit.log");
      break;

    case "help":
    default:
      ctx.reply(`
🛡️ Hardstop Commands
━━━━━━━━━━━━━━━━━━━━
/hs status  → Show protection status
/hs on      → Enable protection
/hs off     → Disable protection
/hs skip N  → Bypass next N commands (max ${config.maxSkip})
/hs log     → View audit log
/hs help    → Show this help
      `.trim());
      break;
  }
}

export default hardstopPlugin;
export { checkDangerousPatterns, checkSafePatterns } from "./patterns";
export { analyzeWithLLM } from "./analyzer";
export { getState, setState, log } from "./state";
