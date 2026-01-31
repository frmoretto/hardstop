/**
 * State management for Hardstop
 * Handles plugin state and audit logging
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export interface HardstopState {
  enabled: boolean;
  skipCount: number;
  lastUpdated: string;
}

const DEFAULT_STATE: HardstopState = {
  enabled: true,
  skipCount: 0,
  lastUpdated: new Date().toISOString()
};

const STATE_DIR = path.join(os.homedir(), ".hardstop");
const STATE_FILE = path.join(STATE_DIR, "state.json");
const LOG_FILE = path.join(STATE_DIR, "audit.log");

// In-memory state (persisted to disk)
let currentState: HardstopState = { ...DEFAULT_STATE };

/**
 * Ensure the .hardstop directory exists
 */
function ensureStateDir(): void {
  if (!fs.existsSync(STATE_DIR)) {
    fs.mkdirSync(STATE_DIR, { recursive: true });
  }
}

/**
 * Load state from disk
 */
function loadState(): HardstopState {
  try {
    ensureStateDir();
    if (fs.existsSync(STATE_FILE)) {
      const data = fs.readFileSync(STATE_FILE, "utf-8");
      return { ...DEFAULT_STATE, ...JSON.parse(data) };
    }
  } catch (error) {
    console.error("[hardstop] Failed to load state:", error);
  }
  return { ...DEFAULT_STATE };
}

/**
 * Save state to disk
 */
function saveState(state: HardstopState): void {
  try {
    ensureStateDir();
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
  } catch (error) {
    console.error("[hardstop] Failed to save state:", error);
  }
}

/**
 * Get the current plugin state
 */
export function getState(): HardstopState {
  return currentState;
}

/**
 * Update the plugin state
 */
export function setState(newState: Partial<HardstopState>): void {
  currentState = {
    ...currentState,
    ...newState,
    lastUpdated: new Date().toISOString()
  };
  saveState(currentState);
}

/**
 * Reset state to defaults
 */
export function resetState(): void {
  currentState = { ...DEFAULT_STATE };
  saveState(currentState);
}

// Initialize state on module load
currentState = loadState();

// ============ Audit Logging ============

export interface AuditEntry {
  timestamp: string;
  command: string;
  verdict: "ALLOW" | "BLOCK";
  layer: "pattern" | "llm" | "skip" | "disabled" | "strict" | "default";
  reason: string;
  cwd?: string;
}

/**
 * Log an audit entry
 * @param verdict ALLOW or BLOCK
 * @param command The command that was evaluated
 * @param layer Which layer made the decision
 * @param reason Why the decision was made
 */
export function log(
  verdict: "ALLOW" | "BLOCK",
  command: string,
  layer: AuditEntry["layer"],
  reason: string
): void {
  const entry: AuditEntry = {
    timestamp: new Date().toISOString(),
    command: command.substring(0, 1000), // Truncate long commands
    verdict,
    layer,
    reason,
    cwd: process.cwd()
  };

  try {
    ensureStateDir();
    fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + "\n");
  } catch (error) {
    console.error("[hardstop] Failed to write audit log:", error);
  }
}

/**
 * Read recent audit log entries
 * @param count Number of entries to return (default: 10)
 * @returns Array of audit entries
 */
export function readLog(count: number = 10): AuditEntry[] {
  try {
    if (!fs.existsSync(LOG_FILE)) {
      return [];
    }

    const lines = fs.readFileSync(LOG_FILE, "utf-8")
      .trim()
      .split("\n")
      .filter(line => line.length > 0);

    return lines
      .slice(-count)
      .map(line => JSON.parse(line))
      .reverse();
  } catch (error) {
    console.error("[hardstop] Failed to read audit log:", error);
    return [];
  }
}

/**
 * Clear the audit log
 */
export function clearLog(): void {
  try {
    if (fs.existsSync(LOG_FILE)) {
      fs.writeFileSync(LOG_FILE, "");
    }
  } catch (error) {
    console.error("[hardstop] Failed to clear audit log:", error);
  }
}

/**
 * Get the path to the audit log file
 */
export function getLogPath(): string {
  return LOG_FILE;
}
