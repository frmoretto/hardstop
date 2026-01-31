/**
 * Pattern database for Hardstop
 * Ported from Python implementation
 */

export interface Pattern {
  id: string;
  regex: RegExp;
  message: string;
  severity: "critical" | "high" | "medium" | "low";
  mitre?: string;
}

/**
 * Dangerous command patterns - BLOCK these
 *
 * TODO: Port all 180+ patterns from Python implementation
 * Currently contains a representative subset for initial testing
 */
export const DANGEROUS_PATTERNS: Pattern[] = [
  // === CRITICAL: Data Destruction ===
  {
    id: "ROOT_DELETE",
    regex: /rm\s+(-[^\s]*\s+)*\/($|\s)/,
    message: "Deletes root filesystem",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "HOME_DELETE",
    regex: /rm\s+(-[^\s]*\s+)*~\//,
    message: "Deletes home directory",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "RECURSIVE_FORCE_DELETE",
    regex: /rm\s+-[rf]*\s+-[rf]*\s+\//,
    message: "Recursive force delete on root path",
    severity: "critical",
    mitre: "T1485"
  },

  // === CRITICAL: System Crash ===
  {
    id: "FORK_BOMB",
    regex: /:\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:/,
    message: "Fork bomb - will crash system",
    severity: "critical",
    mitre: "T1499.004"
  },
  {
    id: "DEV_NULL_MOVE",
    regex: /mv\s+.*\s+\/dev\/null/,
    message: "Moving files to /dev/null destroys them",
    severity: "critical",
    mitre: "T1485"
  },

  // === HIGH: Credential Exfiltration ===
  {
    id: "CURL_ENV",
    regex: /curl\s+.*\$\(cat\s+.*\.env/,
    message: "Exfiltrating .env file contents",
    severity: "high",
    mitre: "T1552"
  },
  {
    id: "CURL_SSH_KEY",
    regex: /curl\s+.*\$\(cat\s+.*\.ssh\//,
    message: "Exfiltrating SSH keys",
    severity: "high",
    mitre: "T1552.004"
  },

  // === HIGH: Reverse Shells ===
  {
    id: "BASH_REVERSE_SHELL",
    regex: /bash\s+-i\s+>&\s*\/dev\/tcp\//,
    message: "Bash reverse shell",
    severity: "high",
    mitre: "T1059.004"
  },
  {
    id: "NC_REVERSE_SHELL",
    regex: /nc\s+-[^\s]*e\s+\/bin\/(ba)?sh/,
    message: "Netcat reverse shell",
    severity: "high",
    mitre: "T1059.004"
  },
  {
    id: "PYTHON_REVERSE_SHELL",
    regex: /python[23]?\s+-c\s+.*socket.*connect/i,
    message: "Python reverse shell",
    severity: "high",
    mitre: "T1059.006"
  },

  // === HIGH: Pipe to Shell ===
  {
    id: "CURL_PIPE_BASH",
    regex: /curl\s+.*\|\s*(sudo\s+)?(ba)?sh/,
    message: "Downloading and executing untrusted code",
    severity: "high",
    mitre: "T1059.004"
  },
  {
    id: "WGET_PIPE_BASH",
    regex: /wget\s+.*-O\s*-\s*\|\s*(sudo\s+)?(ba)?sh/,
    message: "Downloading and executing untrusted code",
    severity: "high",
    mitre: "T1059.004"
  },

  // === MEDIUM: Privilege Escalation ===
  {
    id: "CHMOD_SUID",
    regex: /chmod\s+[0-7]*[4-7][0-7]{2}\s+/,
    message: "Setting SUID/SGID bit - privilege escalation risk",
    severity: "medium",
    mitre: "T1548.001"
  },
  {
    id: "SUDO_CHMOD_777",
    regex: /sudo\s+chmod\s+777/,
    message: "Making files world-writable with sudo",
    severity: "medium",
    mitre: "T1222"
  },

  // === MEDIUM: Disk Operations ===
  {
    id: "DD_DISK_WIPE",
    regex: /dd\s+if=\/dev\/(zero|urandom)\s+of=\/dev\/[sh]d[a-z]/,
    message: "Wiping disk with dd",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "MKFS_FORMAT",
    regex: /mkfs\s+/,
    message: "Formatting filesystem",
    severity: "critical",
    mitre: "T1561.001"
  },

  // === macOS-Specific ===
  {
    id: "MACOS_KEYCHAIN_DUMP",
    regex: /security\s+(dump-keychain|find-(generic|internet)-password\s+-g)/,
    message: "Dumping macOS Keychain credentials",
    severity: "critical",
    mitre: "T1555.001"
  },
  {
    id: "MACOS_DISKUTIL_ERASE",
    regex: /diskutil\s+(eraseDisk|eraseVolume|secureErase)/,
    message: "Erasing disk volume on macOS",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "MACOS_SIP_DISABLE",
    regex: /csrutil\s+disable/,
    message: "Disabling System Integrity Protection",
    severity: "critical",
    mitre: "T1553.006"
  },
  {
    id: "MACOS_GATEKEEPER_DISABLE",
    regex: /spctl\s+--master-disable/,
    message: "Disabling Gatekeeper",
    severity: "high",
    mitre: "T1553.001"
  },

  // === Windows/PowerShell ===
  {
    id: "WINDOWS_RD_RECURSIVE",
    regex: /rd\s+\/s\s+\/q\s+[A-Za-z]:\\/i,
    message: "Recursive delete of Windows drive",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "POWERSHELL_ENCODED",
    regex: /powershell\s+-[eE](?:nc(?:odedcommand)?)?/i,
    message: "Encoded PowerShell command - potential obfuscation",
    severity: "high",
    mitre: "T1027"
  },
  {
    id: "WINDOWS_FORMAT",
    regex: /format\s+[A-Za-z]:\s*\/[qQyY]/i,
    message: "Formatting Windows drive",
    severity: "critical",
    mitre: "T1561.001"
  },

  // === Cloud CLI ===
  {
    id: "AWS_DELETE_BUCKET",
    regex: /aws\s+s3\s+rb\s+.*--force/,
    message: "Force deleting S3 bucket",
    severity: "high",
    mitre: "T1485"
  },
  {
    id: "GCP_DELETE_PROJECT",
    regex: /gcloud\s+projects\s+delete/,
    message: "Deleting GCP project",
    severity: "critical"
  },
  {
    id: "TERRAFORM_DESTROY",
    regex: /terraform\s+destroy\s+(-auto-approve|--auto-approve)/,
    message: "Terraform destroy with auto-approve",
    severity: "critical"
  },

  // === Database ===
  {
    id: "REDIS_FLUSHALL",
    regex: /redis-cli\s+.*FLUSHALL/i,
    message: "Flushing all Redis data",
    severity: "high"
  },
  {
    id: "SQL_DROP_DATABASE",
    regex: /DROP\s+DATABASE/i,
    message: "Dropping database",
    severity: "critical"
  },
  {
    id: "MONGO_DROP",
    regex: /mongo.*--eval.*\.drop\(/,
    message: "Dropping MongoDB collection",
    severity: "high"
  }
];

/**
 * Safe command patterns - ALLOW these without LLM analysis
 */
export const SAFE_PATTERNS: Pattern[] = [
  // Read-only filesystem
  { id: "LS", regex: /^ls(\s|$)/, message: "List directory", severity: "low" },
  { id: "PWD", regex: /^pwd(\s|$)/, message: "Print working directory", severity: "low" },
  { id: "CAT", regex: /^cat\s+[^|;&]+$/, message: "Display file contents", severity: "low" },
  { id: "HEAD", regex: /^head(\s|$)/, message: "Display file start", severity: "low" },
  { id: "TAIL", regex: /^tail(\s|$)/, message: "Display file end", severity: "low" },
  { id: "LESS", regex: /^less(\s|$)/, message: "Page through file", severity: "low" },
  { id: "FIND", regex: /^find\s+[^-].*-name/, message: "Find files", severity: "low" },
  { id: "GREP", regex: /^grep(\s|$)/, message: "Search file contents", severity: "low" },
  { id: "WC", regex: /^wc(\s|$)/, message: "Word count", severity: "low" },
  { id: "DIFF", regex: /^diff(\s|$)/, message: "Compare files", severity: "low" },
  { id: "FILE", regex: /^file(\s|$)/, message: "Determine file type", severity: "low" },

  // Git read-only
  { id: "GIT_STATUS", regex: /^git\s+status/, message: "Git status", severity: "low" },
  { id: "GIT_LOG", regex: /^git\s+log/, message: "Git log", severity: "low" },
  { id: "GIT_DIFF", regex: /^git\s+diff/, message: "Git diff", severity: "low" },
  { id: "GIT_BRANCH", regex: /^git\s+branch\s*$/, message: "List branches", severity: "low" },
  { id: "GIT_SHOW", regex: /^git\s+show/, message: "Git show", severity: "low" },

  // Package managers (read-only)
  { id: "NPM_LIST", regex: /^npm\s+(list|ls|outdated|view)/, message: "npm read operation", severity: "low" },
  { id: "PIP_LIST", regex: /^pip\s+(list|show|freeze)/, message: "pip read operation", severity: "low" },

  // System info
  { id: "ECHO", regex: /^echo(\s|$)/, message: "Print text", severity: "low" },
  { id: "DATE", regex: /^date(\s|$)/, message: "Show date/time", severity: "low" },
  { id: "WHOAMI", regex: /^whoami(\s|$)/, message: "Show current user", severity: "low" },
  { id: "HOSTNAME", regex: /^hostname(\s|$)/, message: "Show hostname", severity: "low" },
  { id: "UNAME", regex: /^uname(\s|$)/, message: "Show system info", severity: "low" },
  { id: "ENV", regex: /^env(\s|$)/, message: "Show environment", severity: "low" },
  { id: "PRINTENV", regex: /^printenv(\s|$)/, message: "Print environment", severity: "low" },

  // Help commands
  { id: "MAN", regex: /^man(\s|$)/, message: "Manual page", severity: "low" },
  { id: "HELP", regex: /--help(\s|$)/, message: "Help flag", severity: "low" },
  { id: "VERSION", regex: /--version(\s|$)/, message: "Version flag", severity: "low" }
];

/**
 * Check if a command matches any dangerous pattern
 * @param command The command to check
 * @returns The matching pattern, or null if no match
 */
export function checkDangerousPatterns(command: string): Pattern | null {
  // Normalize command: trim and handle command chains
  const normalizedCommand = command.trim();

  // Split on command separators and check each part
  const parts = normalizedCommand.split(/\s*[;&|]+\s*/);

  for (const part of parts) {
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.regex.test(part)) {
        return pattern;
      }
    }
  }

  return null;
}

/**
 * Check if a command matches any safe pattern
 * @param command The command to check
 * @returns The matching pattern, or null if no match
 */
export function checkSafePatterns(command: string): Pattern | null {
  const normalizedCommand = command.trim();

  // For safe patterns, ALL parts must be safe
  const parts = normalizedCommand.split(/\s*[;&|]+\s*/);

  for (const part of parts) {
    let partIsSafe = false;
    for (const pattern of SAFE_PATTERNS) {
      if (pattern.regex.test(part)) {
        partIsSafe = true;
        break;
      }
    }
    if (!partIsSafe) {
      return null; // One unsafe part means the whole command is not safe
    }
  }

  // Return the first matching pattern as representative
  for (const pattern of SAFE_PATTERNS) {
    if (pattern.regex.test(parts[0])) {
      return pattern;
    }
  }

  return null;
}
