/**
 * Pattern database for Hardstop
 * Ported from Python implementation (v1.3.6)
 *
 * 180+ dangerous patterns, 77 safe patterns
 */

export interface Pattern {
  id: string;
  regex: RegExp;
  message: string;
  severity: "critical" | "high" | "medium" | "low";
  mitre?: string;
}

// ============================================================
// DANGEROUS COMMAND PATTERNS - BLOCK these
// ============================================================

export const DANGEROUS_PATTERNS: Pattern[] = [
  // === HOME/ROOT DELETION ===
  {
    id: "HOME_DELETE_1",
    regex: /(?<!echo\s)(?<!echo ')(?<!echo ")rm\s+(-[^\s]*\s+)*(\/home\/|~\/)/,
    message: "Deletes home directory",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "HOME_DELETE_2",
    regex: /(?<!echo\s)(?<!echo ')(?<!echo ")rm\s+(-[^\s]*\s+)*~(\/[^/\s]+)?(\s|$|>|;|&|\|)/,
    message: "Deletes home directory or subdirectory",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "ROOT_DELETE",
    regex: /(?<!echo\s)(?<!echo ')(?<!echo ")rm\s+(-[^\s]*\s+)*\/(\s|$|>|;|&|\|)/,
    message: "Deletes root filesystem",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "HOME_DELETE_VAR_1",
    regex: /(?<!echo\s)rm\s+(-[^\s]*\s+)*\$HOME/,
    message: "Deletes home directory via $HOME",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "HOME_DELETE_VAR_2",
    regex: /(?<!echo\s)rm\s+(-[^\s]*\s+)*\$\{HOME\}/,
    message: "Deletes home directory via ${HOME}",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "HOME_DELETE_VAR_3",
    regex: /(?<!echo\s)rm\s+(-[^\s]*\s+)*\/home\/\$USER/,
    message: "Deletes user home via $USER",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "HOME_DELETE_VAR_4",
    regex: /(?<!echo\s)rm\s+(-[^\s]*\s+)*\/home\/\$\{USER\}/,
    message: "Deletes user home via ${USER}",
    severity: "critical",
    mitre: "T1485"
  },

  // === FORK BOMB ===
  {
    id: "FORK_BOMB",
    regex: /:\(\)\s*\{?\s*:\|:&\s*\}?\s*;?\s*:?|:\(\)\{\s*:\|:&\s*\};?:?/,
    message: "Fork bomb - will crash system",
    severity: "critical",
    mitre: "T1499.004"
  },

  // === MOVE TO DEV NULL ===
  {
    id: "DEV_NULL_MOVE",
    regex: /mv\s+.+\s+\/dev\/null/,
    message: "Moving files to /dev/null destroys them",
    severity: "critical",
    mitre: "T1485"
  },

  // === REVERSE SHELLS ===
  {
    id: "BASH_REVERSE_SHELL",
    regex: /bash\s+-i\s+>&\s*\/dev\/tcp\//,
    message: "Reverse shell - remote access backdoor",
    severity: "high",
    mitre: "T1059.004"
  },
  {
    id: "NC_REVERSE_SHELL",
    regex: /nc\s+(-[^\s]*\s+)*-e\s+\/bin\/(ba)?sh/,
    message: "Reverse shell via netcat",
    severity: "high",
    mitre: "T1059.004"
  },
  {
    id: "DEV_TCP",
    regex: /\/dev\/tcp\/[^\s]+/,
    message: "Network connection via /dev/tcp",
    severity: "high",
    mitre: "T1059.004"
  },
  {
    id: "MKFIFO_NC_SHELL",
    regex: /mkfifo.*nc.*sh/,
    message: "Reverse shell via named pipe",
    severity: "high",
    mitre: "T1059.004"
  },
  {
    id: "PYTHON_REVERSE_SHELL",
    regex: /python.*socket.*connect.*exec/i,
    message: "Python reverse shell",
    severity: "high",
    mitre: "T1059.006"
  },
  {
    id: "PERL_REVERSE_SHELL",
    regex: /perl.*socket.*exec/i,
    message: "Perl reverse shell",
    severity: "high",
    mitre: "T1059.006"
  },

  // === CREDENTIAL EXFILTRATION ===
  {
    id: "CURL_EXFIL_CREDS",
    regex: /curl\s+.*(-d|--data|-F|--form)\s+.*(\.ssh|\.aws|\.config|\.gnupg)/,
    message: "Exfiltrates credentials",
    severity: "critical",
    mitre: "T1552"
  },
  {
    id: "WGET_EXFIL_CREDS",
    regex: /wget\s+.*--post-(data|file)\s+.*(\.ssh|\.aws|\.config)/,
    message: "Exfiltrates credentials",
    severity: "critical",
    mitre: "T1552"
  },
  {
    id: "CAT_PIPE_CREDS",
    regex: /cat\s+.*(\.ssh\/id_|\.aws\/credentials|\.env)\s*\|/,
    message: "Pipes credentials to another command",
    severity: "critical",
    mitre: "T1552"
  },
  {
    id: "TAR_EXFIL_CREDS",
    regex: /tar\s+.*\s+(\.ssh|\.aws|\.gnupg|\.config).*\|.*(nc|curl|wget)/,
    message: "Archives and exfiltrates credentials",
    severity: "critical",
    mitre: "T1552"
  },
  {
    id: "SCP_CREDS",
    regex: /scp\s+.*(\.ssh|\.aws|\.config).*@/,
    message: "Copies credentials to remote host",
    severity: "critical",
    mitre: "T1552"
  },
  {
    id: "NC_PIPE_CREDS",
    regex: /cat\s+~\/\.(ssh|aws|gnupg)\/.*\|\s*nc\s+/,
    message: "Pipes credentials via netcat",
    severity: "critical",
    mitre: "T1552"
  },

  // === DISK DESTRUCTION ===
  {
    id: "DD_DISK_OVERWRITE",
    regex: /dd\s+.*of=\/dev\/(sd[a-z]|nvme|xvd|vd[a-z])/,
    message: "Overwrites disk directly",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "MKFS_FORMAT",
    regex: /mkfs(\.[a-z0-9]+)?\s+.*\/dev\/(sd[a-z]|nvme|xvd|vd[a-z])/,
    message: "Formats drive",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "REDIRECT_TO_DISK",
    regex: />\s*\/dev\/(sd[a-z]|nvme)/,
    message: "Redirects to raw disk",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "SHRED_DISK_HOME",
    regex: /shred\s+.*(\/dev\/|\/home\/|~\/)/,
    message: "Shreds disk or home directory",
    severity: "critical",
    mitre: "T1485"
  },

  // === ENCODED PAYLOAD EXECUTION ===
  {
    id: "BASE64_PIPE_SH",
    regex: /base64\s+-d.*\|\s*(ba)?sh/,
    message: "Executes base64-encoded payload",
    severity: "high",
    mitre: "T1027"
  },
  {
    id: "ECHO_BASE64_EXEC",
    regex: /echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s+-d\s*\|\s*(ba)?sh/,
    message: "Executes encoded payload",
    severity: "high",
    mitre: "T1027"
  },
  {
    id: "EVAL_BASE64",
    regex: /eval\s+.*\$\(.*base64/,
    message: "Eval with base64 decode",
    severity: "high",
    mitre: "T1027"
  },
  {
    id: "PYTHON_EXEC_DECODE",
    regex: /python.*-c.*exec.*decode/i,
    message: "Python encoded execution",
    severity: "high",
    mitre: "T1027"
  },

  // === CURL/WGET PIPE TO SHELL ===
  {
    id: "CURL_PIPE_SH",
    regex: /curl\s+[^|]*\|\s*(sudo\s+)?(ba)?sh/,
    message: "Pipes URL content to shell",
    severity: "high",
    mitre: "T1059.004"
  },
  {
    id: "WGET_PIPE_SH",
    regex: /wget\s+.*\|\s*(sudo\s+)?(ba)?sh/,
    message: "Pipes download to shell",
    severity: "high",
    mitre: "T1059.004"
  },
  {
    id: "CURL_PIPE_PYTHON",
    regex: /curl\s+[^|]*\|\s*python/,
    message: "Pipes URL content to Python",
    severity: "high",
    mitre: "T1059.006"
  },

  // === SYSTEM DAMAGE ===
  {
    id: "CHMOD_777_ROOT",
    regex: /chmod\s+(-[^\s]*\s+)*777\s+\//,
    message: "Sets world-writable on system root",
    severity: "critical",
    mitre: "T1222"
  },
  {
    id: "CHMOD_777_RECURSIVE",
    regex: /chmod\s+(-[^\s]*\s+)*-R\s+777/,
    message: "Recursively sets world-writable",
    severity: "high",
    mitre: "T1222"
  },
  {
    id: "CHOWN_RECURSIVE_SYSTEM",
    regex: /chown\s+(-[^\s]*\s+)*-R\s+.*\s+\/(?!home)/,
    message: "Recursive chown on system directories",
    severity: "high",
    mitre: "T1222"
  },

  // === HISTORY MANIPULATION ===
  {
    id: "CLEAR_BASH_HISTORY",
    regex: />\s*~\/\.bash_history/,
    message: "Clears bash history",
    severity: "medium",
    mitre: "T1070.003"
  },

  // === CRON/SCHEDULED TASKS ===
  {
    id: "CRONTAB_REMOVE_ALL",
    regex: /crontab\s+-r/,
    message: "Removes all cron jobs",
    severity: "high"
  },
  {
    id: "PIPE_TO_CRONTAB",
    regex: /echo.*\|\s*crontab/,
    message: "Pipes to crontab (potential persistence)",
    severity: "medium",
    mitre: "T1053.003"
  },

  // === DANGEROUS SUDO ===
  {
    id: "SUDO_RM_SYSTEM",
    regex: /sudo\s+rm\s+(-[^\s]*\s+)*(\/|\/home|\/etc|\/usr|\/var)/,
    message: "Sudo delete on system paths",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "SUDO_CHMOD_777",
    regex: /sudo\s+chmod\s+(-[^\s]*\s+)*777/,
    message: "Sudo world-writable permission",
    severity: "high",
    mitre: "T1222"
  },
  {
    id: "SUDO_DD",
    regex: /sudo\s+dd\s+/,
    message: "Sudo disk write",
    severity: "critical",
    mitre: "T1561.001"
  },

  // ============================================================
  // WINDOWS-SPECIFIC PATTERNS
  // ============================================================

  // === WINDOWS SYSTEM DELETION ===
  {
    id: "WINDOWS_RD_SYSTEM",
    regex: /rd\s+(\/s|\/q|\s)+\s*(C:\\|C:\/|%SystemRoot%|%USERPROFILE%|%APPDATA%)/i,
    message: "Deletes Windows system/user directory",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "WINDOWS_RMDIR_SYSTEM",
    regex: /rmdir\s+(\/s|\/q|\s)+\s*(C:\\|C:\/|%SystemRoot%|%USERPROFILE%)/i,
    message: "Deletes Windows system/user directory",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "WINDOWS_DEL_SYSTEM",
    regex: /del\s+(\/[fqsa]|\s)+\s*(C:\\Windows|C:\\Users|%SystemRoot%)/i,
    message: "Deletes Windows system files",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "POWERSHELL_REMOVE_ITEM",
    regex: /Remove-Item\s+.*-Recurse.*\s+(C:\\|C:\/|~\\|\$env:)/i,
    message: "PowerShell recursive delete on system paths",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "WINDOWS_RM_SYSTEM",
    regex: /rm\s+-r.*\s+(C:\\Windows|C:\\Users\\[^\\]+$|\$HOME)/i,
    message: "Deletes Windows system/user directory",
    severity: "critical",
    mitre: "T1485"
  },

  // === WINDOWS REGISTRY MANIPULATION ===
  {
    id: "REG_DELETE_HKLM",
    regex: /reg\s+delete\s+.*HKLM/i,
    message: "Deletes machine-wide registry keys",
    severity: "critical",
    mitre: "T1112"
  },
  {
    id: "REG_DELETE_HKCU_WINDOWS",
    regex: /reg\s+delete\s+.*HKCU\\Software\\Microsoft\\Windows/i,
    message: "Deletes critical user registry keys",
    severity: "high",
    mitre: "T1112"
  },
  {
    id: "REG_ADD_RUN",
    regex: /reg\s+add\s+.*\\Run\s+/i,
    message: "Adds registry run key (persistence)",
    severity: "high",
    mitre: "T1547.001"
  },
  {
    id: "POWERSHELL_REG_DELETE",
    regex: /Remove-ItemProperty.*Registry/i,
    message: "PowerShell registry deletion",
    severity: "high",
    mitre: "T1112"
  },

  // === WINDOWS CREDENTIAL THEFT ===
  {
    id: "CMDKEY_LIST",
    regex: /cmdkey\s+\/list/i,
    message: "Lists stored Windows credentials",
    severity: "high",
    mitre: "T1555.004"
  },
  {
    id: "VAULTCMD_LIST",
    regex: /vaultcmd\s+\/list/i,
    message: "Lists Windows credential vault",
    severity: "high",
    mitre: "T1555.004"
  },
  {
    id: "MIMIKATZ",
    regex: /mimikatz/i,
    message: "Credential dumping tool",
    severity: "critical",
    mitre: "T1003"
  },
  {
    id: "SEKURLSA",
    regex: /sekurlsa/i,
    message: "Credential dumping (mimikatz module)",
    severity: "critical",
    mitre: "T1003"
  },
  {
    id: "POWERSHELL_EXPORT_CREDS",
    regex: /Get-Credential.*Export/i,
    message: "Exports Windows credentials",
    severity: "high",
    mitre: "T1555.004"
  },
  {
    id: "COPY_SAM_SYSTEM",
    regex: /copy.*\\Windows\\System32\\config\\(SAM|SYSTEM)/i,
    message: "Copies Windows password database",
    severity: "critical",
    mitre: "T1003.002"
  },

  // === WINDOWS DISK/BOOT DESTRUCTION ===
  {
    id: "WINDOWS_FORMAT",
    regex: /format\s+[A-Za-z]:/i,
    message: "Formats Windows drive",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "DISKPART",
    regex: /diskpart/i,
    message: "Windows disk partition tool",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "BCDEDIT_DELETE",
    regex: /bcdedit\s+\/delete/i,
    message: "Deletes boot configuration",
    severity: "critical",
    mitre: "T1542"
  },
  {
    id: "BOOTREC_FIXMBR",
    regex: /bootrec\s+\/fixmbr/i,
    message: "Modifies master boot record",
    severity: "critical",
    mitre: "T1542"
  },

  // === WINDOWS FIREWALL/SECURITY ===
  {
    id: "NETSH_FIREWALL_OFF",
    regex: /netsh\s+advfirewall\s+set\s+.*state\s+off/i,
    message: "Disables Windows firewall",
    severity: "high",
    mitre: "T1562.004"
  },
  {
    id: "NETSH_FIREWALL_OFF_LEGACY",
    regex: /netsh\s+firewall\s+set\s+opmode\s+disable/i,
    message: "Disables Windows firewall (legacy)",
    severity: "high",
    mitre: "T1562.004"
  },
  {
    id: "DISABLE_DEFENDER",
    regex: /Set-MpPreference\s+-DisableRealtimeMonitoring/i,
    message: "Disables Windows Defender",
    severity: "critical",
    mitre: "T1562.001"
  },
  {
    id: "STOP_WINDEFEND",
    regex: /sc\s+stop\s+WinDefend/i,
    message: "Stops Windows Defender service",
    severity: "critical",
    mitre: "T1562.001"
  },

  // === WINDOWS REVERSE SHELLS ===
  {
    id: "POWERSHELL_ENCODED",
    regex: /powershell.*-e\s+[A-Za-z0-9+/=]{20,}/i,
    message: "Encoded PowerShell payload",
    severity: "high",
    mitre: "T1027"
  },
  {
    id: "POWERSHELL_DOWNLOAD_CRADLE",
    regex: /powershell.*IEX.*\(New-Object.*Net\.WebClient\)/i,
    message: "PowerShell download cradle",
    severity: "high",
    mitre: "T1059.001"
  },
  {
    id: "POWERSHELL_IWR_IEX",
    regex: /powershell.*Invoke-WebRequest.*\|\s*iex/i,
    message: "PowerShell download and execute",
    severity: "high",
    mitre: "T1059.001"
  },
  {
    id: "CERTUTIL_DOWNLOAD",
    regex: /certutil.*-urlcache.*-split.*-f/i,
    message: "Certutil download (LOLBin)",
    severity: "high",
    mitre: "T1105"
  },
  {
    id: "BITSADMIN_TRANSFER",
    regex: /bitsadmin.*\/transfer/i,
    message: "BITSAdmin download (LOLBin)",
    severity: "high",
    mitre: "T1105"
  },
  {
    id: "MSHTA_HTTP",
    regex: /mshta\s+http/i,
    message: "MSHTA remote execution",
    severity: "high",
    mitre: "T1218.005"
  },
  {
    id: "REGSVR32_SQUIBLYDOO",
    regex: /regsvr32\s+\/s\s+\/n\s+\/u\s+\/i:http/i,
    message: "Regsvr32 script execution (Squiblydoo)",
    severity: "high",
    mitre: "T1218.010"
  },

  // === WINDOWS USER/ADMIN MANIPULATION ===
  {
    id: "NET_USER_ADD",
    regex: /net\s+user\s+.*\s+\/add/i,
    message: "Creates Windows user account",
    severity: "high",
    mitre: "T1136.001"
  },
  {
    id: "NET_LOCALGROUP_ADMIN",
    regex: /net\s+localgroup\s+administrators\s+.*\s+\/add/i,
    message: "Adds user to administrators",
    severity: "critical",
    mitre: "T1098"
  },
  {
    id: "NET_USER_ADMIN_ENABLE",
    regex: /net\s+user\s+administrator\s+\/active:yes/i,
    message: "Enables built-in administrator",
    severity: "high",
    mitre: "T1098"
  },

  // === WINDOWS SCHEDULED TASKS ===
  {
    id: "SCHTASKS_CREATE",
    regex: /schtasks\s+\/create/i,
    message: "Creates scheduled task (persistence)",
    severity: "medium",
    mitre: "T1053.005"
  },
  {
    id: "AT_JOB",
    regex: /at\s+\d+:\d+/i,
    message: "Creates AT job (legacy scheduler)",
    severity: "medium",
    mitre: "T1053.002"
  },

  // === POWERSHELL EXECUTION POLICY BYPASS ===
  {
    id: "SET_EXECPOLICY_BYPASS",
    regex: /Set-ExecutionPolicy\s+Bypass/i,
    message: "Bypasses PowerShell execution policy",
    severity: "high",
    mitre: "T1059.001"
  },
  {
    id: "POWERSHELL_EP_BYPASS",
    regex: /powershell.*-ExecutionPolicy\s+Bypass/i,
    message: "Bypasses PowerShell execution policy",
    severity: "high",
    mitre: "T1059.001"
  },
  {
    id: "POWERSHELL_EP_BYPASS_SHORT",
    regex: /powershell.*-ep\s+bypass/i,
    message: "Bypasses PowerShell execution policy",
    severity: "high",
    mitre: "T1059.001"
  },

  // === COMMAND SUBSTITUTION IN ARGUMENTS ===
  {
    id: "CD_CMD_SUBSTITUTION",
    regex: /\bcd\s+[^;&|]*(\$\(|`)/,
    message: "cd with command substitution (potential code execution)",
    severity: "medium",
    mitre: "T1059"
  },

  // ============================================================
  // SHELL WRAPPER PATTERNS
  // ============================================================

  {
    id: "SH_WRAPPER_RM_R",
    regex: /\b(ba)?sh\s+-c\s+["'].*\brm\s+(-[^\s]*\s+)*-r/,
    message: "Shell wrapper hiding recursive delete",
    severity: "high",
    mitre: "T1485"
  },
  {
    id: "SH_WRAPPER_DD",
    regex: /\b(ba)?sh\s+-c\s+["'].*\bdd\s+.*of=\/dev\//,
    message: "Shell wrapper hiding disk write",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "SH_WRAPPER_MKFS",
    regex: /\b(ba)?sh\s+-c\s+["'].*\bmkfs/,
    message: "Shell wrapper hiding filesystem format",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "SH_WRAPPER_CURL_PIPE",
    regex: /\b(ba)?sh\s+-c\s+["'].*\bcurl.*\|\s*(ba)?sh/,
    message: "Shell wrapper hiding curl pipe to shell",
    severity: "high",
    mitre: "T1059.004"
  },
  {
    id: "SH_WRAPPER_WGET_PIPE",
    regex: /\b(ba)?sh\s+-c\s+["'].*\bwget.*\|\s*(ba)?sh/,
    message: "Shell wrapper hiding wget pipe to shell",
    severity: "high",
    mitre: "T1059.004"
  },
  {
    id: "SUDO_SH_WRAPPER_RM",
    regex: /\bsudo\s+(ba)?sh\s+-c\s+["'].*\brm\s+(-[^\s]*\s+)*-r/,
    message: "Sudo shell wrapper hiding recursive delete",
    severity: "critical",
    mitre: "T1485"
  },
  {
    id: "SUDO_SH_WRAPPER_CHMOD",
    regex: /\bsudo\s+(ba)?sh\s+-c\s+["'].*\bchmod\s+(-[^\s]*\s+)*777/,
    message: "Sudo shell wrapper hiding chmod 777",
    severity: "high",
    mitre: "T1222"
  },
  {
    id: "ENV_WRAPPER_RM",
    regex: /\benv\s+.*\brm\s+(-[^\s]*\s+)*-r/,
    message: "Env wrapper with recursive delete",
    severity: "high",
    mitre: "T1485"
  },
  {
    id: "XARGS_RM_R",
    regex: /\bxargs\s+.*\brm\s+(-[^\s]*\s+)*-r/,
    message: "xargs piping to recursive delete",
    severity: "high",
    mitre: "T1485"
  },
  {
    id: "FIND_EXEC_RM_R",
    regex: /\bfind\s+.*-exec\s+rm\s+(-[^\s]*\s+)*-r/,
    message: "find -exec with recursive delete",
    severity: "high",
    mitre: "T1485"
  },
  {
    id: "FIND_DELETE_SYSTEM",
    regex: /\bfind\s+(~|\/home|\/|\/etc|\/usr|\/var)\s+.*-delete/,
    message: "find -delete on system/home paths",
    severity: "high",
    mitre: "T1485"
  },

  // ============================================================
  // CLOUD CLI DESTRUCTIVE OPERATIONS
  // ============================================================

  // === AWS CLI ===
  {
    id: "AWS_S3_RM_RECURSIVE",
    regex: /\baws\s+s3\s+rm\s+.*--recursive/,
    message: "AWS S3 recursive delete",
    severity: "high",
    mitre: "T1485"
  },
  {
    id: "AWS_S3_RB_FORCE",
    regex: /\baws\s+s3\s+rb\s+.*--force/,
    message: "AWS S3 force remove bucket",
    severity: "high",
    mitre: "T1485"
  },
  {
    id: "AWS_EC2_TERMINATE",
    regex: /\baws\s+ec2\s+terminate-instances\b/,
    message: "AWS EC2 terminate instances",
    severity: "high"
  },
  {
    id: "AWS_RDS_DELETE",
    regex: /\baws\s+rds\s+delete-db-instance\b/,
    message: "AWS RDS delete database",
    severity: "high"
  },
  {
    id: "AWS_CFN_DELETE",
    regex: /\baws\s+cloudformation\s+delete-stack\b/,
    message: "AWS CloudFormation delete stack",
    severity: "high"
  },
  {
    id: "AWS_DYNAMODB_DELETE",
    regex: /\baws\s+dynamodb\s+delete-table\b/,
    message: "AWS DynamoDB delete table",
    severity: "high"
  },
  {
    id: "AWS_EKS_DELETE",
    regex: /\baws\s+eks\s+delete-cluster\b/,
    message: "AWS EKS delete cluster",
    severity: "high"
  },
  {
    id: "AWS_LAMBDA_DELETE",
    regex: /\baws\s+lambda\s+delete-function\b/,
    message: "AWS Lambda delete function",
    severity: "medium"
  },
  {
    id: "AWS_IAM_DELETE_ROLE",
    regex: /\baws\s+iam\s+delete-role\b/,
    message: "AWS IAM delete role",
    severity: "high"
  },
  {
    id: "AWS_IAM_DELETE_USER",
    regex: /\baws\s+iam\s+delete-user\b/,
    message: "AWS IAM delete user",
    severity: "high"
  },

  // === GCP (gcloud) ===
  {
    id: "GCP_PROJECT_DELETE",
    regex: /\bgcloud\s+projects\s+delete\b/,
    message: "GCP delete entire project",
    severity: "critical"
  },
  {
    id: "GCP_COMPUTE_DELETE",
    regex: /\bgcloud\s+compute\s+instances\s+delete\b/,
    message: "GCP delete compute instance",
    severity: "high"
  },
  {
    id: "GCP_SQL_DELETE",
    regex: /\bgcloud\s+sql\s+instances\s+delete\b/,
    message: "GCP delete SQL instance",
    severity: "high"
  },
  {
    id: "GCP_GKE_DELETE",
    regex: /\bgcloud\s+container\s+clusters\s+delete\b/,
    message: "GCP delete GKE cluster",
    severity: "high"
  },
  {
    id: "GCP_STORAGE_RM",
    regex: /\bgcloud\s+storage\s+rm\s+.*-r/,
    message: "GCP storage recursive delete",
    severity: "high"
  },
  {
    id: "GCP_FUNCTION_DELETE",
    regex: /\bgcloud\s+functions\s+delete\b/,
    message: "GCP delete Cloud Function",
    severity: "medium"
  },
  {
    id: "GCP_SA_DELETE",
    regex: /\bgcloud\s+iam\s+service-accounts\s+delete\b/,
    message: "GCP delete service account",
    severity: "high"
  },

  // === FIREBASE ===
  {
    id: "FIREBASE_PROJECT_DELETE",
    regex: /\bfirebase\s+projects:delete\b/,
    message: "Firebase delete project",
    severity: "critical"
  },
  {
    id: "FIREBASE_FIRESTORE_DELETE_ALL",
    regex: /\bfirebase\s+firestore:delete\s+.*--all-collections/,
    message: "Firebase delete all Firestore data",
    severity: "critical"
  },
  {
    id: "FIREBASE_RTDB_DELETE",
    regex: /\bfirebase\s+database:remove\b/,
    message: "Firebase delete Realtime DB",
    severity: "high"
  },
  {
    id: "FIREBASE_FUNCTIONS_DELETE",
    regex: /\bfirebase\s+functions:delete\b/,
    message: "Firebase delete functions",
    severity: "medium"
  },

  // === KUBERNETES (kubectl) ===
  {
    id: "K8S_DELETE_NAMESPACE",
    regex: /\bkubectl\s+delete\s+namespace\b/,
    message: "Kubernetes delete namespace",
    severity: "high"
  },
  {
    id: "K8S_DELETE_ALL",
    regex: /\bkubectl\s+delete\s+all\s+--all/,
    message: "Kubernetes delete all resources",
    severity: "critical"
  },
  {
    id: "K8S_DELETE_ALL_NS",
    regex: /\bkubectl\s+delete\s+.*--all\s+--all-namespaces/,
    message: "Kubernetes delete across all namespaces",
    severity: "critical"
  },
  {
    id: "HELM_UNINSTALL",
    regex: /\bhelm\s+uninstall\b/,
    message: "Helm uninstall release",
    severity: "medium"
  },

  // === DOCKER ===
  {
    id: "DOCKER_SYSTEM_PRUNE_A",
    regex: /\bdocker\s+system\s+prune\s+.*-a/,
    message: "Docker prune all unused data",
    severity: "high"
  },
  {
    id: "DOCKER_VOLUME_RM",
    regex: /\bdocker\s+volume\s+rm\b/,
    message: "Docker remove volume (data loss)",
    severity: "medium"
  },
  {
    id: "DOCKER_VOLUME_PRUNE",
    regex: /\bdocker\s+volume\s+prune\b/,
    message: "Docker prune volumes",
    severity: "high"
  },

  // === TERRAFORM / PULUMI ===
  {
    id: "TERRAFORM_DESTROY",
    regex: /\bterraform\s+destroy\b/,
    message: "Terraform destroy infrastructure",
    severity: "critical"
  },
  {
    id: "PULUMI_DESTROY",
    regex: /\bpulumi\s+destroy\b/,
    message: "Pulumi destroy resources",
    severity: "critical"
  },

  // === DATABASE CLI ===
  {
    id: "REDIS_FLUSHALL",
    regex: /\bredis-cli\s+FLUSHALL/i,
    message: "Redis flush all data",
    severity: "high"
  },
  {
    id: "REDIS_FLUSHDB",
    regex: /\bredis-cli\s+FLUSHDB/i,
    message: "Redis flush database",
    severity: "high"
  },
  {
    id: "MONGO_DROP_DB",
    regex: /\bmongosh?.*dropDatabase/i,
    message: "MongoDB drop database",
    severity: "high"
  },
  {
    id: "POSTGRES_DROPDB",
    regex: /\bdropdb\b/,
    message: "PostgreSQL drop database",
    severity: "high"
  },
  {
    id: "MYSQL_DROP",
    regex: /\bmysqladmin\s+drop\b/,
    message: "MySQL drop database",
    severity: "high"
  },

  // === OTHER PLATFORMS ===
  {
    id: "VERCEL_REMOVE",
    regex: /\bvercel\s+remove\s+.*--yes/,
    message: "Vercel remove deployment",
    severity: "medium"
  },
  {
    id: "VERCEL_PROJECTS_RM",
    regex: /\bvercel\s+projects\s+rm\b/,
    message: "Vercel delete project",
    severity: "high"
  },
  {
    id: "NETLIFY_SITES_DELETE",
    regex: /\bnetlify\s+sites:delete\b/,
    message: "Netlify delete site",
    severity: "high"
  },
  {
    id: "HEROKU_DESTROY",
    regex: /\bheroku\s+apps:destroy\b/,
    message: "Heroku destroy app",
    severity: "high"
  },
  {
    id: "HEROKU_PG_RESET",
    regex: /\bheroku\s+pg:reset\b/,
    message: "Heroku reset Postgres",
    severity: "high"
  },
  {
    id: "FLY_DESTROY",
    regex: /\bfly\s+(apps\s+)?destroy\b/,
    message: "Fly.io destroy app",
    severity: "high"
  },
  {
    id: "GH_REPO_DELETE",
    regex: /\bgh\s+repo\s+delete\b/,
    message: "GitHub delete repository",
    severity: "critical"
  },
  {
    id: "NPM_UNPUBLISH",
    regex: /\bnpm\s+unpublish\b/,
    message: "npm unpublish package",
    severity: "high"
  },

  // === SQL DESTRUCTIVE ===
  {
    id: "SQL_DELETE_NO_WHERE",
    regex: /\bDELETE\s+FROM\s+\w+\s*;/i,
    message: "SQL DELETE without WHERE clause",
    severity: "critical"
  },
  {
    id: "SQL_DELETE_NO_WHERE_EOF",
    regex: /\bDELETE\s+FROM\s+\w+\s*$/i,
    message: "SQL DELETE without WHERE clause",
    severity: "critical"
  },
  {
    id: "SQL_TRUNCATE",
    regex: /\bTRUNCATE\s+TABLE\b/i,
    message: "SQL TRUNCATE TABLE",
    severity: "critical"
  },
  {
    id: "SQL_DROP_TABLE",
    regex: /\bDROP\s+TABLE\b/i,
    message: "SQL DROP TABLE",
    severity: "critical"
  },
  {
    id: "SQL_DROP_DATABASE",
    regex: /\bDROP\s+DATABASE\b/i,
    message: "SQL DROP DATABASE",
    severity: "critical"
  },

  // ============================================================
  // MACOS-SPECIFIC PATTERNS (v1.3.6)
  // ============================================================

  // === DISK UTILITY ===
  {
    id: "MACOS_DISKUTIL_ERASE_DISK",
    regex: /\bdiskutil\s+eraseDisk\b/,
    message: "Erases entire macOS disk",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "MACOS_DISKUTIL_ERASE_VOLUME",
    regex: /\bdiskutil\s+eraseVolume\b/,
    message: "Erases macOS volume",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "MACOS_DISKUTIL_PARTITION",
    regex: /\bdiskutil\s+partitionDisk\b/,
    message: "Repartitions macOS disk (data loss)",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "MACOS_DISKUTIL_DELETE_APFS",
    regex: /\bdiskutil\s+apfs\s+deleteContainer\b/,
    message: "Deletes APFS container",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "MACOS_DISKUTIL_SECURE_ERASE",
    regex: /\bdiskutil\s+secureErase\b/,
    message: "Secure erases macOS disk",
    severity: "critical",
    mitre: "T1561.001"
  },
  {
    id: "MACOS_DISKUTIL_ZERO",
    regex: /\bdiskutil\s+zeroDisk\b/,
    message: "Writes zeros to macOS disk",
    severity: "critical",
    mitre: "T1561.001"
  },

  // === KEYCHAIN ACCESS ===
  {
    id: "MACOS_SECURITY_DELETE_KEYCHAIN",
    regex: /\bsecurity\s+delete-keychain\b/,
    message: "Deletes macOS keychain",
    severity: "critical",
    mitre: "T1555.001"
  },
  {
    id: "MACOS_SECURITY_DUMP_KEYCHAIN",
    regex: /\bsecurity\s+dump-keychain\b/,
    message: "Dumps macOS keychain contents",
    severity: "critical",
    mitre: "T1555.001"
  },
  {
    id: "MACOS_SECURITY_FIND_GENERIC_PW",
    regex: /\bsecurity\s+find-generic-password\s+.*-w\b/,
    message: "Extracts password from macOS keychain",
    severity: "critical",
    mitre: "T1555.001"
  },
  {
    id: "MACOS_SECURITY_FIND_INTERNET_PW",
    regex: /\bsecurity\s+find-internet-password\s+.*-w\b/,
    message: "Extracts internet password from keychain",
    severity: "critical",
    mitre: "T1555.001"
  },
  {
    id: "MACOS_SECURITY_EXPORT_KEYCHAIN",
    regex: /\bsecurity\s+export\s+.*-k\b/,
    message: "Exports macOS keychain",
    severity: "critical",
    mitre: "T1555.001"
  },

  // === TIME MACHINE ===
  {
    id: "MACOS_TMUTIL_DELETE",
    regex: /\btmutil\s+delete\b/,
    message: "Deletes Time Machine backup",
    severity: "high"
  },
  {
    id: "MACOS_TMUTIL_DISABLE",
    regex: /\btmutil\s+disable\b/,
    message: "Disables Time Machine",
    severity: "medium"
  },
  {
    id: "MACOS_TMUTIL_DELETE_SNAPSHOTS",
    regex: /\btmutil\s+deletelocalsnapshots\b/,
    message: "Deletes local Time Machine snapshots",
    severity: "high"
  },
  {
    id: "MACOS_RM_BACKUPS",
    regex: /\brm\s+.*Backups\.backupdb/,
    message: "Deletes Time Machine backup data",
    severity: "critical"
  },

  // === DIRECTORY SERVICES ===
  {
    id: "MACOS_DSCL_DELETE_USER",
    regex: /\bdscl\s+\.\s+-delete\s+\/Users\//,
    message: "Deletes macOS user account",
    severity: "critical"
  },
  {
    id: "MACOS_DSCL_DELETE_GROUP",
    regex: /\bdscl\s+\.\s+-delete\s+\/Groups\//,
    message: "Deletes macOS group",
    severity: "high"
  },
  {
    id: "MACOS_DSCL_ADD_ADMIN",
    regex: /\bdscl\s+\.\s+-append\s+\/Groups\/admin\s+/,
    message: "Adds user to admin group",
    severity: "high",
    mitre: "T1098"
  },

  // === SYSTEM SECURITY ===
  {
    id: "MACOS_GATEKEEPER_DISABLE",
    regex: /\bspctl\s+--master-disable\b/,
    message: "Disables macOS Gatekeeper",
    severity: "high",
    mitre: "T1553.001"
  },
  {
    id: "MACOS_SIP_DISABLE",
    regex: /\bcsrutil\s+disable\b/,
    message: "Disables System Integrity Protection",
    severity: "critical",
    mitre: "T1553.006"
  },
  {
    id: "MACOS_ENABLE_REMOTE_LOGIN",
    regex: /\bsystemsetup\s+-setremotelogin\s+on\b/,
    message: "Enables SSH/remote login",
    severity: "medium"
  },
  {
    id: "MACOS_NVRAM_BOOT_ARGS",
    regex: /\bnvram\s+boot-args/,
    message: "Modifies macOS boot arguments",
    severity: "high",
    mitre: "T1542"
  },

  // === PRIVACY DATABASE ===
  {
    id: "MACOS_TCC_DB_ACCESS",
    regex: /\bsqlite3\s+.*TCC\.db/,
    message: "Direct access to macOS privacy database",
    severity: "critical",
    mitre: "T1552"
  },
  {
    id: "MACOS_TCCUTIL_RESET",
    regex: /\btccutil\s+reset\b/,
    message: "Resets macOS privacy permissions",
    severity: "high"
  },

  // === PERSISTENCE ===
  {
    id: "MACOS_LAUNCHCTL_LOAD_DAEMON",
    regex: /\blaunchctl\s+load\s+.*\/Library\/LaunchDaemons\//,
    message: "Loads system daemon (persistence mechanism)",
    severity: "high",
    mitre: "T1543.001"
  },
  {
    id: "MACOS_LAUNCHCTL_UNLOAD_APPLE",
    regex: /\blaunchctl\s+unload\s+.*com\.apple\./,
    message: "Unloads Apple system service",
    severity: "high"
  },
  {
    id: "MACOS_CP_PLIST_DAEMON",
    regex: /\bcp\s+.*\.plist\s+.*\/Library\/LaunchDaemons\//,
    message: "Installs system daemon (persistence)",
    severity: "high",
    mitre: "T1543.001"
  },
  {
    id: "MACOS_CP_PLIST_AGENT",
    regex: /\bcp\s+.*\.plist\s+.*\/Library\/LaunchAgents\//,
    message: "Installs launch agent (persistence)",
    severity: "medium",
    mitre: "T1543.001"
  },
  {
    id: "MACOS_MV_PLIST_LAUNCH",
    regex: /\bmv\s+.*\.plist\s+.*\/Library\/Launch/,
    message: "Moves plist to launch directory (persistence)",
    severity: "high",
    mitre: "T1543.001"
  },

  // === APPLICATION DATA ===
  {
    id: "MACOS_RM_APP_SUPPORT",
    regex: /\brm\s+.*~\/Library\/Application\\ Support\//,
    message: "Deletes macOS application data",
    severity: "high"
  },
  {
    id: "MACOS_RM_PREFERENCES",
    regex: /\brm\s+(-[^\s]*\s+)*-r.*~\/Library\/Preferences\//,
    message: "Recursively deletes macOS preferences",
    severity: "high"
  },
  {
    id: "MACOS_DEFAULTS_DELETE_SYSTEM",
    regex: /\bdefaults\s+delete\s+(com\.apple\.|NSGlobalDomain)/,
    message: "Deletes system preferences",
    severity: "high"
  }
];

// ============================================================
// SAFE COMMAND PATTERNS - ALLOW these without LLM analysis
// ============================================================

export const SAFE_PATTERNS: Pattern[] = [
  // Hardstop's own operations
  { id: "HS_PYTHON_PLUGIN", regex: /^python\s+.*[/\\]\.claude[/\\]plugins[/\\]hs[/\\].*\.py(\s+.*)?$/, message: "Hardstop plugin operation", severity: "low" },
  { id: "HS_PYTHON_HARDSTOP", regex: /^python\s+.*\.hardstop.*$/, message: "Hardstop operation", severity: "low" },
  { id: "HS_CAT_HARDSTOP", regex: /^cat\s+.*\.hardstop[/\\].*$/, message: "Read hardstop config", severity: "low" },
  { id: "HS_CAT_PLUGIN", regex: /^cat\s+.*\.claude[/\\]plugins[/\\]hs[/\\].*$/, message: "Read hardstop plugin", severity: "low" },
  { id: "HS_RM_SKIP", regex: /^rm\s+(-f\s+)?.*\.hardstop[/\\](skip_next|hook_debug\.log)$/, message: "Remove hardstop temp files", severity: "low" },
  { id: "HS_GREP_PLUGIN", regex: /^grep\s+.*\.claude[/\\]plugins[/\\]hs[/\\].*$/, message: "Search hardstop plugin", severity: "low" },

  // Read-only operations
  { id: "LS", regex: /^ls(\s+.*)?$/, message: "List directory", severity: "low" },
  { id: "CD", regex: /^cd(\s+(?:"[^`$()]*"|'[^']*'|[^\s`$()]+))?$/, message: "Change directory", severity: "low" },
  { id: "CAT", regex: /^cat\s+.+$/, message: "Display file contents", severity: "low" },
  { id: "HEAD", regex: /^head\s+.+$/, message: "Display file start", severity: "low" },
  { id: "TAIL", regex: /^tail\s+.+$/, message: "Display file end", severity: "low" },
  { id: "LESS", regex: /^less\s+.+$/, message: "Page through file", severity: "low" },
  { id: "MORE", regex: /^more\s+.+$/, message: "Page through file", severity: "low" },
  { id: "PWD", regex: /^pwd\s*$/, message: "Print working directory", severity: "low" },
  { id: "WHICH", regex: /^which\s+.+$/, message: "Locate command", severity: "low" },
  { id: "TYPE", regex: /^type\s+.+$/, message: "Describe command", severity: "low" },
  { id: "FILE", regex: /^file\s+.+$/, message: "Determine file type", severity: "low" },
  { id: "WC", regex: /^wc\s+.+$/, message: "Word count", severity: "low" },
  { id: "GREP", regex: /^grep\s+.+$/, message: "Search file contents", severity: "low" },
  { id: "FIND_NAME", regex: /^find\s+.*\s-name\s+.*$/, message: "Find files by name", severity: "low" },
  { id: "ECHO", regex: /^echo(\s+.*)?$/, message: "Print text", severity: "low" },
  { id: "DATE", regex: /^date\s*$/, message: "Show date/time", severity: "low" },
  { id: "WHOAMI", regex: /^whoami\s*$/, message: "Show current user", severity: "low" },
  { id: "HOSTNAME", regex: /^hostname\s*$/, message: "Show hostname", severity: "low" },
  { id: "UNAME", regex: /^uname(\s+.*)?$/, message: "Show system info", severity: "low" },
  { id: "ENV", regex: /^env\s*$/, message: "Show environment", severity: "low" },
  { id: "PRINTENV", regex: /^printenv(\s+.*)?$/, message: "Print environment", severity: "low" },

  // Git read operations
  { id: "GIT_READ", regex: /^git\s+(status|log|diff|show|remote|describe|shortlog|whatchanged|rev-parse|rev-list|cat-file|ls-tree)(\s+.*)?$/, message: "Git read operation", severity: "low" },
  { id: "GIT_LS", regex: /^git\s+ls-[^\s]+(\s+.*)?$/, message: "Git list operation", severity: "low" },

  // Git standard workflow (recoverable)
  { id: "GIT_WORKFLOW", regex: /^git\s+(add|commit|push|pull|fetch|clone|stash|checkout|switch|restore|merge|cherry-pick|branch|tag|init|config|am|apply|bisect|blame|bundle|format-patch|gc|mv|notes|reflog|revert|rm|submodule|worktree)(\s+.*)?$/, message: "Git workflow operation", severity: "low" },
  { id: "GIT_REBASE", regex: /^git\s+rebase(?!\s+.*--exec)(\s+.*)?$/, message: "Git rebase", severity: "low" },

  // Regeneratable cleanup
  { id: "RM_NODE_MODULES", regex: /^rm\s+(-[^\s]*\s+)*node_modules\/?\s*$/, message: "Remove node_modules", severity: "low" },
  { id: "RM_PYCACHE", regex: /^rm\s+(-[^\s]*\s+)*__pycache__\/?\s*$/, message: "Remove pycache", severity: "low" },
  { id: "RM_VENV", regex: /^rm\s+(-[^\s]*\s+)*(\.venv|venv)\/?\s*$/, message: "Remove virtual env", severity: "low" },
  { id: "RM_PYTEST_CACHE", regex: /^rm\s+(-[^\s]*\s+)*\.pytest_cache\/?\s*$/, message: "Remove pytest cache", severity: "low" },
  { id: "RM_DIST", regex: /^rm\s+(-[^\s]*\s+)*dist\/?\s*$/, message: "Remove dist", severity: "low" },
  { id: "RM_BUILD", regex: /^rm\s+(-[^\s]*\s+)*build\/?\s*$/, message: "Remove build", severity: "low" },
  { id: "RM_NEXT", regex: /^rm\s+(-[^\s]*\s+)*\.next\/?\s*$/, message: "Remove .next", severity: "low" },
  { id: "RM_NUXT", regex: /^rm\s+(-[^\s]*\s+)*\.nuxt\/?\s*$/, message: "Remove .nuxt", severity: "low" },
  { id: "RM_COVERAGE", regex: /^rm\s+(-[^\s]*\s+)*coverage\/?\s*$/, message: "Remove coverage", severity: "low" },
  { id: "RM_TMP", regex: /^rm\s+(-[^\s]*\s+)*(\/tmp\/|\$TMPDIR)\s*$/, message: "Remove temp files", severity: "low" },

  // Package managers (read/lock operations)
  { id: "NPM_READ", regex: /^npm\s+(list|ls|outdated|audit|view)(\s+.*)?$/, message: "npm read operation", severity: "low" },
  { id: "PIP_READ", regex: /^pip\s+(list|show|freeze)(\s+.*)?$/, message: "pip read operation", severity: "low" },
  { id: "YARN_READ", regex: /^yarn\s+(list|outdated|why)(\s+.*)?$/, message: "yarn read operation", severity: "low" },

  // === WINDOWS-SPECIFIC SAFE PATTERNS ===
  { id: "WIN_DIR", regex: /^dir(\s+.*)?$/i, message: "Windows list directory", severity: "low" },
  { id: "WIN_TYPE", regex: /^type\s+.+$/i, message: "Windows display file", severity: "low" },
  { id: "WIN_MORE", regex: /^more\s+.+$/i, message: "Windows page file", severity: "low" },
  { id: "WIN_WHERE", regex: /^where\s+.+$/i, message: "Windows locate command", severity: "low" },
  { id: "WIN_HOSTNAME", regex: /^hostname\s*$/i, message: "Windows hostname", severity: "low" },
  { id: "WIN_WHOAMI", regex: /^whoami\s*$/i, message: "Windows whoami", severity: "low" },
  { id: "WIN_SYSTEMINFO", regex: /^systeminfo\s*$/i, message: "Windows system info", severity: "low" },
  { id: "WIN_VER", regex: /^ver\s*$/i, message: "Windows version", severity: "low" },
  { id: "WIN_SET", regex: /^set\s*$/i, message: "Windows show env vars", severity: "low" },

  // PowerShell read-only
  { id: "PS_GET_CONTENT", regex: /^Get-Content\s+.+$/i, message: "PowerShell read file", severity: "low" },
  { id: "PS_GET_CHILDITEM", regex: /^Get-ChildItem(\s+.*)?$/i, message: "PowerShell list items", severity: "low" },
  { id: "PS_GET_LOCATION", regex: /^Get-Location\s*$/i, message: "PowerShell get location", severity: "low" },
  { id: "PS_GET_ITEM", regex: /^Get-Item\s+.+$/i, message: "PowerShell get item", severity: "low" },
  { id: "PS_GET_PROCESS", regex: /^Get-Process\s*$/i, message: "PowerShell list processes", severity: "low" },
  { id: "PS_GET_SERVICE", regex: /^Get-Service\s*$/i, message: "PowerShell list services", severity: "low" },
  { id: "PS_PWD", regex: /^\$PWD\s*$/i, message: "PowerShell current dir", severity: "low" },

  // Windows cleanup (regeneratable)
  { id: "WIN_RD_NODE_MODULES", regex: /^rd\s+(\/s|\/q|\s)+\s*node_modules\s*$/i, message: "Windows remove node_modules", severity: "low" },
  { id: "WIN_RD_PYCACHE", regex: /^rd\s+(\/s|\/q|\s)+\s*__pycache__\s*$/i, message: "Windows remove pycache", severity: "low" },
  { id: "WIN_RD_VENV", regex: /^rd\s+(\/s|\/q|\s)+\s*\.venv\s*$/i, message: "Windows remove venv", severity: "low" },
  { id: "WIN_RD_DIST", regex: /^rd\s+(\/s|\/q|\s)+\s*dist\s*$/i, message: "Windows remove dist", severity: "low" },
  { id: "WIN_RD_BUILD", regex: /^rd\s+(\/s|\/q|\s)+\s*build\s*$/i, message: "Windows remove build", severity: "low" },
  { id: "WIN_RMDIR_NODE_MODULES", regex: /^rmdir\s+(\/s|\/q|\s)+\s*node_modules\s*$/i, message: "Windows rmdir node_modules", severity: "low" },

  // === MACOS-SPECIFIC SAFE PATTERNS ===
  { id: "MACOS_DISKUTIL_LIST", regex: /^diskutil\s+list\s*$/, message: "macOS list disks", severity: "low" },
  { id: "MACOS_DISKUTIL_INFO", regex: /^diskutil\s+info\s+.+$/, message: "macOS disk info", severity: "low" },
  { id: "MACOS_SYSTEM_PROFILER", regex: /^system_profiler\s+.+$/, message: "macOS system profiler", severity: "low" },
  { id: "MACOS_SW_VERS", regex: /^sw_vers\s*$/, message: "macOS version", severity: "low" },
  { id: "MACOS_DEFAULTS_READ", regex: /^defaults\s+read\s+.+$/, message: "macOS read defaults", severity: "low" },
  { id: "MACOS_SECURITY_FIND_CERT", regex: /^security\s+find-certificate\s+.+$/, message: "macOS find certificate", severity: "low" },
  { id: "MACOS_TMUTIL_LISTBACKUPS", regex: /^tmutil\s+listbackups\s*$/, message: "macOS list backups", severity: "low" },
  { id: "MACOS_TMUTIL_STATUS", regex: /^tmutil\s+status\s*$/, message: "macOS backup status", severity: "low" },
  { id: "MACOS_LAUNCHCTL_LIST", regex: /^launchctl\s+list\s*$/, message: "macOS list services", severity: "low" },
  { id: "MACOS_DSCL_READ", regex: /^dscl\s+\.\s+-read\s+.+$/, message: "macOS read directory", severity: "low" },
  { id: "MACOS_SPCTL_STATUS", regex: /^spctl\s+--status\s*$/, message: "macOS Gatekeeper status", severity: "low" }
];

// ============================================================
// PATTERN CHECKING FUNCTIONS
// ============================================================

/**
 * Split a command string into individual commands for separate analysis.
 * Handles &&, ||, ;, and | (pipes).
 */
function splitChainedCommands(command: string): string[] {
  const commands: string[] = [];
  let current = "";
  let i = 0;
  let inQuotes = false;
  let quoteChar: string | null = null;

  while (i < command.length) {
    const char = command[i];

    // Track quote state
    if ((char === '"' || char === "'") && (i === 0 || command[i - 1] !== "\\")) {
      if (!inQuotes) {
        inQuotes = true;
        quoteChar = char;
      } else if (char === quoteChar) {
        inQuotes = false;
        quoteChar = null;
      }
    }

    // Only split on operators outside quotes
    if (!inQuotes) {
      // Check for && or ||
      if (i < command.length - 1) {
        const twoChar = command.substring(i, i + 2);
        if (twoChar === "&&" || twoChar === "||") {
          if (current.trim()) {
            commands.push(current.trim());
          }
          current = "";
          i += 2;
          continue;
        }
      }

      // Check for ; or |
      if (char === ";" || char === "|") {
        if (current.trim()) {
          commands.push(current.trim());
        }
        current = "";
        i += 1;
        continue;
      }
    }

    current += char;
    i += 1;
  }

  // Add final command
  if (current.trim()) {
    commands.push(current.trim());
  }

  return commands.length > 0 ? commands : [command];
}

/**
 * Check if a command matches any dangerous pattern
 * @param command The command to check
 * @returns The matching pattern, or null if no match
 */
export function checkDangerousPatterns(command: string): Pattern | null {
  const normalizedCommand = command.trim();

  // First, check the WHOLE command (important for patterns like "curl ... | bash")
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.regex.test(normalizedCommand)) {
      return pattern;
    }
  }

  // Then split on && ; || and check each part (but NOT on | for pipe commands)
  // This catches "safe_cmd && dangerous_cmd"
  const parts = normalizedCommand.split(/\s*(?:&&|\|\||;)\s*/);

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
  if (!normalizedCommand) return { id: "EMPTY", regex: /^$/, message: "Empty command", severity: "low" };

  const parts = splitChainedCommands(normalizedCommand);

  // All parts must match a safe pattern
  for (const part of parts) {
    let partIsSafe = false;
    for (const pattern of SAFE_PATTERNS) {
      if (pattern.regex.test(part)) {
        partIsSafe = true;
        break;
      }
    }
    if (!partIsSafe) {
      return null;
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
