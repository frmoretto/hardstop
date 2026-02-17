---
description: Skip Hardstop safety check for the next command only
allowed-tools: ["Bash"]
---

# Skip Next Command

Set a one-time bypass flag so the next shell command skips the safety check.

## Your Task

Run this command to set the skip flag:

```bash
python "${CLAUDE_PLUGIN_ROOT}/commands/hs_cmd.py" skip $ARGUMENTS
```

Then inform the user that the next command will bypass safety checks, but protection will resume automatically after that.
