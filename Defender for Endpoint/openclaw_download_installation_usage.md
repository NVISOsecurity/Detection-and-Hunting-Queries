# OpenClaw Download, Installation or Usage

## Description

Detects downloads or installations of OpenClaw based on the OpenClaw's docs and installation scripts. A secondary query is provided to detect general usage in the environment based on process logs.

## References

- https://openclaw.ai/

## Queries

### Defender for Endpoint

Download or Installation

```KQL
DeviceProcessEvents
| where (FileName in ("node", "node.exe") and ProcessCommandLine contains " install " and ProcessCommandLine contains "openclaw@latest") or 
(FileName in ("curl", "curl.exe") and ProcessCommandLine contains "https://openclaw.ai") or
(FileName in ("git", "git.exe") and ProcessCommandLine contains "hhttps://github.com/openclaw/")
```

Usage

```KQL
let openclaw_caller_processes = dynamic(["git.exe", "git", "curl.exe", "curl", "node.exe", "node", "powershell.exe", "python", "python.exe", "notepad.exe", "code.exe", "schtasks.exe", "cmd.exe", "sh","sh.exe", "bash", "bash.exe", "env.exe", "pnpm", "crashhelper"]);
DeviceProcessEvents
| where FileName in (openclaw_caller_processes)
| where ProcessCommandLine contains "openclaw"
```

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                                                                 |
| ------------------- | ------------ | ------------------------------------------------------------------------------ |
| Initial Access      | T1204        | [Execution](https://attack.mitre.org/techniques/T1204/)                          |


## Version History
| Version | Date       | Comments                          |
| ------- |------------| ----------------------------------|
| 1.0     | 2025-01-15 | Initial queries published           |