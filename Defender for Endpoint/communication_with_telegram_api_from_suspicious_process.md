# Communication with Telegram API from Suspicious Process

## Description

Telegram has constantly been the subject of abuse by multiple threat actors, favored for its anonymity, accessibility, resilience, and operational advantages. The following query detects potential abuse of the Telegram Bot API for Command and Control (C2) by identifying command-line usage of tools or network communications accessing api.telegram.org/bot, which is known to be used by adversaries to send or receive commands via Telegram bots.

## References

- https://blog.nviso.eu/2025/12/16/the-detection-response-chronicles-exploring-telegram-abuse/

## Query

### Defender for Endpoint

```KQL
(DeviceProcessEvents
| where FileName in ("cmd.exe", "curl.exe", "powershell.exe", "pwsh.exe")
| where ProcessCommandLine contains "api.telegram.org"
| project-reorder InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine)
| union (DeviceNetworkEvents
| where RemoteUrl contains "api.telegram.org"
| project-reorder RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessFileName
| where InitiatingProcessFileName in ("curl.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"))
```

## MITRE ATT&CK Mapping

| Tactic   | Technique ID | Technique Name                      |
| -------- | -------------- | ----------------------------------|
| Command and Control | T1102 | [Web Service](https://attack.mitre.org/techniques/T1102/) |
| Command and Control | T1071.001 | [Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |

## Version History
| Version | Date       | Comments                          |
| ------- |------------| ----------------------------------|
| 1.0     | 2025-01-26 | Initial publish                   |