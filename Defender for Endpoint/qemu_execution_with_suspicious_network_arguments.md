# QEMU Execution with Suspicious Network Arguments

## Description

Detects QEMU execution with suspicious networking and tunneling arguments such as host/guest forwarding, listen/connect socket directives, and stream/dgram transport patterns.

## References

- https://blog.nviso.eu/2026/06/04/the-detection-response-chronicles-covert-operations-through-qemu/
- https://www.qemu.org/docs/master/about/index.html

## Query

### Defender for Endpoint

```KQL
DeviceProcessEvents
| where (ProcessVersionInfoInternalFileName == "qemu" and FileName != "qemu-img.exe") or FileName startswith "qemu-system"
| where ProcessCommandLine matches regex @"hostfwd=(tcp|udp|unix)?:(([A-Za-z0-9\.\-\[\]\:]*?:\d+|\S+?))?\-[A-Za-z0-9\.\-\[\]\:]*:\d+" or
ProcessCommandLine matches regex @"guestfwd=(tcp)?:([A-Za-z0-9\.\-\[\]\:]*:\d+)\-((tcp)?:[A-Za-z0-9\.\-\[\]\:]*:\d+|cmd:\S+)" or
ProcessCommandLine matches regex @"(,|\s)(listen|connect)=[A-Za-z0-9\.\-\[\]\:]*:\d+" or
ProcessCommandLine matches regex @"stream,\S*(addr\.host=\S+?,addr\.port=\d+|addr\.path=)" or
ProcessCommandLine matches regex @"dgram,\S*(remote\.host=\S+?,remote\.port=\d+|remote\.path=)" 
| project-reorder FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
| join kind=inner (DeviceInfo | where OSPlatform startswith "Windows" | summarize by DeviceId | project DeviceId) on DeviceId
| where FolderPath !contains @"\Windows\System32\"
| where FolderPath !contains @"\Program Files"
```

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                                                    |
| ------------------- | ------------ | ----------------------------------------------------------------- |
| Command and Control | T1572        | [Protocol Tunneling](https://attack.mitre.org/techniques/T1572/) |
| Command and Control | T1571        | [Non-Standard Port](https://attack.mitre.org/techniques/T1571/)  |

## Version History
| Version | Date       | Comments                |
| ------- |------------| ------------------------|
| 1.0     | 2026-06-10 | Initial query published |
