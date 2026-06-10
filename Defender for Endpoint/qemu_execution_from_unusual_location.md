# QEMU Execution from Unusual Location

## Description

Detects QEMU execution from non-standard paths and uncommon parent processes, filtering common legitimate emulator and tooling locations.

## References

- https://blog.nviso.eu/2026/06/04/the-detection-response-chronicles-covert-operations-through-qemu/
- https://www.qemu.org/docs/master/about/index.html

## Query

### Defender for Endpoint

```KQL
DeviceProcessEvents
| where (ProcessVersionInfoInternalFileName == "qemu" and FileName != "qemu-img.exe") or FileName startswith "qemu-system"
| where not(InitiatingProcessFileName startswith "qemu-system")
| where InitiatingProcessFileName != "emulator.exe"
| where InitiatingProcessFileName != "emulator"
| where InitiatingProcessFileName != "limactl"
| where InitiatingProcessFileName != "multipassd"
| where FolderPath !contains @"\Windows\System32\"
| where FolderPath !contains @"\Program Files"
| where FolderPath !contains @"\appdata\local\Android\Sdk\emulator\qemu\"
| where FolderPath !contains @"\Android\Sdk\emulator\qemu\"
| where FolderPath !contains @"\emulator\qemu\"
| where FolderPath !contains @"/Android/sdk/emulator/"
| where FolderPath !contains @"/usr/bin/"
| where FolderPath !contains @"/android-sdk/emulator/qemu/"
| where FolderPath !contains @"/sdk/android/emulator/"
| where FolderPath !contains @"/snap/lxd/"
| project-reorder InitiatingProcessCommandLine, InitiatingProcessFileName, FileName, FolderPath, ProcessCommandLine
```

```KQL
DeviceProcessEvents
| where (ProcessVersionInfoInternalFileName == "qemu" and FileName != "qemu-img.exe") or FileName startswith "qemu-system"
| where FolderPath contains @"\Users\" or FolderPath contains @"\temp\" or FolderPath contains @"/tmp/" or FolderPath contains @"/home/"
| project-reorder InitiatingProcessCommandLine, InitiatingProcessFileName, FileName, FolderPath, ProcessCommandLine
```

## MITRE ATT&CK Mapping

| Tactic          | Technique ID | Technique Name                                              |
| --------------- | ------------ | ----------------------------------------------------------- |
| Defense Evasion | T1036        | [Masquerading](https://attack.mitre.org/techniques/T1036/) |

## Version History
| Version | Date       | Comments                |
| ------- |------------| ------------------------|
| 1.0     | 2026-06-10 | Initial query published |
