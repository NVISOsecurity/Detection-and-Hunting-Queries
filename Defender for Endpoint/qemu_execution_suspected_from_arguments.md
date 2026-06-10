# QEMU Execution Suspected from Arguments

## Description

Detects QEMU-like execution based on command-line arguments, to detect scenarios where the QEMU binary has been renamed to evade simple name-based detections.

## References

- https://blog.nviso.eu/2026/06/04/the-detection-response-chronicles-covert-operations-through-qemu/
- https://www.qemu.org/docs/master/about/index.html

## Query

### Defender for Endpoint

```KQL
DeviceProcessEvents
| where ProcessCommandLine has_any (" -readconfig ", " -nic ", " -netdev ", " -device e1000", " -device virtio-net-pci", "-drive ", " -hda ", " -hdb ", " -hdc ", " -hdd ", " -nographic ", " -display ", "restrict=off")
| extend qemu_args = extract_all(@"( -readconfig | -nic | -netdev | -device e1000| -device virtio-net-pci| -drive | -hda | -hdb | -hdc | -hdd | -nographic | -display |restrict=off)", ProcessCommandLine)
| where array_length(qemu_args) >=2
| project-reorder qemu_args, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
| where ProcessCommandLine !contains "qemu"
| where FolderPath !contains @"\Windows\System32\"
| where FolderPath !contains @"\Program Files"
| where FolderPath !contains @"/usr/bin/"
```

## MITRE ATT&CK Mapping

| Tactic          | Technique ID | Technique Name                                              |
| --------------- | ------------ | ----------------------------------------------------------- |
| Defense Evasion | T1036        | [Masquerading](https://attack.mitre.org/techniques/T1036/) |

## Version History
| Version | Date       | Comments                |
| ------- |------------| ------------------------|
| 1.0     | 2026-06-10 | Initial query published |
