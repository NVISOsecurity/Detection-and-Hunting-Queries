# QEMU Execution with Suspicious Arguments

## Description

Detects QEMU execution with stealth-oriented arguments such as very low memory allocation, disabled graphics output, and unrestricted user-mode networking.

## References

- https://blog.nviso.eu/2026/06/04/the-detection-response-chronicles-covert-operations-through-qemu/
- https://www.qemu.org/docs/master/about/index.html

## Query

### Defender for Endpoint

```KQL
DeviceProcessEvents
| where (ProcessVersionInfoInternalFileName =~ "qemu" and FileName !~ "qemu-img.exe") or FileName startswith "qemu-system"
| extend mem_value = toint(extract(@"\-m\s+(\d+)\S", 1, ProcessCommandLine)),
         mem_unit  = extract(@"\-m\s+\d+(\S)", 1, ProcessCommandLine)
| where ProcessCommandLine has_any ("-nographic", "restrict=off") or (isnotempty(mem_value) and mem_value < 100 and tolower(mem_unit) == "m")
| project-reorder ProcessCommandLine
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
