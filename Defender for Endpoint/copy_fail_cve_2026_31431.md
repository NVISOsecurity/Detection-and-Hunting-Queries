# Copy Fail - CVE-2026-31431

## Description

Detects the execution of the following commands within a 5-minute window: /sbin/modprobe -q -- net-pf-38, /sbin/modprobe -q -- algif-aead, /sbin/modprobe -q -- crypto-authencesn(hmac(sha256),cbc(aes), and a non-root Python process attempting to run su. When all four commands occur together this may indicate potential exploitation of opy Fail (CVE-2026-31431).

## References

- https://github.com/theori-io/copy-fail-CVE-2026-31431/blob/main/copy_fail_exp.py
- https://copy.fail/

## Query

### Defender for Endpoint


```KQL
let bin_buckets = 5m;
// Load the Linux kernel module that provides support for the AF_ALG (38) crypto socket interface.
// /sbin/modprobe -q -- net-pf-38
let modprobe_AF_ALG = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where ProcessCommandLine has_all ("/sbin/modprobe", "net-pf-38")
| extend cmd_type = "modprobe_AF_ALG";
// Loads the Linux kernel module algif-aead (AEAD algorithm interface)
// /sbin/modprobe -q -- algif-aead
let modprobe_AEAD = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where ProcessCommandLine has_all ("/sbin/modprobe", "algif-aead")
| extend cmd_type = "modprobe_AEAD";
// Loads a Linux kernel module for the combined algorithm HMAC-SHA256 authentication with AES-CBC encryption
// /sbin/modprobe -q -- crypto-authencesn(hmac(sha256),cbc(aes))
let modprobe_HMAC_SHA256_AES_CBC = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where ProcessCommandLine has_all ("/sbin/modprobe", "crypto-authencesn(hmac(sha256),cbc(aes)")
| extend cmd_type = "modprobe_HMAC_SHA256_AES_CBC";
let spawning_su = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where AccountName != "root"
| where InitiatingProcessFileName startswith "python"
| where ProcessCommandLine matches regex @"\bsu\b" or ProcessCommandLine contains "sh -c -- su"
| extend cmd_type = "spawning_su";
union spawning_su, modprobe_AF_ALG, modprobe_AEAD, modprobe_HMAC_SHA256_AES_CBC
| extend TimestampWithSeconds = format_datetime(Timestamp, 'yyyy-MM-dd HH:mm:ss.fff')
| sort by TimestampWithSeconds
| extend AdditionalFields = todynamic(AdditionalFields)
| extend ProcessPosixSessionId = AdditionalFields.ProcessPosixSessionId
| extend ProcessPosixAttachedTerminal = AdditionalFields.ProcessPosixAttachedTerminal
| extend ProcessCurrentWorkingDirectory = AdditionalFields.ProcessCurrentWorkingDirectory
| project-reorder Timestamp, TimestampWithSeconds, ProcessPosixSessionId, ProcessPosixAttachedTerminal, ProcessCurrentWorkingDirectory, ActionType, AccountName, ProcessId, ProcessCommandLine, FileName, FolderPath, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentId, InitiatingProcessParentFileName
| summarize 
    minTimestampWithSeconds = min(TimestampWithSeconds),
    maxTimestampWithSeconds = max(TimestampWithSeconds),
    CommandExecutions = make_set(ProcessCommandLine),
    CommandTypes = make_set(cmd_type),
    Accounts = make_set(AccountName)
by DeviceId, DeviceName, bin(Timestamp, bin_buckets)
| where array_length(CommandTypes) == 4 // We need all 4 to assume exploitation
```

Alternative query that detects the modprobe command executions without the su attempt.

```KQL
let bin_buckets = 5m;
// Load the Linux kernel module that provides support for the AF_ALG (38) crypto socket interface.
// /sbin/modprobe -q -- net-pf-38
let modprobe_AF_ALG = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where ProcessCommandLine has_all ("/sbin/modprobe", "net-pf-38")
| extend cmd_type = "modprobe_AF_ALG";
// Loads the Linux kernel module algif-aead (AEAD algorithm interface)
// /sbin/modprobe -q -- algif-aead
let modprobe_AEAD = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where ProcessCommandLine has_all ("/sbin/modprobe", "algif-aead")
| extend cmd_type = "modprobe_AEAD";
// Loads a Linux kernel module for the combined algorithm HMAC-SHA256 authentication with AES-CBC encryption
// /sbin/modprobe -q -- crypto-authencesn(hmac(sha256),cbc(aes))
let modprobe_HMAC_SHA256_AES_CBC = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where ProcessCommandLine has_all ("/sbin/modprobe", "crypto-authencesn(hmac(sha256),cbc(aes)")
| extend cmd_type = "modprobe_HMAC_SHA256_AES_CBC";
union modprobe_AF_ALG, modprobe_AEAD, modprobe_HMAC_SHA256_AES_CBC
| extend TimestampWithSeconds = format_datetime(Timestamp, 'yyyy-MM-dd HH:mm:ss.fff')
| sort by TimestampWithSeconds
| extend AdditionalFields = todynamic(AdditionalFields)
| extend ProcessPosixSessionId = AdditionalFields.ProcessPosixSessionId
| extend ProcessPosixAttachedTerminal = AdditionalFields.ProcessPosixAttachedTerminal
| extend ProcessCurrentWorkingDirectory = AdditionalFields.ProcessCurrentWorkingDirectory
| project-reorder Timestamp, TimestampWithSeconds, ProcessPosixSessionId, ProcessPosixAttachedTerminal, ProcessCurrentWorkingDirectory, ActionType, AccountName, ProcessId, ProcessCommandLine, FileName, FolderPath, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentId, InitiatingProcessParentFileName
| summarize 
    minTimestampWithSeconds = min(TimestampWithSeconds),
    maxTimestampWithSeconds = max(TimestampWithSeconds),
    CommandExecutions = make_set(ProcessCommandLine),
    CommandTypes = make_set(cmd_type),
    Accounts = make_set(AccountName)
by DeviceId, DeviceName, bin(Timestamp, bin_buckets)
| where array_length(CommandTypes) == 3 // We need all 3 to assume exploitation
```

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                                                                 |
| ------------------- | ------------ | ------------------------------------------------------------------------------ |
| Privilege Escalation| T1068        | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|


## Version History
| Version | Date       | Comments                          |
| ------- |------------| ----------------------------------|
| 1.0     | 2026-04-30 | Initial query published           |