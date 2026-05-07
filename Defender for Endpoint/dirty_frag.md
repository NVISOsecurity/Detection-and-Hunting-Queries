# Dirty Frag

## Description

Detects the execution of the following commands within a 5-minute window: ```/sbin/modprobe -q -- net-pf-16-proto-6```, ```/sbin/modprobe -q -- xfrm-type-2-50```, 
```/sbin/modprobe -q -- crypto-echainiv(authencesn(hmac(sha256),cbc(aes))) ```. When all four commands occur together this may indicate potential exploitation of Dirty Frag.

## References

- https://x.com/v4bel/status/2052464007857185136
- https://github.com/V4bel/dirtyfrag

## Query

### Defender for Endpoint


```KQL
let bin_buckets = 5m;
// /sbin/modprobe -q -- net-pf-16-proto-6
let modprobe_AF_NETLINK = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where ProcessCommandLine has_all ("/sbin/modprobe", "net-pf-16-proto-6")
| extend cmd_type = "modprobe_AF_NETLINK";
// /sbin/modprobe -q -- xfrm-type-2-50
let modprobe_IPPROTO_ESP = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where ProcessCommandLine has_all ("/sbin/modprobe", "xfrm-type-2-50")
| extend cmd_type = "modprobe_IPPROTO_ESP";
// /sbin/modprobe -q -- crypto-echainiv(authencesn(hmac(sha256),cbc(aes)))
let modprobe_HMAC_SHA256_AES_CBC = DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where ProcessCommandLine has_all ("/sbin/modprobe", "crypto-echainiv(authencesn(hmac(sha256),cbc(aes)))")
| extend cmd_type = "modprobe_HMAC_SHA256_AES_CBC";
union modprobe_AF_NETLINK, modprobe_IPPROTO_ESP, modprobe_HMAC_SHA256_AES_CBC
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
| 1.0     | 2026-05-08 | Initial query published           |