# Remote Application Installation via RunDLL ClickOnce App

## Description

ClickOnce is a deployment method that allows deployment of Windows-based applications. It can be used via Dfsvc.exe and dfshim.dll.
An adversary can leverage this method to install an arbitrary application used for malicious purposes. This query identifies the execution of a remotely hosted application via rundll,
identifies the network connection from the respected process and gathers information for the files that have been created. In can be combined with GlobalPrevalance information or File Signature information
to identify suspicious or malicious content execution.

## References

- https://www.trellix.com/blogs/research/oneclik-a-clickonce-based-red-team-campaign-simulating-apt-tactics-in-energy-infrastructure/
- https://thehackernews.com/2025/06/oneclik-malware-targets-energy-sector.html

## Query

### <Defender for Endpoint>

```KQL
DeviceProcessEvents 
| where Timestamp >= ago(30d) 
| where FileName =~ "RUNDLL32.EXE"
| where ProcessCommandLine contains "dfshim.dll" 
| where ProcessCommandLine has_any ('ShOpenVerbApplication', 'ShOpenVerbShortcut')
| join kind=leftouter DeviceNetworkEvents on $left.DeviceName == $right.DeviceName, $left.ProcessId == $right.InitiatingProcessParentId 
| where iff(isnotempty(RemoteUrl), ProcessCommandLine contains RemoteUrl, False) or iff(isnotempty(RemoteIP), ProcessCommandLine contains RemoteIP, False) 
| where RemoteIPType == 'Public'
| project-rename NetConnection_Timestamp = Timestamp1, NetConnection_InitiatingProcessFileName = InitiatingProcessFileName1, NetConnection_InitiatingProcessId = InitiatingProcessId1
| join kind=leftouter DeviceFileEvents on $left.DeviceName == $right.DeviceName, $left.NetConnection_InitiatingProcessId == $right.InitiatingProcessId, $left.NetConnection_InitiatingProcessFileName == $right.InitiatingProcessFileName
| project-rename FileCreated_FolderPath = FolderPath1, FileCreated_SHA256 = SHA2561, FileCreated_Timestamp = Timestamp1
| invoke FileProfile(FileCreated_SHA256)
| project-reorder Timestamp, ProcessCommandLine, RemoteUrl, RemoteIP, FileCreated_Timestamp, FileCreated_FolderPath, FileCreated_SHA256, GlobalPrevalence, GlobalFirstSeen, IsExecutable
| where GlobalPrevalence <= 50 or SignatureState == "Unsigned"
```

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                                                                 |
| ------------------- | ------------ | ------------------------------------------------------------------------------ |
| Defense Evasion     | T1127.002    | [Trusted Developer Utilities Proxy Execution: ClickOnce](https://attack.mitre.org/techniques/T1127/002/)|


## Version History
| Version | Date       | Comments                          |
| ------- |------------| ----------------------------------|
| 1.0     | 2026-04-27 | Initial query published           |
