# ClawdBot Suspicious VS Code Extensions

## Description

Detects the installation of a fake Clawdbot VS Code extension that installs screenConnect RAT as published in the aikido.dev blog post.

## References

- https://www.aikido.dev/blog/fake-clawdbot-vscode-extension-malware

## Queries

### Defender for Endpoint

Checks process command line arguments and folder path file modifications that may occur during the installation of the vs code extension.

```KQL
let suspicious_extension_identifiers = dynamic([
clawdbot.clawdbot-agent
]);
union(
DeviceProcessEvents
| where InitiatingProcessFileName == "code.exe"
| where FileName == "vsce-sign.exe"
| extend ExtFileName = extract(@"\\CachedExtensionVSIXs\\(\S+)", 1, ProcessCommandLine)
| extend ExtVersion = extract(@"(\d+\.\d+\.\d+)", 1, ExtFileName)
| extend ExtIdentifier = tostring(split(ExtFileName, strcat("-", ExtVersion))[0])
| project-reorder Timestamp, ExtIdentifier, ExtVersion, ExtFileName, DeviceId, DeviceName, ProcessCommandLine
| summarize min(Timestamp), max(Timestamp), make_set(DeviceName), make_set(ExtVersion), make_set(ExtFileName) by ExtIdentifier
),(
DeviceProcessEvents
| where (ProcessCommandLine contains @"\\code" or ProcessCommandLine contains @"/code") and ProcessCommandLine contains @"--install-extension"
| extend ExtIdentifier = extract(@'--install-extension\s+\^?"?(\S+)(?:\.vsix)?\"?\^?', 1, ProcessCommandLine)
| project-reorder Timestamp, ExtIdentifier, DeviceId, DeviceName, ProcessCommandLine
| summarize min(Timestamp), max(Timestamp), make_set(DeviceName) by ExtIdentifier
),(
DeviceFileEvents
| where FolderPath contains ".vscode\\extensions\\"
| extend ExtFileName = tostring(extract(@".vscode\\extensions\\(\S+?)(\\|$)", 1, FolderPath))
| where ExtFileName != "extensions.json"
| where not(ExtFileName matches regex @"^\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")
| extend ExtVersion = extract(@"(\d+\.\d+\.\d+)", 1, ExtFileName)
| extend ExtIdentifier = tostring(split(ExtFileName, strcat("-", ExtVersion))[0])
| project-reorder Timestamp, ExtIdentifier, ExtVersion, ExtFileName, DeviceId, DeviceName, FolderPath
| summarize min(Timestamp), max(Timestamp), make_set(DeviceName), make_set(ExtVersion), make_set(ExtFileName) by ExtIdentifier
)
| where ExtIdentifier in (suspicious_extension_identifiers)
```

Checks network indicators from the blog post.

```
DeviceNetworkEvents
| where RemoteIP == "179.43.176.32" or RemoteUrl has_any ("meeting.bulletmailer.net", "clawdbot.getintwopc.site", "getintwopc.site", "darkgptprivate.com")
```

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                                                                 |
| ------------------- | ------------ | ------------------------------------------------------------------------------ |
| Persistence         | T1176.002        | [Software Extensions: IDE Extensions](https://attack.mitre.org/techniques/T1176/002/)|


## Version History
| Version | Date       | Comments                          |
| ------- |------------| ----------------------------------|
| 1.0     | 2025-02-06 |  Initial query published       |