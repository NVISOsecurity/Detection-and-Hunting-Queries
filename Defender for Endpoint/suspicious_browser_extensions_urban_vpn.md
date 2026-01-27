# Urban VPN Suspicious Broswer Extensions

## Description

Detects the presence of Urban VPN browser extensions that inject scripts when users visit AI chat platforms to intercept and exfiltrate user prompts and responses. These extensions where identified to collect AI conversations, silently transmitting the data to third-party analytics endpoints without user consent.

## References

- https://www.koi.ai/blog/urban-vpn-browser-extension-ai-conversations-data-collection

## Query

### <Defender for Endpoint>

If you have Microsoft Defender Vulnerability Management run:

```KQL
let extension_ids = dynamic(["eppiocemhmnlbhjplcgkofciiegomcon", // Urban VPN Proxy (Chrome)
"almalgbpmcfpdaopimbdchdliminoign", // Urban Browser Guard (Chrome)
"feflcgofneboehfdeebcfglbodaceghj", // Urban Ad Blocker (Chrome)
"pphgdbgldlmicfdkhondlafkiomnelnk", // 1ClickVPN Proxy for Chrome
"nimlmejbmnecnaghgmbahmbaddhjbecg", // Urban VPN Proxy (Edge)
"jckkfbfmofganecnnpfndfjifnimpcel", // Urban Browser Guard (Edge)
"gcogpdjkkamgkakkjgeefgpcheonclca", // Urban Ad Blocker (Edge)
"deopfbighgnpgfmhjeccdifdmhcjckoe" // 1ClickVPN Proxy for Edge
]);
DeviceTvmBrowserExtensions
| where ExtensionId in (extension_ids)
```

Can also be detected from DeviceFileEvents as the extension id is part of the Folder path.

```KQL
let extension_ids = dynamic(["eppiocemhmnlbhjplcgkofciiegomcon", // Urban VPN Proxy (Chrome)
"almalgbpmcfpdaopimbdchdliminoign", // Urban Browser Guard (Chrome)
"feflcgofneboehfdeebcfglbodaceghj", // Urban Ad Blocker (Chrome)
"pphgdbgldlmicfdkhondlafkiomnelnk", // 1ClickVPN Proxy for Chrome
"nimlmejbmnecnaghgmbahmbaddhjbecg", // Urban VPN Proxy (Edge)
"jckkfbfmofganecnnpfndfjifnimpcel", // Urban Browser Guard (Edge)
"gcogpdjkkamgkakkjgeefgpcheonclca", // Urban Ad Blocker (Edge)
"deopfbighgnpgfmhjeccdifdmhcjckoe" // 1ClickVPN Proxy for Edge
]);
DeviceFileEvents
| project Timestamp, ActionType, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, DeviceName, DeviceId
| where FolderPath has_any (extension_ids)
| summarize min(Timestamp), max(Timestamp), ActionTypes = make_set(ActionType), FolderPaths = make_set(FolderPath) by DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessAccountName
```

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                                                                 |
| ------------------- | ------------ | ------------------------------------------------------------------------------ |
| Persistence         | T1547        | [Software Extensions: Browser Extensions](https://attack.mitre.org/techniques/T1176/001/)|
| Exfiltration        | T1041        | [Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)     |


## Version History
| Version | Date       | Comments                          |
| ------- |------------| ----------------------------------|
| 1.0     | 2025-01-27 | Initial query published           |