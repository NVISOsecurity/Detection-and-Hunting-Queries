# Zoom Stealer Suspicious Browser Extensions

## Description

The following queries detect the presence of browser extensions associated with the zoom stealer campaign. The Zoom Stealer focuses on the collection of corporate meeting intelligence. 

## References

- https://www.koi.ai/blog/darkspectre-unmasking-the-threat-actor-behind-7-8-million-infected-browsers#heading-3

## Queries

### <Defender for Endpoint>

If you have Microsoft Defender Vulnerability Management run:

```KQL
let extension_ids = dynamic([
"kfokdmfpdnokpmpbjhjbcabgligoelgp",
"pdadlkbckhinonakkfkdaadceojbekep",
"akmdionenlnfcipmdhbhcnkighafmdha",
"pabkjoplheapcclldpknfpcepheldbga",
"aedgpiecagcpmehhelbibfbgpfiafdkm",
"dpdgjbnanmmlikideilnpfjjdbmneanf",
"kabbfhmcaaodobkfbnnehopcghicgffo",
"cphibdhgbdoekmkkcbbaoogedpfibeme",
"ceofheakaalaecnecdkdanhejojkpeai",
"dakebdbeofhmlnmjlmhjdmmjmfohiicn",
"adjoknoacleghaejlggocbakidkoifle",
"pgpidfocdapogajplhjofamgeboonmmj",
"ifklcpoenaammhnoddgedlapnodfcjpn",
"ebhomdageggjbmomenipfbhcjamfkmbl",
"ajfokipknlmjhcioemgnofkpmdnbaldi",
"mhjdjckeljinofckdibjiojbdpapoecj",
"{7536027f-96fb-4762-9e02-fdfaedd3bfb5}"
]);
DeviceTvmBrowserExtensions
| where ExtensionId in (extension_ids)
```

Can also be detected from DeviceFileEvents as the extension id is part of the Folder path.

```KQL
let extension_ids = dynamic([
"kfokdmfpdnokpmpbjhjbcabgligoelgp",
"pdadlkbckhinonakkfkdaadceojbekep",
"akmdionenlnfcipmdhbhcnkighafmdha",
"pabkjoplheapcclldpknfpcepheldbga",
"aedgpiecagcpmehhelbibfbgpfiafdkm",
"dpdgjbnanmmlikideilnpfjjdbmneanf",
"kabbfhmcaaodobkfbnnehopcghicgffo",
"cphibdhgbdoekmkkcbbaoogedpfibeme",
"ceofheakaalaecnecdkdanhejojkpeai",
"dakebdbeofhmlnmjlmhjdmmjmfohiicn",
"adjoknoacleghaejlggocbakidkoifle",
"pgpidfocdapogajplhjofamgeboonmmj",
"ifklcpoenaammhnoddgedlapnodfcjpn",
"ebhomdageggjbmomenipfbhcjamfkmbl",
"ajfokipknlmjhcioemgnofkpmdnbaldi",
"mhjdjckeljinofckdibjiojbdpapoecj",
"{7536027f-96fb-4762-9e02-fdfaedd3bfb5}"
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