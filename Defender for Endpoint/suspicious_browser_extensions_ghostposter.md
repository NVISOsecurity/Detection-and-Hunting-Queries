# Ghostposter Suspicious Browser Extensions

## Description

Security researchers have uncovered a large-scale campaign involving 17 malicious browser extensions associated with the GhostPoster threat actor. These extensions were distributed via official stores for Chrome, Firefox, and Edge, accumulating more than 840,000 installations. To evade store reviews and static analysis, the operators leveraged steganography within PNG icon files, delayed payload activation, and a multi-stage delivery chain. The following  queries identift browser extensions linked to the GhostPoster campaign.

## References

- https://www.koi.ai/blog/inside-ghostposter-how-a-png-icon-infected-50-000-firefox-browser-users
- https://layerxsecurity.com/blog/browser-extensions-gone-rogue-the-full-scope-of-the-ghostposter-campaign/

## Queries

### Defender for Endpoint

If you have Microsoft Defender Vulnerability Management run:

```KQL
let extension_ids = dynamic([
    "maiackahflfnegibhinjhpbgeoldeklb", // Page Screenshot Clipper
    "kjkhljbbodkfgbfnhjfdchkjacdhmeaf", // Full Page Screenshot
    "ielbkcjohpgmjhoiadncabphkglejgih", // Convert Everything
    "obocpangfamkffjllmcfnieeoacoheda", // Translate Selected Text with Google
    "dhnibdhcanplpdkcljgmfhbipehkgdkk", // Youtube Download
    "gmciomcaholgmklbfangdjkneihfkddd", // RSS Feed
    "fbobegkkdmmcnmoplkgdmfhdlkjfelnb", // Ads Block Ultimate
    "onlofoccaenllpjmalbnilfacjmcfhfk", // AdBlocker
    "bmmchpeggdipgcobjbkcjiifgjdaodng", // Color Enhancer
    "knoibjinlbaolannjalfdjiloaadnknj", // Floating Player – PiP Mode
    "jihipmfmicjjpbpmoceapfjmigmemfam", // One Key Translate
    "ajbkmeegjnmaggkhmibgckapjkohajim", // Cool Cursor
    "fcoongackakfdmiincikmjgkedcgjkdp", // Google Translate in Right Click
    "fmchencccolmmgjmaahfhpglemdcjfll", // Translate Selected Text with Right Click
    "amazon-price-history",            // Amazon Price History
    "save-image-to-pinterest",         // Save Image to Pinterest on Right Click
    "instagram-downloading"            // Instagram Downloader
]);
DeviceTvmBrowserExtensions
| where ExtensionId in (extension_ids)
```

Can also be detected from DeviceFileEvents as the extension id is part of the Folder path.

```KQL
let extension_ids = dynamic([
    "maiackahflfnegibhinjhpbgeoldeklb", // Page Screenshot Clipper
    "kjkhljbbodkfgbfnhjfdchkjacdhmeaf", // Full Page Screenshot
    "ielbkcjohpgmjhoiadncabphkglejgih", // Convert Everything
    "obocpangfamkffjllmcfnieeoacoheda", // Translate Selected Text with Google
    "dhnibdhcanplpdkcljgmfhbipehkgdkk", // Youtube Download
    "gmciomcaholgmklbfangdjkneihfkddd", // RSS Feed
    "fbobegkkdmmcnmoplkgdmfhdlkjfelnb", // Ads Block Ultimate
    "onlofoccaenllpjmalbnilfacjmcfhfk", // AdBlocker
    "bmmchpeggdipgcobjbkcjiifgjdaodng", // Color Enhancer
    "knoibjinlbaolannjalfdjiloaadnknj", // Floating Player – PiP Mode
    "jihipmfmicjjpbpmoceapfjmigmemfam", // One Key Translate
    "ajbkmeegjnmaggkhmibgckapjkohajim", // Cool Cursor
    "fcoongackakfdmiincikmjgkedcgjkdp", // Google Translate in Right Click
    "fmchencccolmmgjmaahfhpglemdcjfll", // Translate Selected Text with Right Click
    "amazon-price-history",            // Amazon Price History
    "save-image-to-pinterest",         // Save Image to Pinterest on Right Click
    "instagram-downloading"            // Instagram Downloader
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

## Version History
| Version | Date       | Comments                          |
| ------- |------------| ----------------------------------|
| 1.0     | 2025-01-27 | Initial query published           |