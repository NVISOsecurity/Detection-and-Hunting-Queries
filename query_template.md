# Query Title

## Description

Description of the query and the bahavior we are trying to detect.

## References

- https://github.com/NVISOsecurity
- https://github.com/NVISOsecurity/Detection-and-Hunting-Queries/
- 

## Query

### <Sentinel/Defender for Endpoint>

```KQL
// Paste your query here
DeviceEvents
| where Sth == "sth"
```

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                                                                 |
| ------------------- | ------------ | ------------------------------------------------------------------------------ |
| Initial Access      | T1566        | [Phishing](https://attack.mitre.org/techniques/T1566/)                          |
| Execution           | T1059        | [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)|
| Persistence         | T1547        | [Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)|
| Privilege Escalation| T1068        | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)|
| Defense Evasion     | T1027        | [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) |
| Credential Access   | T1003        | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)            |
| Discovery           | T1087        | [Account Discovery](https://attack.mitre.org/techniques/T1087/)                |
| Lateral Movement    | T1021        | [Remote Services](https://attack.mitre.org/techniques/T1021/)                  |
| Collection          | T1114        | [Email Collection](https://attack.mitre.org/techniques/T1114/)                 |
| Command and Control | T1071        | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)      |
| Exfiltration        | T1041        | [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)     |
| Impact              | T1486        | [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)        |


## Version History
| Version | Date       | Comments                          |
| ------- |------------| ----------------------------------|
| 1.0     | 2025-01-15 | Initial publish                   |
| 1.1     | 2025-01-16 | Changes to the query              |