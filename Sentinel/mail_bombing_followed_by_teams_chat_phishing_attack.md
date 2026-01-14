# Mail Bombing followed by Teams Chat Phishing Attack

## Description

Adversaries first bomb a user's mailbox with spam emails and then pose as Help Desk or IT Support on Microsoft Teams to trick their potential victims into providing access. This social engineering tactic is being attributed to the ransomware group Black Basta.

## References

- https://blog.nviso.eu/2025/01/16/detecting-teams-chat-phishing-attacks-black-basta/
- https://www.forbes.com/sites/daveywinder/2025/01/20/new-email-warning-hackers-target-microsoft-users-with-fatigue-attack/

## Query

### Sentinel

```
// Set the threshold for identifying a high number of bad emails and the time window for chat creation
let bad_email_threshold = 100;
let chat_creation_time_diff_minutes = 180;
// Filter inbound emails that have threat types or specific email actions applied
EmailEvents 
| where EmailDirection == "Inbound"
| where ThreatTypes != "" or EmailActionPolicy != ""
// Summarize the count of bad emails and the time range they were received, grouped by hour and recipient email address
| summarize
    BadEmailCount = count(),
    minTimeGenerated = min(TimeGenerated),
    maxTimeGenerated = max(TimeGenerated),
    Subjects = make_set(Subject, 100),
    SenderFromAddresses = make_set(SenderFromAddress, 100)
    by bin(TimeGenerated, 1h), RecipientEmailAddress
// Filter for recipients with a count of bad emails exceeding the threshold
| where BadEmailCount > bad_email_threshold
// Normalize the recipient email address to lowercase for consistent matching
| extend RecipientEmailAddress = tolower(RecipientEmailAddress)
// Further summarize the data by 3-hour bins to identify potential email bombing incidents
| summarize
    BadEmailCount = sum(BadEmailCount),
    EmailBombingTimeGeneratedStart = min(minTimeGenerated),
    EmailBombingTimeGeneratedEnd = max(maxTimeGenerated),
    Subjects = make_set(Subjects, 100),
    SenderFromAddresses = make_set(SenderFromAddresses, 100)
    by bin(TimeGenerated, 3h), RecipientEmailAddress
// Join with OfficeActivity data to find chat creation events related to the potentially bombed email addresses
| join kind=inner (
    OfficeActivity
    | where RecordType == "MicrosoftTeams"
    | where Operation == "ChatCreated"
    | where CommunicationType == "OneOnOne"
    // Normalize the user ID to lowercase for consistent matching
    | extend UserId = tolower(UserId)
    )
    on $left.RecipientEmailAddress == $right.UserId
// Extract details about the chat participants and the time the chat was created
| extend Member0DisplayName = Members[0].DisplayName
| extend Member0UPN = Members[0].UPN
| extend Member1DisplayName = Members[1].DisplayName
| extend Member1UPN = Members[1].UPN
| extend ChatCreationTimeGenerated = TimeGenerated1
// Calculate the time difference between the chat creation and the start/end of the email bombing period
| extend ChatCreationTimeDifferenceStart = datetime_diff('minute', ChatCreationTimeGenerated, EmailBombingTimeGeneratedStart)
| extend ChatCreationTimeDifferenceEnd = datetime_diff('minute', ChatCreationTimeGenerated, EmailBombingTimeGeneratedEnd)
// Filter chats that were created within the specified time window of the email bombing period
| where (ChatCreationTimeDifferenceStart >= 0 and ChatCreationTimeDifferenceStart <= chat_creation_time_diff_minutes) or (ChatCreationTimeDifferenceEnd >= 0 and ChatCreationTimeDifferenceEnd <= chat_creation_time_diff_minutes)
// Select the relevant fields to display in the final result
| project
    Operation,
    CommunicationType,
    ChatCreationTimeGenerated,
    EmailBombingTimeGeneratedStart,
    EmailBombingTimeGeneratedEnd,
    ChatCreationTimeDifferenceStart,
    ChatCreationTimeDifferenceEnd,
    Member0DisplayName,
    Member0UPN,
    Member1DisplayName,
    Member1UPN,
    RecipientEmailAddress,
    BadEmailCount,
    Subjects,
    SenderFromAddresses,
    UserId,
    ClientIP,
    Members,
    ExtraProperties
```

## MITRE ATT&CK Mapping

| Tactic   | Technique ID | Technique Name                      |
| -------- | -------------- | ----------------------------------|
| Initial Access | T1566 | [Phishing](https://attack.mitre.org/techniques/T1566/) |

## Author
- Name: Stamatis Chatzimangou
- Github: https://github.com/st0pp3r
- X: [https://x.com/\_st0pp3r\_](https://x.com/_st0pp3r_)
- LinkedIn: https://www.linkedin.com/in/stamatis-chatzimangou/

## Version History
| Version | Date       | Comments                          |
| ------- |------------| ----------------------------------|
| 1.0     | 2025-01-16 | Initial publish                   |