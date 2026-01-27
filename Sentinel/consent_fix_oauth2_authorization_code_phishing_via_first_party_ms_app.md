# ConsentFix (a.k.a. AuthCodeFix) - OAuth2 Authorization Code Phishing via First-party Microsoft Application

## Description

ConsentFix (a.k.a. AuthCodeFix) is a technique where the adversary tricks the victim into generating an OAuth authorization code that is part of a localhost URL, by signing in to the Azure CLI instance (or other vulnerable applications). Then, the victim is instructed to copy that URL and paste it into a phishing website, essentially handing over the authorization code to the adversary, who is now able to exchange it for an access token. Using the access token, the adversary gets access to the victim's Microsoft account.

The query detects a successful interactive sign-in quickly followed by a non-interactive sign-in to the same Microsoft application from a different IP address and geographic location, which is the behavior you would normally expect from a successful execution of this attack. The query focuses on the affected Microsoft first-party applications (e.g., Azure CLI, Azure PowerShell, Visual Studio, VS Code). The query can be tuned to allowlist locations (countries), cities, or IP addresses and can also limit the comparison of the sign-ins to location (country) or city.

## References

- https://pushsecurity.com/blog/consentfix

## Query

### Sentinel

```KQL
let affected_application_ids = dynamic([
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46", // Microsoft Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2", // Microsoft Azure PowerShell
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1", // Visual Studio
    "aebc6443-996d-45c2-90f0-388ff96faa56", // Visual Studio Code
    "9bc3ab49-b65d-410a-85ad-de819febfddc", // Microsoft SharePoint Online Management Shell
    "a672d62c-fc7b-4e81-a576-e60dc46e951d" // Microsoft Power Query for Excel
    ]);
let lookback= 30d;
let sign_in_diff_seconds = 600;
let compare_location = true;
let compare_city = false;
let non_interactive_locations_allowlist = dynamic([]);
let non_interactive_cities_allowlist = dynamic([]);
let non_interactive_ips_allowlist = dynamic([]);
SigninLogs
| where TimeGenerated > ago(lookback)
| where AppId in (affected_application_ids)
| where ResultType == 0
| project
    InteractiveSignInTime = TimeGenerated,
    UserPrincipalName,
    InteractiveSignInLocation = Location,
    InteractiveSignInCity = tostring(parse_json(LocationDetails).city),
    InteractiveSignInIP = IPAddress,
    InteractiveSignInUserAgent = UserAgent,
    InteractiveSignInResourceIdentity = ResourceIdentity,
    InteractiveSignInResourceDisplayName = ResourceDisplayName,
    AppId,
    AppDisplayName,
    SessionId
| join kind=inner (AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(lookback)
    | where AppId in (affected_application_ids)
    | where ResultType == 0
    | project
        NonInteractiveSignInTime = TimeGenerated,
        UserPrincipalName,
        NonInteractiveSignInLocation = Location,
        NonInteractiveSignInCity = tostring(parse_json(LocationDetails).city),
        NonInteractiveSignInIP = IPAddress,
        NonInteractiveSignInUserAgent = UserAgent,
        NonInteractiveSignInResourceIdentity = ResourceIdentity,
        NonInteractiveSignInResourceDisplayName = ResourceDisplayName,
        AppId,
        AppDisplayName,
        SessionId
    )
    on UserPrincipalName, AppId, SessionId
| where NonInteractiveSignInLocation !in (non_interactive_locations_allowlist)
| where NonInteractiveSignInCity !in (non_interactive_cities_allowlist)
| where NonInteractiveSignInIP !in (non_interactive_ips_allowlist)
| where NonInteractiveSignInTime > InteractiveSignInTime // Interactive sign in precedes the non-interactive sign in
| extend TimeDiffSeconds = datetime_diff("second", NonInteractiveSignInTime, InteractiveSignInTime)
| where TimeDiffSeconds <= sign_in_diff_seconds
| where InteractiveSignInIP != NonInteractiveSignInIP
| where
    (compare_location and InteractiveSignInLocation != NonInteractiveSignInLocation and isnotempty(InteractiveSignInLocation) and isnotempty(NonInteractiveSignInLocation))
    or (compare_city and InteractiveSignInCity != NonInteractiveSignInCity and isnotempty(InteractiveSignInCity) and isnotempty(NonInteractiveSignInCity))
| project
    InteractiveSignInTime,
    NonInteractiveSignInTime,
    TimeDiffSeconds,
    UserPrincipalName,
    InteractiveSignInLocation,
    NonInteractiveSignInLocation,
    InteractiveSignInCity,
    NonInteractiveSignInCity,
    InteractiveSignInIP,
    NonInteractiveSignInIP,
    InteractiveSignInUserAgent,
    NonInteractiveSignInUserAgent,
    InteractiveSignInResourceIdentity,
    NonInteractiveSignInResourceIdentity,
    InteractiveSignInResourceDisplayName,
    NonInteractiveSignInResourceDisplayName,
    AppDisplayName,
    AppId
```

## MITRE ATT&CK Mapping

| Tactic              | Technique ID | Technique Name                                                                 |
| ------------------- | ------------ | ------------------------------------------------------------------------------ |
| Initial Access      | T1566        | [Phishing](https://attack.mitre.org/techniques/T1566/)                          |
| Credential Access   | T1003        | [Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)            |


## Version History
| Version | Date       | Comments                          |
| ------- |------------| ----------------------------------|
| 1.0     | 2025-01-15 | Initial query published           |