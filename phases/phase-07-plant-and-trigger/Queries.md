# Phase 07 - The Plant and the Trigger: Queries

> Query log for Phase 07. These queries prove automation, not a human, drove the mail behavior by validating MFA count, identifying Microsoft Flow Portal, discovering MicrosoftGraphActivityLogs, and proving the Graph call occurred before the mail event.

---

## Q26 - Disprove the Innocent Explanation

**Purpose:** Count successful MFA completions around the malicious mail behavior.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where ResultType == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize SuccessfulMFA = count()
```

**Expected Result:** `0`

**Pivot Produced:** Successful MFA count, `0`.

**Investigation Value:** Eliminates the innocent explanation that a human successfully completed MFA and manually triggered the forwarding.

---

## Q27 - Catch the Plant

**Purpose:** Identify the automation application touched by the compromised session.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize SignIns = count() by AppDisplayName
| order by SignIns desc
```

**Expected Result:** `Microsoft Flow Portal`

**Pivot Produced:** Automation app, `Microsoft Flow Portal`.

**Investigation Value:** Redirects the investigation from mailbox-only review to Flow / Power Automate and Graph telemetry.

---

## Q28 - The Cause Behind the Forward

**Purpose:** Discover which table contains the event that actually caused the forwarded mail.

**KQL Query**
```kql
search *
| summarize count() by $table
| order by count_ desc
```

**Expected Result:** `MicrosoftGraphActivityLogs`

**Pivot Produced:** Responsible table, `MicrosoftGraphActivityLogs`.

**Investigation Value:** Identifies Microsoft Graph as the telemetry layer that explains the forward.

---

## Q29 - Prove It With The Sequence

**Purpose:** Show the Graph call happened before the resulting mail event.

**KQL Query**
```kql
MicrosoftGraphActivityLogs
| project TimeGenerated,
          IPAddress,
          Location,
          RequestMethod,
          RequestUri,
          AppId,
          ServicePrincipalId
| order by TimeGenerated asc
```

**Expected Result:** The Graph API call appears before the forwarded mail event.

**Pivot Produced:** Sequence proof, `The Graph call`.

**Investigation Value:** Proves cause before effect: automation triggered the forwarding behavior.

---

## Supporting Query - Graph Mail Actions

**Purpose:** Narrow Graph activity to mail-related POST operations.

**KQL Query**
```kql
MicrosoftGraphActivityLogs
| where RequestMethod == "POST"
| where RequestUri has "forward"
    or RequestUri has "sendMail"
    or RequestUri has "messages"
| project TimeGenerated,
          IPAddress,
          Location,
          RequestMethod,
          RequestUri,
          AppId,
          ServicePrincipalId
| order by TimeGenerated asc
```

**Expected Result:** Shows mail-related Graph operations used later in Phase 08.

**Pivot Produced:** Graph forwarding/mail action timeline.

**Investigation Value:** Bridges Phase 07 automation proof into Phase 08 attribution.