# Phase 02 - Session Scope: Queries

> Query log for Phase 02. Focus is the authentication mechanism: how the session survived MFA and how far one token reached.

---

## Q07 - How the Session Beat MFA

**Purpose:** Determine the authentication requirement the platform enforced on the attacker's sign-ins, to test whether MFA was satisfied or bypassed.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| project TimeGenerated, AuthenticationRequirement, AuthenticationDetails,
          ResultType, ResultDescription
| order by TimeGenerated asc
```

**Expected Result:** Sign-ins return `AuthenticationRequirement == singleFactorAuthentication`; the `AuthenticationDetails` blob shows no fresh MFA challenge, consistent with refresh-token / KMSI reuse.

**Pivot Produced:** Mechanism, token persistence (Keep Me Signed In), MFA bypassed via reuse rather than satisfied.

**Investigation Value:** Establishes that the attacker did not defeat MFA. This reframes containment toward session revocation.

---

## Q08 - The Control Surface That Let Them In

**Purpose:** Determine whether Conditional Access evaluated and acted on the attacker's sign-ins.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| project TimeGenerated, ConditionalAccessStatus, ConditionalAccessPolicies,
          ResultType
| order by TimeGenerated asc
```

**Expected Result:** `ConditionalAccessStatus == notApplied`, no CA policy was in scope.

**Pivot Produced:** Control gap, Conditional Access notApplied.

**Investigation Value:** Identifies the missing control that should have re-challenged or blocked the session. Feeds directly into Phase 08 Q36 (the control that never fired).

---

## Q09 - Failed Attempts Before Entry

**Purpose:** Identify failed authentication attempts preceding the successful session to characterize the access pattern and anchor the timeline.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultType != 0
| summarize FailedAttempts = count(), FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
        by IPAddress, ResultType, ResultDescription
| order by FailedAttempts desc
```

**Expected Result:** Returns **2** failed sign-in attempts before successful access.

**Pivot Produced:** Failed attempt count, `2`.

**Investigation Value:** Distinguishes attacker probing from the legitimate user's activity and sharpens the start-of-compromise timestamp.

---

## Q10 - Blast Radius of One Token

**Purpose:** Measure how many distinct cloud applications/resources were reachable from the single compromised session.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| summarize AppCount = dcount(AppDisplayName), Apps = make_set(AppDisplayName)
        by UserPrincipalName, IPAddress
| order by AppCount desc
```

**Expected Result:** Returns **7** applications/resources:

- `One Outlook Web`
- `OfficeHome`
- `Microsoft Teams Web Client`
- `Office 365 SharePoint Online`
- `SharePoint Online Web Client Extensibility`
- `Microsoft Flow Portal`
- `App Service`

**Pivot Produced:** Blast radius, `7` Microsoft 365 applications/resources from one token.

**Investigation Value:** Quantifies the cost of the single dismissed risk detection and motivates session-level, not app-level, containment.

---

## Q11 - One Continuous Session

**Purpose:** Confirm whether the attacker operated from one sustained session or re-authenticated repeatedly.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| summarize SignInCount = count(), FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated),
            Apps = make_set(AppDisplayName)
        by SessionId, IPAddress
| order by SignInCount desc
```

**Expected Result:** The attacker activity resolves to session ID `005d431a-380b-1f5e-e554-16d5010dc28e`.

**Pivot Produced:** Session ID, `005d431a-380b-1f5e-e554-16d5010dc28e`.

**Investigation Value:** Confirms a live, persistent session is the unit of compromise, the reason revocation is the primary containment action.