# Phase 02 - Session Scope: Queries

> Query log for Phase 02. These queries validate token reuse, Conditional Access non-application, pre-entry failures, application blast radius, and the continuous session identifier.

---

## Q07 - How the Session Beat MFA

**Purpose:** Determine whether the attacker completed MFA or reused an already trusted session.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| project TimeGenerated,
          IPAddress,
          AppDisplayName,
          AuthenticationRequirement,
          AuthenticationDetails,
          ConditionalAccessStatus,
          ResultType,
          ResultDescription
| order by TimeGenerated asc
```

**Expected Result:** `AuthenticationRequirement == singleFactorAuthentication`, consistent with Keep Me Signed In / refresh-token reuse.

**Pivot Produced:** Token persistence mechanism.

**Investigation Value:** Shows the attacker did not defeat MFA. They reused a trusted session.

---

## Q08 - The Control Surface That Let Them In

**Purpose:** Determine whether Conditional Access applied to the suspicious sign-ins.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| project TimeGenerated,
          IPAddress,
          AppDisplayName,
          AuthenticationRequirement,
          ConditionalAccessStatus,
          ConditionalAccessPolicies,
          ResultType,
          ResultDescription
| order by TimeGenerated asc
```

**Expected Result:** `ConditionalAccessStatus == notApplied`

**Pivot Produced:** Conditional Access coverage gap.

**Investigation Value:** Explains why no MFA challenge or block occurred.

---

## Q09 - Failed Attempts Before Entry

**Purpose:** Count failed authentication attempts from the attacker IP before successful access.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultType != 0
| project TimeGenerated, IPAddress, AppDisplayName, ResultType, ResultDescription
| order by TimeGenerated asc
```

**Expected Result:** `2` failed sign-in attempts.

**Pivot Produced:** Failed attempt count, `2`.

**Investigation Value:** Establishes pre-entry probing before successful access.

---

## Q10 - Blast Radius of One Token

**Purpose:** Count how many Microsoft 365 applications/resources were reached from the attacker activity.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| summarize AppCount = dcount(AppDisplayName), Apps = make_set(AppDisplayName)
| project AppCount, Apps
```

**Expected Result:** `7` applications/resources.

**Pivot Produced:** Application blast radius, `7`.

**Investigation Value:** Shows one token reached multiple cloud surfaces, not only Outlook.

---

## Q11 - One Continuous Session

**Purpose:** Identify the sustained session used by the attacker.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| summarize SignIns = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated),
            Apps = make_set(AppDisplayName)
        by SessionId, IPAddress
| order by SignIns desc
```

**Expected Result:** Session ID `005d431a-380b-1f5e-e554-16d5010dc28e`.

**Pivot Produced:** Continuous session ID, `005d431a-380b-1f5e-e554-16d5010dc28e`.

**Investigation Value:** Supports session revocation as the first containment action.