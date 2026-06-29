# Phase 05 - Persistence Hunt: Queries

> Query log for Phase 05. These queries identify the concealment rule, confirm what it did with mail, isolate the external forwarding rule, and prove both rules targeted the same finance mailbox.

---

## Q18 - The Concealment Rule

**Purpose:** Identify the mailbox rule created to hide payment-verification mail.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| project Timestamp, AccountDisplayName, Application, ActionType, ObjectName, RawEventData
| order by Timestamp asc
```

**Expected Result:** A mailbox rule named `Invoice Processing`.

**Pivot Produced:** Concealment rule, `Invoice Processing`.

**Investigation Value:** Identifies the rule the attacker created to suppress finance-related mail.

---

## Q19 - Where the Hidden Mail Goes

**Purpose:** Determine whether the rule deleted messages or moved them elsewhere.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| where RawEventData has "Invoice Processing"
| project Timestamp, ObjectName, RawEventData
```

**Expected Result:** Rule behavior shows a move action rather than deletion.

**Pivot Produced:** Messages were moved to a hidden or low-visibility folder, not deleted.

**Investigation Value:** Confirms concealment over destruction, which matters for recovery and explains why the fraud stayed hidden.

---

## Q20 - The Exfiltration Rule

**Purpose:** Find inbox rules that forwarded mail to an external recipient.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| where RawEventData has "ForwardTo"
| project Timestamp, AccountDisplayName, ObjectName, RawEventData
| order by Timestamp asc
```

**Expected Result:** External forwarding to `merovingian1337@proton.me`.

**Pivot Produced:** Exfiltration destination, `merovingian1337@proton.me`.

**Investigation Value:** Confirms the attacker created live external mail exfiltration.

---

## Q21 - The Both-Rules Target

**Purpose:** Confirm both mailbox rules were created to manipulate mail for the same finance contact.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| where RawEventData has "j.reynolds@lognpacific.org"
| project Timestamp, AccountDisplayName, ObjectName, RawEventData
| order by Timestamp asc
```

**Expected Result:** Rule conditions reference `j.reynolds@lognpacific.org`.

**Pivot Produced:** Targeted mailbox or sender condition tied to `j.reynolds@lognpacific.org`.

**Investigation Value:** Links the persistence directly to the fraud target and proves the rules were built to suppress payment verification replies.