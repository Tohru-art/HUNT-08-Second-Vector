# Phase 04 - The Fraud: Queries

> Query log for Phase 04. Focus is the BEC: isolating the fraudulent banking-change message, reconstructing the mimicked payment thread, identifying the target, and separating attacker IPs from platform infrastructure.

---

## Q14 - The Fraudulent Request

**Purpose:** Locate the fraudulent banking-detail change email and capture its core metadata.

**KQL Query**
```kql
EmailEvents
| where Timestamp between (datetime(2026-06-10) .. datetime(2026-06-20))
| where Subject has "Updated Banking Details"
| project Timestamp, SenderFromAddress, SenderMailFromAddress,
          RecipientEmailAddress, Subject, SenderIPv4, NetworkMessageId
| order by Timestamp asc
```

**Expected Result:** The message **"Updated Banking Details - Pacific IT Monthly"** is returned with its sender, recipient, and sending IP.

**Pivot Produced:** Fraud subject + recipient + sender-IP pivots.

**Investigation Value:** Anchors the entire fraud phase on a single identified message and exposes the IPs and recipient used in the following queries.

---

## Q15 - The Thread They Mimicked

**Purpose:** Identify the legitimate payment workflow thread the attacker reviewed and mimicked.

**KQL Query**
```kql
EmailEvents
| where Timestamp between (datetime(2026-06-10) .. datetime(2026-06-20))
| where Subject has_any ("payment", "approval", "invoice", "vendor", "bank", "wire")
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, SenderIPv4
| order by Timestamp asc
```

**Expected Result:** The historical payment thread **`Q1 Vendor Payment Schedule - Review Required`** appears as the legitimate workflow the attacker mimicked.

**Pivot Produced:** Mimicked thread, `Q1 Vendor Payment Schedule - Review Required`.

**Investigation Value:** Proves the attacker used real payment workflow context to make the fraudulent banking-details message more credible.

---

## Q16 - The Fraud Target

**Purpose:** Identify who the fraudulent banking-change request was steered toward.

**KQL Query**
```kql
EmailEvents
| where Subject == "Updated Banking Details - Pacific IT Monthly"
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, SenderIPv4
| order by Timestamp asc
```

**Expected Result:** The fraud target is **`j.reynolds@lognpacific.org`**.

**Pivot Produced:** Fraud target, `j.reynolds@lognpacific.org`.

**Investigation Value:** Names the human the attacker attempted to manipulate into authorizing fraud, and links directly to the mailbox targeted by the Phase 05 persistence rules.

---

## Q17 - Second Channel Reinforcement

**Purpose:** Determine whether the deception was reinforced outside the single email thread.

**KQL Query**
```kql
CloudAppEvents
| where Timestamp between (datetime(2026-06-10) .. datetime(2026-06-20))
| where Application has "Teams" or RawEventData has "Teams"
| where RawEventData has_any ("banking", "Updated Banking", "j.reynolds@lognpacific.org")
| project Timestamp, Application, ActionType, AccountDisplayName, RawEventData
| order by Timestamp asc
```

**Expected Result:** Microsoft Teams activity appears around the same fraud window.

**Pivot Produced:** Second channel, `Microsoft Teams`.

**Investigation Value:** Demonstrates the attacker reinforced the BEC through a trusted collaboration channel, raising the credibility of the request.

---

### Supporting query: Sender IP attribution

**Purpose:** Separate attacker-originated sending IPs from Microsoft platform infrastructure such as NDR responses.

**KQL Query**
```kql
EmailEvents
| where Subject has "Updated Banking Details"
| summarize Messages = count(), Subjects = make_set(Subject) by SenderIPv4
| order by Messages desc
```

**Expected Result:** `103.69.224.136` and `185.130.187.4` are attacker-associated; `20.190.190.224` is Microsoft service infrastructure.

**Pivot Produced:** Clean attacker-vs-infrastructure IP split.

**Investigation Value:** Prevents misattributing platform-generated mail to the actor and adds `185.130.187.4` as a second attacker pivot.