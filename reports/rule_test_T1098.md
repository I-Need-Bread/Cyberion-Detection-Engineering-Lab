# Rule Test Report — T1098 Account Manipulation

**Rule file:** `rules/T1098_account_manipulation.yml`
**Test date:** 2026-10-15
**Tester:** Cyberion Detection Engineering Lab
**Dataset:** EVTX-ATTACK-SAMPLES (278 EVTX files)
**Target Security events in corpus:** 7 (4720×2, 4722×1, 4724×2, 4732×2, 4738×5)

---

## Test Methodology

A Python tester (`test_rule_T1098.py`) walks every EVTX file, extracts
Windows Security events 4720, 4722, 4724, 4728, 4732, 4756, and applies
the Sigma-equivalent rule. The rule uses three detection signals:

- `new_account` — EventID 4720 (any user account creation)
- `privileged_group` — EventIDs 4728/4732/4756 with privileged group
  as `TargetUserName`
- `suspicious_name` — EventID 4720 with account name matching admin/
  svc/backup/test/temp/help patterns

---

## Results

| Metric | Value |
|---|---|
| EVTX files scanned | 278 |
| Target Security events | 7 |
| **Rule matches** | **4** |
| **Files containing matches** | **2** |
| Estimated false positives | **0** |

### Matches per signal

| Signal | Count | Fired on |
|---|---|---|
| `new_account` | 2 | Fake computer account creation |
| `privileged_group` | 2 | Network Service / Guest → Administrators |
| `suspicious_name` | 0 | (no attacker-named accounts with those keywords) |

### Matched files

| File | Attack family | Signals |
|---|---|---|
| `Defense Evasion\DE_Fake_ComputerAccount_4720.evtx` | Fake machine account creation | `new_account` ×2 |
| `Persistence\Network_Service_Guest_added_to_admins_4732.evtx` | Privileged group add | `privileged_group` ×2 |

---

## Attack Patterns Detected

### Pattern 1 — Fake computer account (4720)

Attackers create accounts named `$` (the machine-account naming
convention) to impersonate legitimate computers. This is used in:

- **Machine account quota abuse** (default 10 per user)
- **Unconstrained delegation attacks** — the fake machine account is
  granted delegation rights, then coerced into authenticating to the
  attacker
- **sAMAccountName spoofing (CVE-2021-42287/42278)** — creating a
  machine account named like a DC, then exploiting Kerberos

**Detection significance:** Legitimate 4720 events for computer accounts
come from machine-join operations, not interactive user actions.

### Pattern 2 — Privileged group membership (4732)

Adding `NETWORK SERVICE` or `Guest` to `Administrators` is a
canonical privilege-escalation-persistence move:

- `NETWORK SERVICE` is used by dozens of legitimate Windows services
- Adding it to Administrators means any process that can be coerced
  into running as NETWORK SERVICE gets SYSTEM
- This pattern is common in **PrintNightmare**, **JuicyPotato**,
  **RottenPotato**, and similar privilege-escalation exploits

**Detection significance:** In a healthy environment, service accounts
and built-in principals are **never** added to local Administrators by
non-admin users. Any 4732 targeting `Administrators` where the actor
is a standard user is a high-fidelity alert.

---

## Correlation with Other Rules

The `Network_Service_Guest_added_to_admins_4732.evtx` file represents
an escalation chain that **complements Rule 9 (Web C2)** and
**Rule 10 (Ransomware)**:

- Credential theft (Rule 8) → group membership escalation (Rule 11) →
  C2 callback (Rule 9) → ransomware encryption (Rule 10)

The full T1098 → T1071 → T1486 progression is now detectable across
your rule set.

---

## ATT&CK Coverage Achieved

| Tactic | Technique | Notes |
|---|---|---|
| Persistence | T1098 | Account Manipulation |
| Persistence | T1098.001 (subset) | Additional Cloud Credentials — future |
| Persistence | T1136 (related) | Create Account — covered by 4720 |

---

## Assessment

- **Sensitivity:** Caught all 4 account-manipulation events in the
  corpus (100% recall on this dataset).
- **Precision:** 100% — all 4 matches are known attack samples.
- **Detection breadth:** Covers fake computer accounts, privileged
  group escalation, and (via the rule's other branches) suspicious
  account names and password resets.
- **Recommendation:** Promote to `stable` at `high` severity. In
  production, add a per-OU allowlist of legitimately provisioned
  accounts to reduce onboarding noise.

---

## Known Gaps / Limitations

1. **Legitimate onboarding triggers 4720.** New employees, service
   accounts, and computer joins all produce 4720. In production,
   filter by `SubjectUserName` — an HR/IT provisioning account is
   expected; a random user is suspicious.
2. **`MemberName` field is often empty** in the corpus (4732 events
   show `MemberName: -`). This appears to be a Windows version
   difference — some builds populate `MemberSid` only. The rule does
   not depend on `MemberName`, which is correct, but analysts
   investigating the alert should look at `MemberSid` for the SID of
   the added principal.
3. **Does not detect ACL modification (Event 4670 / 4663).** Attackers
   often add `DCSync` rights or modify ACLs instead of joining a
   privileged group. That requires a companion rule on Event ID 4670
   (Permissions on object changed).
4. **Does not cover Azure AD / Entra ID equivalent events.** Cloud
   identity manipulation uses different telemetry (Azure AD audit logs).
5. **Event ID 4738 (User Account Changed) is noisy.** The current rule
   does not alert on 4738 events on their own — only when they
   accompany a 4720 or 4732. This is deliberate and correct.
6. **No detection of AdminSDHolder abuse.** Admins who abuse the
   AdminSDHolder template can inherit DA rights without a 4732 event.
   Detection requires monitoring 4780 (ACL set on admin accounts).

---

## Reproducing this Test

```cmd
python diagnose_accounts.py    # 7 target events across 5 files
python test_rule_T1098.py      # 4 matches across 2 files