# Rule Test Report — T1053.005 Scheduled Task (Security 4698)

**Rule file:** `rules/T1053.005_scheduled_task_security.yml`
**Test date:** 2026-10-15
**Tester:** Cyberion Detection Engineering Lab
**Dataset:** EVTX-ATTACK-SAMPLES (278 EVTX files)
**Security Event ID 4698 records in corpus:** 3

---

## Test Methodology

A Python tester (`test_rule_T1053.005_security.py`) walks every EVTX
file, extracts Security Event ID 4698 (Scheduled Task Created) records,
and applies the Sigma-equivalent rule. The rule matches on the
`TaskContent` XML when it contains suspicious commands, script
interpreters, or attacker-typical file paths.

Exclusions:
- Windows built-in tasks (`\Microsoft\Windows\*`)
- Machine accounts creating tasks (`SubjectUserName` ends with `$`)

---

## Results

| Metric | Value |
|---|---|
| EVTX files scanned | 278 |
| Security 4698 records | 3 |
| **Rule matches** | **3** |
| **Files containing matches** | **3** |
| Estimated false positives | **0** |

### Matched events

| File | TaskName | Creator | Command |
|---|---|---|---|
| `Execution\temp_scheduled_task_4698_4699.evtx` | `\CYAlyNSS` | Administrator | `cmd.exe /C tasklist > %windir%\Temp\CYAlyNSS.tmp 2>&1` |
| `Lateral Movement\LM_ScheduledTask_ATSVC_target_host.evtx` | `\CYAlyNSS` | Administrator | Same command (created via ATSVC on remote host) |
| `Privilege Escalation\PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx` | `\FullPowersTask` | LOCAL SERVICE | `C:\Users\Public\Tools\TokenManip\FullPowers.exe -t 4932` |

---

## Cross-Telemetry Validation — Rule 2 + Rule 12 Pair

Rule 12 (Security 4698) complements Rule 2 (Sysmon EID 1 schtasks.exe).
Both rules target the same ATT&CK technique (T1053.005) but via
independent telemetry channels:

| File | Rule 2 (Sysmon) | Rule 12 (Security) |
|---|---|---|
| `temp_scheduled_task_4698_4699.evtx` | ✅ | ✅ |
| `LM_ScheduledTask_ATSVC_target_host.evtx` | ✅ | ✅ |
| `PrivEsc_SeImpersonatePriv_enabled_...4698.evtx` | ✅ | ✅ |
| `sysmon_uacbypass_CDSSync_schtask_hijack_byeintegrity5.evtx` | ✅ | ❌ (no 4698) |

**Interpretation:**

- The `sysmon_uacbypass_CDSSync_schtask_hijack` file contains a scheduled
  task operation that Sysmon observed (via `schtasks.exe` process
  creation) but for which Windows Security did not log 4698. Likely
  causes: scheduled task audit was not enabled, the operation used a
  COM API that bypasses the process-creation telemetry, or the task
  was later deleted without registering an audit event.

- This is **exactly the value** of running both rules: the Sysmon rule
  catches tasks the Security log misses, and the Security rule catches
  tasks Sysmon misses (e.g., when an attacker uses COM APIs directly
  without spawning `schtasks.exe`).

**Defeating both requires independent evasion of two logging systems.**
This is the defense-in-depth pattern for T1053.005.

---

## Attack Patterns Detected

### Pattern 1 — Recon scheduled task
