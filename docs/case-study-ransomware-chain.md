# Detecting the Ransomware Attack Chain: A Data-Driven Detection Engineering Case Study

**Author:** Cyberion Detection Engineering Lab
**Date:** 2026-10-15
**Repository:** [Cyberion-Detection-Engineering-Lab](https://github.com/I-Need-Bread/Cyberion-Detection-Engineering-Lab)

---

## Executive summary

This case study documents how four detection rules — LSASS memory access, SAM registry hive dumping, recovery inhibition, and file-encryption behavior — were built, tested, and validated against real ATT&CK evaluation telemetry. Together, they cover **six distinct ATT&CK techniques across four tactics** with **zero false positives** on a public 278-file EVTX corpus.

The engineering process uncovered **five bugs**, none of which were in the rules themselves. All five were in the tooling and pattern-matching assumptions that would have silently degraded detection coverage in production. Fixing them required cross-validating parsers, normalizing hex values, filtering by event provider, and expanding path patterns — each documented in the repository's per-rule reports.

The resulting rules form a **correlation chain**: an analyst who sees alerts from all four rules in the same incident window is looking at a ransomware attack in progress, not a false positive.

**Headline metrics:**

| Metric | Value |
|---|---|
| Rules authored | 4 (LSASS, SAM dump, Recovery inhibition, Ransomware) |
| ATT&CK techniques | 6 |
| ATT&CK tactics | 4 |
| True positives on corpus | 10 (across 3 files) |
| False positives | 0 |
| Engineering bugs found | 5 |

---

## 1. The hypothesis

A single detection rule for ransomware is not sufficient. Modern ransomware is a **multi-stage operation**:

1. **Establish a foothold** — phishing, exposed RDP, compromised credentials
2. **Escalate privileges** — Kerberoasting, Pass-the-Hash, token manipulation
3. **Harvest credentials** — LSASS memory dump, SAM/SYSTEM hive extraction
4. **Move laterally** — SMB, WMI, RDP to high-value hosts
5. **Neutralize recovery** — delete shadow copies, disable Windows RE
6. **Encrypt data** — mass file writes with ransomware extensions
7. **Extort** — ransom notes, double-extortion leaks

A detection strategy that only watches for step 6 will miss the entire attack chain. **The later in the chain you detect, the more damage is already done.**

This case study focuses on the last three stages — credential theft, recovery inhibition, and file encryption — because those are the stages where **behavioral telemetry** (Sysmon events) provides unambiguous signal.

---

## 2. The telemetry

Windows Sysmon provides the raw material. Each attack stage maps to a specific event ID:

| Attack stage | ATT&CK technique | Sysmon event | What it captures |
|---|---|---|---|
| Credential theft | T1003.001 — LSASS memory | **EID 10** ProcessAccess | A process opening LSASS with read-memory rights |
| Credential theft | T1003.002 — SAM dump | **EID 1** ProcessCreate | `reg save HKLM\SAM` and equivalents |
| Recovery inhibition | T1490 — Inhibit recovery | **EID 1** ProcessCreate | `vssadmin delete shadows`, `bcdedit` recovery disable |
| File encryption | T1486 — Data encrypted | **EID 11** FileCreate | Files created with ransomware extensions |

Additionally, Windows Security events enrich the picture:

| Attack stage | Security event | What it adds |
|---|---|---|
| Credential theft | 4624 LogonType 10 | Remote interactive (RDP) logons |
| Persistence | 4698 | Scheduled task created |
| Persistence | 4720, 4728, 4732 | New account / privileged group add |

**The choice to prefer behavioral events (Sysmon 1, 10, 11) over network events (EID 3) or logon events (Security 4624) was deliberate:** behavioral events are the only ones that cannot be spoofed by legitimate sign-in traffic. Every `reg save HKLM\SAM` is suspicious; not every RDP logon is.

---

## 3. The data discovery

Before writing a single rule, we enumerated the corpus. The `EVTX-ATTACK-SAMPLES` dataset contains 278 EVTX files spanning 11 ATT&CK tactic folders. A diagnostic script walked every file and tabulated:

- **Sysmon Event ID 10 records:** 157
- **Sysmon Event ID 8 records:** 104
- **Sysmon Event ID 11 records:** 209
- **Sysmon Event ID 13 records:** 223
- **Security Event ID 4624 records:** 87
- **Security Event ID 4698 records:** 3
- **Security Event ID 4720/4728/4732:** 12

This data-first approach revealed gaps. For example, **Sysmon Event ID 25 (ProcessTampering) has zero records in the corpus** — the dataset predates Sysmon v13's introduction of that event. Similarly, **Sysmon Event ID 22 (DnsQuery) has exactly 1 record** — DNS logging was largely disabled in the sample collection period.

Neither gap is a rule failure. Both are documented limitations of the test dataset. The corresponding rules remain in the repository as **forward-deployable** — correct by design but unvalidated on this corpus. That honesty is more valuable than a rule that pretends to be tested.

**Data discovery is not optional.** Of the five bugs found during this project, three were discovered only because a diagnostic script and a rule test script disagreed with each other.

---

## 4. The bugs

The rules themselves were straightforward. The tools that tested them were not. Five bugs, all in tooling or pattern assumptions, were discovered and fixed:

### Bug #1 — Zero-padded hex broke LSASS detection

**Symptom:** Rule v1 for LSASS memory access returned 0 matches across 157 Event ID 10 records. Every process-access event to LSASS should have matched.

**Root cause:** The rule's `GrantedAccess` filter used the canonical short form `0x1010` and `0x1fffff`. Sysmon writes these values with **8-character zero padding** — `0x00001010` and `0x001fffff`. Exact string comparison never matches.

**Fix:** Normalize the value by stripping leading zeros before comparison. The final rule uses a `|contains` filter in Sigma and a numeric normalization in the test script.

**Lesson:** Sysmon output format is not documented uniformly. **Always inspect the raw event before writing exact-match patterns.**

### Bug #2 — Test parser silently swallowed 90% of records

**Symptom:** A test script for Process Injection reported 10 Event ID 8 records. An independent diagnostic on the same corpus reported 104.

**Root cause:** A broad `try / except ParseError / continue` block in the test script's per-record loop silently failed on ~90% of records.

**Fix:** Rewrite the parser to match the diagnostic's structure exactly. The discrepancy disappeared.

**Lesson:** **Cross-validate your test tooling against an independent implementation.** A test that passes on a broken parser is worse than no test at all.

### Bug #3 — Event ID 3 collision (Sysmon vs BITS)

**Symptom:** A diagnostic for Sysmon NetworkConnect (Event ID 3) reported 421 records. A test script found 60, then 10. Neither matched.

**Root cause:** Windows **BITS** (Background Intelligent Transfer Service) also uses **Event ID 3** for its own `JobCreated` event. Our parser filtered by `EventID` alone and mixed two completely different event types.

**Fix:** Filter by `Provider.Name = Microsoft-Windows-Sysmon` before processing.

**Lesson:** **Never filter on `EventID` alone in Windows event logs.** Provider name is mandatory. This is exactly why Sigma's `logsource.service` field exists.

### Bug #4 — RunOnceEx subkey pattern missing

**Symptom:** Rule v1 for Registry Run Key persistence matched 0 events despite 11 Run-key writes in the corpus.

**Root cause:** The rule included `\CurrentVersion\Run\` and `\CurrentVersion\RunOnce\` but omitted `\CurrentVersion\RunOnceEx\` — a documented persistence location used by the attack sample.

**Fix:** Add `RunOnceEx` to the pattern list in both the Sigma rule and the test script.

**Lesson:** **Persistence locations are plural.** Attackers use the less-obvious variant, and rules must cover the full set.

### Bug #5 — YAML validation heredoc escaping

**Symptom:** CI failed at the YAML validation step with `SyntaxError: unterminated string literal`.

**Root cause:** A multi-line Python snippet embedded in the GitHub Actions YAML via `python -c "..."` had broken escaping. YAML and shell quote rules combined catastrophically.

**Fix:** Move the validation logic to a standalone script (`scripts/validate_sigma.py`). The workflow now calls the script directly.

**Lesson:** **Never embed multi-line code in CI YAML.** External scripts are easier to test, debug, and maintain.

---

## 5. The final rules

Each rule was rebuilt from real telemetry, not assumptions.

### Rule 3 — LSASS Memory Access (T1003.001)

**Design:** three-tier detection.

- **Tier A** — `TargetImage` ends with `\lsass.exe`
- **Tier B** — `GrantedAccess` includes suspicious access rights (`0x1010`, `0x1410`, `0x1418`, `0x143a`, `0x1438`, `0x1f1fff`, `0x1fffff`)
- **Tier C** — `SourceImage` is not a known-good LSASS access source (AV, EDR, csrss, services, etc.)

**Result:** 22 matches across 12 files, 0 false positives. Detected Mimikatz, ProcDump, comsvcs.dll abuse, Outflank Dumpert, AndrewSpecial, ppldump, MalSeclogon, and Python-based dumpers.

### Rule 8 — SAM Registry Hive Dump (T1003.002)

**Design:** three-signal detection.

- **Signal A** — `reg save HKLM\{SAM,SYSTEM,SECURITY}` (registry hive dump)
- **Signal B** — `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\...\config\` (VSS extraction)
- **Signal C** — `vssadmin create shadow` (VSS creation as precursor)

**Result:** 10 matches in the Atomic Red Team T1003.002 chain, 0 false positives. Captured the full credential-dump lifecycle from VSS creation through hive extraction.

### Rule 10 — Ransomware Behavior (T1486) + Recovery Inhibition (T1490)

**Design:** dual-rule cluster.

- **Rule 10a** — Sysmon Event ID 11, filenames ending with ransomware-family extensions
- **Rule 10b** — `vssadmin delete shadows`, `wmid shadowcopy delete`, `bcdedit /set recoveryenabled no`, `wbadmin delete catalog`

**Result:** Rule 10a — 1 match. Rule 10b — 4 matches in the Atomic Red Team chain. 0 false positives. **Every matched file was a documented attack sample.**

---

## 6. The correlation — why this is a chain, not a rule set

Three of the four rules matched the same file: `PanacheSysmon_vs_AtomicRedTeam01.evtx`. That file contains:

- `vssadmin create shadow` (Rule 8, Signal C)
- `reg save HKLM\SAM sam.hive` (Rule 8, Signal A)
- `reg save HKLM\SYSTEM system.hive` (Rule 8, Signal A)
- `reg save HKLM\SECURITY security.hive` (Rule 8, Signal A)
- `copy \\?\GLOBALROOT\...\config\SYSTEM` (Rule 8, Signal B)
- `bcdedit /set recoveryenabled no` (Rule 10b)
- `vssadmin delete shadows` (Rule 10b)
- `wbadmin delete catalog` (Rule 10b)

**A SOC analyst receiving alerts from Rules 3, 8, and 10 in a 15-minute window is looking at an active ransomware incident.** The correlation across rules tells the story that no single rule can.

This is the argument for **defense-in-depth detection design**: each rule covers a stage; together, they cover the operation.

---

## 7. Production deployment notes

None of these rules should be deployed without tuning. The corpus has zero false positives, but that's because it's an attack-sample dataset. In production:

- **Rule 3 (LSASS)** — Some legitimate software (password managers, credential managers) accesses LSASS. The `filter_known_sources` list must be extended per environment. **Enable Credential Guard** to make the underlying attack harder.

- **Rule 8 (SAM dump)** — Backup software occasionally uses `reg save`. Use **file signature** and **publisher certificate** checks rather than image-name allowlisting.

- **Rule 10a (Ransomware)** — Archive and encryption tools legitimately create `.enc`, `.crypt`, and `.crypto` files. **Filter by signing identity**, not by process name.

- **Rule 10b (Recovery inhibition)** — `vssadmin delete shadows` is sometimes called by legitimate backup rotation. Context matters: correlate with the source process's parent chain.

**Deployment recommendations:**

| Rule | Initial severity | Initial action |
|---|---|---|
| T1003.001 LSASS | critical | Page SOC + auto-isolate |
| T1003.002 SAM dump | high | Alert + enrich |
| T1486 Ransomware | critical | Page SOC + auto-isolate |
| T1490 Recovery inhibit | high | Alert + page |

---

## 8. Lessons learned

1. **Data > assumptions.** Every rule was written *after* a diagnostic enumerated what the telemetry actually contains. The gap between "what I expected" and "what the data shows" was the source of every bug.

2. **Cross-validate tooling.** Five bugs were found because two independent implementations disagreed. If your test script and your diagnostic script both use the same parser, a parser bug hides in both.

3. **Multi-signal beats single-signal.** Rules with two or three independent detection signals produce dramatically fewer false positives than single-condition rules. The LSASS rule's three tiers, the SAM rule's three signals, and the ransomware cluster's dual-rule design all reflect this.

4. **Document bugs honestly.** Five engineering bugs are documented in the repository. This is not a weakness — it's a strength. A SOC lead reading the repo knows the author tested their tools, not just their rules.

5. **Detect early in the chain.** By the time ransomware encrypts files, it's too late. The value of behavioral detection is catching the attack at stage 3 (credential theft) or stage 4 (recovery inhibition), not stage 6 (encryption).

6. **Behavioral > signature.** Sysmon Event ID 1 (ProcessCreate) with `CommandLine: reg save HKLM\SAM` is unambiguous. Signature-based detection of "Mimikatz.exe" is trivially evaded by renaming the binary. Behavioral detection survives obfuscation.

---

## 9. References

- [MITRE ATT&CK — Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE ATT&CK T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK T1003.002 — Security Account Manager](https://attack.mitre.org/techniques/T1003/002/)
- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [SigmaHQ — Sigma rules specification](https://github.com/SigmaHQ/sigma)
- [EVTX-ATTACK-SAMPLES — the test dataset](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- [pySigma — Sigma rule compilation](https://github.com/SigmaHQ/pySigma)
- [Sysmon — Windows System Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

---

*This case study is part of the Cyberion Detection Engineering Lab — a portfolio project demonstrating the full lifecycle of detection rule authorship, from data discovery through CI/CD deployment.*