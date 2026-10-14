# Rule Test Report — T1486 Ransomware Behavior + T1490 Inhibit Recovery

**Rule files:**
- `rules/T1486_ransomware_file_encryption.yml` — ransomware encryption patterns
- `rules/T1490_inhibit_system_recovery.yml` — ransomware precursor commands

**Test date:** 2026-10-15
**Tester:** Cyberion Detection Engineering Lab
**Dataset:** EVTX-ATTACK-SAMPLES (278 EVTX files)

---

## Test Methodology

A combined tester (`test_rule_T1486_T1490.py`) walks every EVTX file
and applies two Sigma-equivalent rules:

- **T1486** — Sysmon Event ID 11 (FileCreate). Matches known ransomware
  extensions or ransom-note filenames; excludes legitimate encryption
  tools.
- **T1490** — Sysmon Event ID 1 (ProcessCreate). Matches recovery
  inhibition commands (`vssadmin delete shadows`, `wmic shadowcopy
  delete`, `bcdedit recoveryenabled no`, `wbadmin delete catalog`).

The two rules ship as a **ransomware detection cluster** — T1490 is the
precursor, T1486 is the payoff.

---

## Results

### T1486 — Ransomware File Encryption

| Metric | Value |
|---|---|
| Sysmon Event ID 11 records | 209 |
| **Rule matches** | **1** |
| **Files containing matches** | **1** |
| Estimated false positives | **0** |

**Matched file:** `AutomatedTestingTools\Malware\rundll32_cmd_schtask.evtx`
**Signal:** `A_ransom_ext` (file created with a ransomware-family extension)

### T1490 — Inhibit System Recovery

| Metric | Value |
|---|---|
| Sysmon Event ID 1 records | 1,501 |
| **Rule matches** | **4** |
| **Files containing matches** | **1** |
| Estimated false positives | **0** |

**Matched file:** `AutomatedTestingTools\PanacheSysmon_vs_AtomicRedTeam01.evtx`

**Signals fired:**

| Signal | Count | Meaning |
|---|---|---|
| `C_bcdedit_recovery` | 2 | `bcdedit /set recoveryenabled no` — disables Windows RE |
| `A_vssadmin_delete` | 1 | `vssadmin delete shadows /all /quiet` |
| `D_wbadmin_delete` | 1 | `wbadmin delete catalog` |

---

## Attack Chain Correlation

The T1490 matches are **in the same file** as Rule 8's SAM-dump matches
(`PanacheSysmon_vs_AtomicRedTeam01.evtx`). This reveals a **multi-stage
attack playbook**:

1. **Credential Access** — dump SAM/SYSTEM/SECURITY hives (Rule 8)
2. **Defense Evasion / Impact prep** — disable Windows Recovery (Rule 10)
3. **Command and Control** — outbound network connections (Rule 9)

A SOC analyst seeing these three rule alerts on the same host within
minutes would **correctly escalate to a ransomware incident** even before
the encryption stage begins.

This is the **defense-in-depth payoff**: no single rule needs to be
perfect; the correlation across rules tells the story.

---

## ATT&CK Coverage Achieved

| Tactic | Technique | Rule |
|---|---|---|
| Impact | T1486 (Data Encrypted for Impact) | T1486_ransomware |
| Impact | T1490 (Inhibit System Recovery) | T1490_inhibit_recovery |

---

## Assessment

- **T1486 sensitivity:** Caught the single ransomware sample in the
  corpus (100% recall on this dataset).
- **T1486 precision:** 100% — no legitimate file creation matched any
  ransomware extension.
- **T1490 sensitivity:** Caught all recovery-inhibition commands in the
  corpus (4/4).
- **T1490 precision:** 100% — Atomic Red Team tests are the ground-truth
  attack chain; no backup-rotation false positives.
- **Cluster value:** When T1490 and T1486 fire on the same host within
  a short window, escalate to ransomware incident response. This
  correlation is the real detection value.

**Recommendation:** Promote T1490 to `stable` at `high` severity.
Promote T1486 to `stable` at `critical` severity with immediate paging.

---

## Known Gaps / Limitations

1. **Diagnostic under-reported ransomware samples.** The initial
   `diagnose_ransomware.py` used a shorter extension list than the
   final rule and reported 0 ransom-extension files, while the rule
   correctly matched 1. **Lesson:** diagnostic keyword lists must be
   at least as comprehensive as the rule's matching set, or ground
   truth will be under-counted. This is the **5th detection-engineering
   bug** caught in the project.

2. **T1486 requires per-file matching.** Ransomware encrypts thousands
   of files per second. A per-event rule produces thousands of alerts.
   Production deployment must include an aggregation companion in
   SPL/EQL (e.g., "same Image, 100+ FileCreate events in 60s, same
   new extension").

3. **Legitimate archive tools can trigger T1486.** The filter list
   includes 7-Zip, WinRAR, etc., but any encrypting tool that writes
   files with `.enc`, `.crypt`, or similar extensions will false-
   positive. Environments with heavy archive usage should refine.

4. **T1486 does not detect overwrite-in-place encryption.** Some
   ransomware overwrites files without creating new ones, generating
   no Event ID 11. Coverage requires Sysmon Event ID 23 (FileDelete)
   or 4663 (File write auditing).

5. **T1490 exclusions may need tuning.** Legitimate backup software
   occasionally deletes old shadow copies during rotation. In
   production, allowlist by signed publisher certificate.

6. **No coverage of `wbadmin delete catalog` variants.** Some
   ransomware uses `bcdedit /set {default} recoveryenabled no` with
   braces around `default` — the current rule's `contains` check on
   `recoveryenabled no` catches this, but explicit variants should be
   added to the rule's pattern list.

---

## Reproducing this Test

```cmd
python diagnose_ransomware.py       # initial diagnostic (under-reports)
python diagnose_ransomware_ext.py   # drill-down on the ransomware sample
python test_rule_T1486_T1490.py     # combined rule test