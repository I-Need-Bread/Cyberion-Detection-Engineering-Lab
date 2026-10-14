# Rule Test Report — T1547.001 Registry Run Key Persistence

**Rule file:** `rules/T1547.001_registry_run_keys.yml`
**Test date:** 2026-10-15
**Tester:** Cyberion Detection Engineering Lab
**Dataset:** EVTX-ATTACK-SAMPLES (278 EVTX files)
**Sysmon Event ID 13 records in corpus:** 223

---

## Test Methodology

A Python tester (`test_rule_T1547.001.py`) walks every EVTX file, extracts
Sysmon Event ID 13 (RegistryValueSet) records, and applies the
Sigma-equivalent rule. Matches require:

1. `TargetObject` contains a Run/RunOnce/RunOnceEx subpath
2. `Image` is not a known installer (msiexec, TrustedInstaller, setup,
   Defender, Sysmon)
3. `Details` is not a known-default value (SecurityHealth, OneDriveSetup)

---

## v1 → v2 Detection Engineering Iteration

### v1 — pattern coverage bug

The initial rule included `\CurrentVersion\Run\` and `\CurrentVersion\RunOnce\`
but omitted `\CurrentVersion\RunOnceEx\`. Records targeting the RunOnceEx
subkey (a documented persistence location) were silently missed.

**Added:** `\CurrentVersion\RunOnceEx\` to both the Sigma rule and the
test script.

### Test-script parser bug (independent)

During iteration, the test script reported **60** Event ID 13 records
while the diagnostic reported **223**. Root cause: a malformed
`try/except` block silently swallowed the majority of records.

This is the **third tooling bug** caught by cross-validating against an
independent parser (following Rules 5 and 6). Rewriting the test script
to mirror the diagnostic parser resolved the discrepancy — 223 == 223.

### v2 — final rule

The final rule matches on the complete Run-key subpath set, with
installer and default-value exclusions, and produces 8 matches across
6 files with 0 estimated false positives.

---

## Results

| Metric | Value |
|---|---|
| EVTX files scanned | 278 |
| Sysmon Event ID 13 records | **223** |
| Parse failures | 0 |
| **Rule matches** | **8** |
| **Files containing matches** | **6** |
| Estimated false positives | **0** |

---

## Matched Events

| # | File | Image | TargetObject | Details |
|---|---|---|---|---|
| 1 | `DE_timestomp_and_dll_sideloading_and_RunPersist.evtx` | `NvSmart.exe` | `HKCU\...\Run\360v` | `C:\...\svchost.exe` (masquerading) |
| 2 | `sideloading_injection_persistence_run_key.evtx` | `tendyron.exe` | `HKCU\...\Run\Tendyron` | Self-persistence |
| 3 | `PanacheSysmon_vs_AtomicRedTeam01.evtx` | `reg.exe` | `HKCU\...\Run\Atomic Red Team` | Atomic Red Team T1547.001 |
| 4 | `PanacheSysmon_vs_AtomicRedTeam01.evtx` | `reg.exe` | `HKLM\...\RunOnceEx\0001\Depend\1` | Atomic Red Team RunOnceEx |
| 5 | `PanacheSysmon_vs_AtomicRedTeam01.evtx` | `powershell.exe` | `HKLM\...\RunOnce\NextRun` | **PowerShell download cradle** |
| 6 | `lm_remote_registry_sysmon_1_13_3.evtx` | `svchost.exe` | `HKCU\...\Run\SUpdate` | `rundll32 smssvc.dll,Start` — remote registry |
| 7 | `wmi_remote_registry_sysmon.evtx` | `wmiprvse.exe` | `HKLM\...\Run\wmipers` | `rundll32 a.dll, DllMain` — WMI persistence |
| 8 | `evasion_persis_hidden_run_keyvalue_sysmon_13.evtx` | `a.exe` | `HKLM\...\Run\` (empty name) | `taskhost.exe` — hidden Run key |

---

## Attack Patterns Detected

- **Atomic Red Team T1547.001** — validation against a canonical test case
- **PowerShell download cradle** — RunOnce `NextRun` executes `IEX DownloadString`
- **Remote registry lateral movement** — `svchost.exe` (RemoteRegistry service) writing another user's HKCU Run
- **WMI remote persistence** — `wmiprvse.exe` writing HKLM Run
- **Hidden Run key with empty value name** — a documented evasion technique
- **Masquerading persistence** — `NvSmart.exe` writes `360v` value pointing at `svchost.exe`

---

## ATT&CK Coverage Achieved

| Tactic | Technique | Notes |
|---|---|---|
| Persistence | T1547.001 | Registry Run Keys |
| Lateral Movement | T1021.002 (implicit) | Remote Registry via svchost |
| Execution | T1047 (implicit) | WMI remote registry writes |

The rule captures **remote persistence** as well as local — an unexpected
but valuable extension of the technique.

---

## Assessment

- **Sensitivity:** The rule matched 8 of 8 Run-key persistence events
  present in the corpus (100% recall on this dataset).
- **Precision:** 100% — all matches are known attack samples; zero benign
  hits despite 223 total Event ID 13 records.
- **Detection breadth:** Covers local persistence, remote registry
  persistence, WMI persistence, hidden Run keys, and PowerShell
  download-cradle persistence in a single rule.
- **Recommendation:** Promote to `stable` at `medium` severity. Consider
  splitting into two rules: **Rule 7a** (local, medium) and **Rule 7b**
  (remote source = svchost/wmiprvse, high severity).

---

## Known Gaps / Limitations

1. **Legitimate installers write Run keys.** In production, allowlist
   must be extended with per-environment signed installers.
2. **The rule does not evaluate `Details` content** (the command line).
   A Run key pointing at a signed updater and a Run key pointing at
   `powershell.exe IEX DownloadString` both fire identically. Consider
   a companion rule that pattern-matches the value content.
3. **RunOnceEx subkey coverage required a pattern update.** Future
   variants (e.g., `RunOnceEx\0002`, `Policies\Explorer\Run`) should
   be reviewed periodically.
4. **`HKLM\SOFTWARE\WOW6432Node\...\Run` (32-bit hive on 64-bit Windows)**
   is not explicitly matched — the substring check catches it via
   `\CurrentVersion\Run\`, but a dedicated pattern entry would be clearer.
5. **Tooling bug #3** — the test script silently under-counted Event ID
   13 records by 73%. Fixed by rewriting the parser. Pattern across
   Rules 5, 6, and 7: **always cross-validate test tooling against an
   independent diagnostic.**

---

## Reproducing this Test

```cmd
python diagnose_run_keys.py       # 223 EID13, Run-key hits listed
python test_rule_T1547.001.py     # 8 matches across 6 files