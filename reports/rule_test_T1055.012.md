# Rule Test Report — T1055.012 Process Hollowing

**Rule files:**
- `rules/T1055.012_process_hollowing.yml` — modern telemetry (Sysmon EID 25)
- `rules/T1055.012_process_hollowing_via_eid8.yml` — legacy telemetry (Sysmon EID 8)

**Test date:** 2026-10-09
**Tester:** Cyberion Detection Engineering Lab
**Dataset:** EVTX-ATTACK-SAMPLES (278 EVTX files)
**Sysmon Event ID 25 records in corpus:** 0
**Sysmon Event ID 8 records in corpus:** 104

---

## Test Methodology

Two rules are shipped for the same technique, targeting two Sysmon
generations:

- **Rule 6 (EID 25)** — primary rule. Fires on Sysmon ProcessTampering,
  added in Sysmon v13 (Jan 2021). Highly specific behavioral signal.
- **Rule 6b (EID 8)** — companion rule for hosts with Sysmon < v13.
  Fires on `CreateRemoteThread` with empty `StartModule` (unbacked
  thread address) targeting a commonly-hollowed process.

---

## Data Discovery

### Sysmon Event ID 25 — 0 records

A diagnostic (`diagnose_tampering.py`) enumerated the corpus and found
**zero** Event ID 25 records. Root cause: the EVTX-ATTACK-SAMPLES
corpus is primarily 2019–2020 attack telemetry captured with
Sysmon v10/v11 — **before ProcessTampering was introduced in v13**.

This is a data-coverage gap, not a rule defect. Rule 6 is retained
as-is for deployment on modern fleets.

### Sysmon Event ID 8 — 104 records

The same diagnostic suite confirmed 104 Event ID 8 records across the
corpus. These were used to build Rule 6b, which targets the hollowing
signature visible in pre-v13 telemetry:

- `StartModule` is empty → thread start address is not backed by any
  loaded module (the injected PE image entry point)
- `TargetImage` is a commonly-hollowed process (`svchost.exe`,
  `notepad.exe`, `explorer.exe`, `rundll32.exe`, etc.)

---

## Detection Rule (Rule 6b — active)

```yaml
selection_event:
  EventID: 8
selection_no_module:
  StartModule: ''
selection_target:
  TargetImage|endswith:
    - '\svchost.exe'  - '\notepad.exe'  - '\rundll32.exe'
    - '\explorer.exe' - '\dllhost.exe'
    - '\RegAsm.exe'   - '\RegSvcs.exe'  - '\MSBuild.exe'
filter_known_sources:
  SourceImage|endswith:
    - '\svchost.exe' - '\csrss.exe' - '\smss.exe' - '\wininit.exe'
    - '\services.exe' - '\lsass.exe'
    - '\MsMpEng.exe'  - '\MpCmdRun.exe'
    - '\Sysmon.exe'   - '\Sysmon64.exe' - '\MsSense.exe'
condition: selection_event and selection_no_module and selection_target
           and not filter_known_sources