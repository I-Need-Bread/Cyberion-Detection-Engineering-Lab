# Rule Test Report — T1003.001 LSASS Memory Access

**Rule file:** `rules/T1003.001_lsass_memory_access.yml`
**Test date:** 2026-10-09
**Tester:** Cyberion Detection Engineering Lab
**Dataset:** EVTX-ATTACK-SAMPLES (278 EVTX files, 157 Sysmon Event ID 10 records)

---

## Test Methodology

A Python tester (`test_rule_T1003.001.py`) replicates the Sigma rule's
detection logic against every Sysmon Event ID 10 (Process Access) record.
A match requires:

1. `TargetImage` ends with `\lsass.exe`
2. `GrantedAccess` (normalized, leading zeros stripped) matches a known
   suspicious access mask
3. `SourceImage` is NOT one of the known-benign processes (AV, csrss,
   services, taskmgr, opera_autoupdate, etc.)

---

## v1 → v2 Detection Engineering Iteration

### v1 — Exact string match on canonical mask

The initial rule used:
```yaml
selection_access:
  GrantedAccess:
    - '0x1010'
    - '0x1410'
    - '0x1438'
    - '0x143a'
    - '0x1fffff'