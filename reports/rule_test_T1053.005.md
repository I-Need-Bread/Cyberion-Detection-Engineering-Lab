\# Rule Test Report — T1053.005 Suspicious Scheduled Task Creation



\*\*Rule file:\*\* `rules/T1053.005\_scheduled\_task\_suspicious.yml`

\*\*Test date:\*\* 2026-10-09

\*\*Tester:\*\* Cyberion Detection Engineering Lab

\*\*Dataset:\*\* EVTX-ATTACK-SAMPLES (278 EVTX files, 1,501 Sysmon Event ID 1 records)



\---



\## Test Methodology



Custom Python tester (`test\_rule\_T1053.005.py`) replicates the Sigma rule's

detection logic against every Sysmon Process Creation (Event ID 1) record.

A match is recorded when:



1\. Image ends with `\\schtasks.exe` OR OriginalFileName is `schtasks.exe`

2\. AND CommandLine contains `/create`

3\. AND CommandLine contains at least one suspicious trigger, action, or

&#x20;  masquerade string



\---



\## Results



| Metric | Value |

|---|---|

| EVTX files scanned | 278 |

| Sysmon EventID 1 records examined | 1,501 |

| Rule matches | \*\*2\*\* |

| Files containing matches | \*\*2\*\* |

| Estimated false positives | \*\*0\*\* |



\---



\## Matched Events



\### 1. panache\_sysmon\_vs\_EDRTestingScript.evtx

\*\*ATT\&CK:\*\* T1053.005 — Scheduled Task, T1036 — Masquerading



