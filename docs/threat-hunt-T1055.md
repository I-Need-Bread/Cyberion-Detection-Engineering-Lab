# Threat Hunt Report: Unbacked Process Injection (T1055)

## 1. Hypothesis
"An attacker has compromised a host and is using process injection to hide malicious execution. Specifically, we suspect a process is creating a remote thread (Sysmon EID 8) with an empty `StartModule` (indicating execution from unbacked memory), targeting a legitimate host process like `notepad.exe` or `explorer.exe`."

## 2. Method
- **Data Source:** Sysmon Event ID 8 (CreateRemoteThread).
- **Approach:** Python script scanning 278 EVTX files. Filtering for EID 8 where `StartModule` is empty AND `TargetImage` is a known hollowable process.
- **Query Logic:** `EventID=8 AND StartModule IS NULL AND TargetImage LIKE '%explorer.exe' OR '%notepad.exe'`

## 3. Findings
The hunt yielded **96 matches** across 6 files. We confirmed multiple instances of:
- Meterpreter migrating to `explorer.exe`.
- PowerShell injecting reflective PE payloads into `notepad.exe`.
- APT10 process hollowing targeting `svchost.exe`.

## 4. Conclusion
**CONFIRMED.** The hypothesis is validated. This hunt directly resulted in the creation of Detection Rule `T1055_process_injection.yml`. 