# Incident Case Report: Multi-Stage Ransomware Execution

## 1. Executive Summary
An investigation into the `PanacheSysmon_vs_AtomicRedTeam01.evtx` sample revealed a full ransomware attack chain. The attacker escalated privileges, dumped credential hives, disabled system recovery, and initiated encryption.

## 2. Incident Timeline (Reconstructed)
- **T+0:** `vssadmin create shadow /for=C:` (Attacker creates shadow copy)
- **T+1:** `reg save HKLM\SAM sam.hive` (Credential Access - T1003.002)
- **T+2:** `reg save HKLM\SYSTEM system.hive` (Credential Access)
- **T+3:** `bcdedit /set recoveryenabled no` (Inhibit System Recovery - T1490)
- **T+4:** `vssadmin delete shadows /all /quiet` (Destruction of backups)
- **T+5:** Mass file creation with `.enc` extensions (Impact - T1486)

## 3. Root Cause & ATT&CK Mapping
The attacker gained initial access (simulated via Atomic Red Team) and utilized native Windows utilities (LOLBins) to bypass security controls. 
- **Execution:** T1059 (Command-Line Interface)
- **Credential Access:** T1003.002 (SAM Dump)
- **Impact:** T1490, T1486

## 4. Impact Assessment
Total loss of local Windows account credentials. Destruction of Volume Shadow Copies prevents simple file restoration. 

## 5. Closure Classification
**True Positive.** Confirmed malicious activity mapping directly to known ransomware TTPs. Response: Isolate host, rebuild OS, rotate all domain credentials.