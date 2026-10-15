# ATT&CK Coverage Matrix

Auto-generated from **14 rule files** in `rules/`.

| # | Rule | ATT&CK Techniques | Tactic | Log Source | Level | Status |
|---|------|-------------------|--------|------------|-------|--------|
| 1 | Suspicious LSASS Process Access for Credential Dumping | attack.t1003.001 | credential_access | `windows/?` | critical | experimental |
| 2 | SAM Registry Hive Dump via reg save or VSS | attack.t1003.002 | credential_access | `windows/sysmon` | high | experimental |
| 3 | RDP Lateral Movement - RemoteInteractive Logon (RDP) | attack.t1021.001, attack.t1572 | lateral_movement, command_and_control | `windows/security` | medium | experimental |
| 3 | RDP Tunneling - Loopback RDP Logon (High Confidence) | attack.t1572, attack.t1021.001 | command_and_control, lateral_movement | `windows/security` | high | experimental |
| 4 | Suspicious Scheduled Task Creation via schtasks.exe | attack.t1053.005 | persistence, privilege_escalation | `windows/?` | high | experimental |
| 5 | Process Hollowing - Sysmon ProcessTampering | attack.t1055.012 | defense_evasion, privilege_escalation | `windows/sysmon` | critical | experimental |
| 6 | Process Hollowing - CreateRemoteThread with Unbacked Start Address | attack.t1055.012 | defense_evasion | `windows/sysmon` | high | experimental |
| 7 | Process Injection - Suspicious CreateRemoteThread | attack.t1055, attack.t1055.002 | defense_evasion, privilege_escalation | `windows/sysmon` | high | experimental |
| 8 | Suspicious PowerShell Execution | attack.t1059.001 | execution | `windows/?` | high | experimental |
| 9 | Suspicious DNS Query - Potential C2 (Long Labels / DGA / Bad TLD) | attack.t1071.001, attack.t1568.002 | command_and_control | `windows/sysmon` | medium | experimental |
| 10 | Suspicious Outbound Network Connection - Potential C2 | attack.t1071, attack.t1071.001 | command_and_control | `windows/sysmon` | high | experimental |
| 11 | Account Manipulation - New Account or Privileged Group Add | attack.t1098 | persistence | `windows/security` | high | experimental |
| 12 | Ransomware File Encryption Behavior | attack.t1486 | impact | `windows/sysmon` | critical | experimental |
| 13 | Inhibit System Recovery - Ransomware Precursor | attack.t1490 | impact | `windows/sysmon` | high | stable |
| 14 | Registry Run Key Persistence | attack.t1547.001 | persistence | `windows/sysmon` | medium | experimental |

## Summary

- **Total rules**: 14
- **Unique techniques**: 16
- **Unique tactics**: 9

### Techniques covered

- attack.t1003.001
- attack.t1003.002
- attack.t1021.001
- attack.t1053.005
- attack.t1055
- attack.t1055.002
- attack.t1055.012
- attack.t1059.001
- attack.t1071
- attack.t1071.001
- attack.t1098
- attack.t1486
- attack.t1490
- attack.t1547.001
- attack.t1568.002
- attack.t1572

### Tactics covered

- command_and_control
- credential_access
- defense_evasion
- execution
- impact
- lateral_movement
- persistence
- privilege_escalation
