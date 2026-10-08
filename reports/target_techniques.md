\# Target ATT\&CK Techniques — Cyberion Detection Engineering Lab



Five techniques chosen for detection engineering focus, spanning multiple

tactics and log sources.



| # | Technique ID | Tactic | Name | Primary Log Source |

|---|---|---|---|---|

| 1 | T1059.001 | Execution | PowerShell | PowerShell 4104 |

| 2 | T1053.005 | Persistence | Scheduled Task | Security 4698 / Sysmon 1 |

| 3 | T1003.001 | Credential Access | LSASS Memory | Sysmon 10 |

| 4 | T1021.001 | Lateral Movement | RDP | Security 4624 |

| 5 | T1071.001 | Command \& Control | Web Protocols | Sysmon 3 |



\## Justification



Chosen for high SOC relevance, availability in EVTX-ATTACK-SAMPLES, coverage

across the attack lifecycle, and mapping to distinct detection fields.

