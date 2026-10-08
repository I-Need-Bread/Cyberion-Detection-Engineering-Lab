\# Data Dictionary — Cyberion Detection Engineering Lab



Three log sources mapped for detection engineering. Field names verified

against real EVTX-ATTACK-SAMPLES records.



\---



\## Source 1: Sysmon (Windows Event Log)



\*\*Provider:\*\* Microsoft-Windows-Sysmon

\*\*Channel:\*\* Microsoft-Windows-Sysmon/Operational



\### Event ID 1 — Process Creation

Key fields:

\- `Image` — full path of the created process

\- `CommandLine` — full command line (highest-value detection field)

\- `ParentImage` — parent process path

\- `User` — account that ran the process

\- `ProcessGuid` / `ProcessId` — correlates with other Sysmon events

\- `Hashes` — MD5/SHA256/IMPHASH



\### Event ID 3 — Network Connection

Key fields:

\- `Image`, `User`

\- `DestinationIp`, `DestinationPort`, `DestinationHostname`

\- `SourceIp`, `SourcePort`, `Protocol`

\- `Initiated` — true if outbound



\### Event ID 10 — Process Access

Key fields:

\- `SourceImage` — process doing the accessing

\- `TargetImage` — process being accessed (e.g. lsass.exe)

\- `GrantedAccess` — access rights requested

\- `CallTrace` — stack trace of the call



\### Event ID 11 — File Create

Key fields:

\- `Image`, `TargetFilename`, `CreationUtcTime`



\---



\## Source 2: Windows Security Log



\*\*Provider:\*\* Microsoft-Windows-Security-Auditing

\*\*Channel:\*\* Security



\### Event ID 4624 — Successful Logon

Key fields:

\- `TargetUserName`, `TargetDomainName`

\- `LogonType` (2=interactive, 3=network, 10=RDP)

\- `IpAddress`, `WorkstationName`

\- `LogonProcessName`



\### Event ID 4625 — Failed Logon

Key fields:

\- `TargetUserName`, `IpAddress`, `Status`, `SubStatus`, `LogonType`



\### Event ID 4688 — Process Creation

Key fields:

\- `NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserName`



\### Event ID 4720 / 4726 — User Account Created / Deleted

Key fields:

\- `TargetUserName`, `SubjectUserName`



\---



\## Source 3: PowerShell Operational Log



\*\*Provider:\*\* Microsoft-Windows-PowerShell

\*\*Channel:\*\* Microsoft-Windows-PowerShell/Operational



\### Event ID 4104 — Script Block Logging

Key fields:

\- `ScriptBlockText` — full deobfuscated PowerShell code (highest-value detection field)

\- `ScriptBlockId`

\- `MessageNumber`, `MessageTotal` — for reassembling multi-part scripts



\### Event ID 4103 — Module Logging

Key fields:

\- `Payload`, `ContextInfo`



\---



\## Detection-Relevant Field Mapping



| ATT\&CK Technique | Log Source | Key Event | Detection Field |

|---|---|---|---|

| T1059.001 PowerShell | PowerShell Op | 4104 | ScriptBlockText |

| T1003.001 LSASS Memory | Sysmon | 10 | TargetImage, GrantedAccess |

| T1053.005 Scheduled Task | Security / Sysmon | 4698 / 1 | TaskName, CommandLine |

| T1021.001 RDP | Security | 4624 | LogonType=10, IpAddress |

| T1071.001 Web C2 | Sysmon | 3 | DestinationHostname, DestinationPort |

