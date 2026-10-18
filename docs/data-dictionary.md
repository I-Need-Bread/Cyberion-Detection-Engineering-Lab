# Data Dictionary & Telemetry Familiarization

This engagement utilizes the `EVTX-ATTACK-SAMPLES` dataset. Below are the three primary telemetry sources analyzed.

## 1. Sysmon (Event ID 1, 3, 8, 10, 11, 13, 22)
- **Provider:** `Microsoft-Windows-Sysmon`
- **Fields:** `Image`, `CommandLine`, `TargetImage`, `GrantedAccess`, `TargetFilename`, `DestinationIp`, `DestinationPort`.
- **Detection Value:** Provides deep behavioral visibility (process creation, network connections, process injection, file creation). Used heavily for detecting T1055, T1003.001, and T1071.

## 2. Windows Security Log (Event ID 4624, 4698, 4720, 4732)
- **Provider:** `Microsoft-Windows-Security-Auditing`
- **Fields:** `LogonType`, `TargetUserName`, `IpAddress`, `TaskName`, `TaskContent`.
- **Detection Value:** The authoritative source for identity and access events. Used for detecting lateral movement (RDP), persistence (Scheduled Tasks), and account manipulation.

## 3. Windows System / BITS Logs (Event ID 3, 4)
- **Provider:** `Microsoft-Windows-Bits-Client`
- **Detection Value:** Crucial for detecting C2 and payload delivery via the Background Intelligent Transfer Service. Note: Event ID 3 collides with Sysmon EID 3; rules must filter by Provider.Name.