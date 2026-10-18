# Incident Response Playbook: C2 Beaconing

## 1. Trigger Conditions
- Alert from `T1071_web_c2_network.yml` (Suspicious Outbound Network Connection).
- Anomalous outbound traffic from a LOLBin (e.g., `notepad.exe` making an HTTP request).

## 2. Investigation Steps
1. Identify the source process `Image` and `CommandLine` from Sysmon EID 1.
2. Check parent process (e.g., did `winword.exe` spawn the process?).
3. Extract `DestinationIp` and `DestinationPort` from Sysmon EID 3.
4. Correlate with DNS logs (Sysmon EID 22) to find the requested domain.
5. Use threat intel (VirusTotal, AlienVault) to check domain/IP reputation.

## 3. Containment
- Isolate the endpoint via EDR.
- Block the destination IP/Domain at the perimeter firewall.

## 4. Eradication & Recovery
- Identify the initial infection vector (e.g., phishing email).
- Kill the malicious process tree.
- Remove persistence mechanisms (Run keys, Scheduled Tasks).

## 5. Communication
- Notify SOC Lead immediately.
- If data exfiltration is suspected, escalate to Legal and Compliance.