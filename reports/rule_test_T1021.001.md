# Rule Test Report — T1021.001 RDP Lateral Movement

**Rule files:** `rules/T1021.001_rdp_lateral_movement.yml`
  (contains Rule A "broad" and Rule B "RDP Tunneling loopback")
**Test date:** 2026-10-09
**Tester:** Cyberion Detection Engineering Lab
**Dataset:** EVTX-ATTACK-SAMPLES (278 EVTX files)
**Total Security Event ID 4624 records analyzed:** 87

---

## Test Methodology

A Python tester (`test_rule_T1021.001.py`) parses every EVTX file in the
dataset, extracts all Windows Security Event ID 4624 (successful logon)
records, and applies two Sigma-equivalent rules:

- **Rule A (broad)** — fires on `LogonType = 10` (RemoteInteractive / RDP),
  excluding machine accounts (`*$`) and well-known service accounts.
- **Rule B (loopback tunnel)** — Rule A + `IpAddress ∈ {127.0.0.1, ::1}`.
  Loopback RDP is the hallmark of protocol tunneling (chisel, socat,
  plink, stunnel, Meterpreter portfwd) that exposes RDP on a victim.

---

## Data Discovery — Before Writing the Rule

An initial diagnostic (`diagnose_rdp.py`) enumerated all 87 Security 4624
records across the corpus and revealed:

| LogonType | Count | Meaning |
|---|---|---|
| 3 | 61 | Network (SMB / WMI / PSExec / etc.) |
| 5 | 13 | Service |
| 2 | 4 | Interactive (console) |
| 9 | 4 | NewCredentials (PTH / runas /netonly) |
| **10** | **2** | **RemoteInteractive (RDP)** ⭐ |
| 0/1/7/11 | 1 each | Edge cases |

**Key finding:** Only **2 RDP (LogonType=10) records** exist in the entire
278-file corpus. Public attack-sample datasets under-represent RDP
because RDP tends to blend into legitimate administrative traffic.

A second diagnostic (`diagnose_rdp_detail.py`) drilled into both records
and revealed that **both had `IpAddress = 127.0.0.1`** — the loopback
interface. Legitimate users do not RDP to localhost. This pattern is the
distinctive signature of RDP-tunneling abuse, where port-forwarding
tools bind a local listener and tunnel RDP traffic out to the attacker.

### The 2 discovered events

| File | User | Source IP | Workstation | LogonProcess |
|---|---|---|---|---|
| `Command and Control\DE_RDP_Tunneling_4624.evtx` | IEUser | 127.0.0.1 | PC02 | User32 |
| `Command and Control\DE_RDP_Tunnel_5156.evtx` | admin01 | 127.0.0.1 | PC01 | User32 |

Both are from the **Command and Control** category — i.e., the dataset
authors explicitly labeled these as C2 tunnel abuse.

---

## Detection Rules

### Rule A — RDP Lateral Movement (broad, medium severity)

```yaml
selection_event:
  EventID: 4624
selection_logon_type:
  LogonType: '10'
filter_machine_accounts:
  TargetUserName|endswith: '$'
filter_system_accounts:
  TargetUserName: ['SYSTEM', 'LOCAL SERVICE', ...]
condition: selection_event and selection_logon_type
           and not filter_machine_accounts
           and not filter_system_accounts