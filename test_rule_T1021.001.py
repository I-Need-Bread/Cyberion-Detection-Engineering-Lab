"""
Test the T1021.001 RDP lateral movement rules against the local dataset.
Two rule variants are checked:
  Rule A (broad)  : 4624 + LogonType 10 + not machine/system accounts
  Rule B (tunnel) : Rule A + IpAddress in {127.0.0.1, ::1}
"""
import glob, os, sys
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

# Rule A filters
MACHINE_SUFFIX = "$"
SYSTEM_USERS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
    "DWM-1", "DWM-2", "UMFD-0", "UMFD-1",
}
LOOPBACK_IPS = {"127.0.0.1", "::1"}


def parse(xml_bytes):
    root = ET.fromstring(xml_bytes)
    system = root.find(f"{NS}System")
    if system is None:
        return None, None
    eid_el = system.find(f"{NS}EventID")
    if eid_el is None:
        return None, None
    eid = eid_el.text.strip()
    data = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for d in ed.findall(f"{NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()
    return eid, data


def matches_rule_a(data):
    if data.get("LogonType") != "10":
        return False
    user = data.get("TargetUserName", "")
    if user.endswith(MACHINE_SUFFIX):
        return False
    if user in SYSTEM_USERS:
        return False
    return True


def matches_rule_b(data):
    return matches_rule_a(data) and data.get("IpAddress", "") in LOOPBACK_IPS


def main():
    files = glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True)
    print(f"[+] Found {len(files)} EVTX files\n")

    total_4624 = 0
    matches_a = []
    matches_b = []

    for i, path in enumerate(files, 1):
        if i % 25 == 0:
            print(f"[..] {i}/{len(files)} files scanned | "
                  f"A={len(matches_a)} B={len(matches_b)}")
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid != "4624":
                        continue
                    total_4624 += 1
                    if matches_rule_a(data):
                        matches_a.append((path, data))
                    if matches_rule_b(data):
                        matches_b.append((path, data))
        except Exception:
            continue

    def dump(title, matches):
        print("\n" + "=" * 72)
        print(title)
        print("=" * 72)
        for path, d in matches:
            print(f"\n  [MATCH] {os.path.relpath(path, BASE)}")
            for k in ("TargetUserName", "TargetDomainName", "IpAddress",
                      "IpPort", "WorkstationName", "LogonType",
                      "AuthenticationPackageName", "LogonProcessName",
                      "SubjectUserName"):
                print(f"          {k:<26}: {d.get(k, '')}")
        print(f"\n  Total: {len(matches)}")

    dump("Rule A — RDP Lateral Movement (broad)", matches_a)
    dump("Rule B — RDP Tunneling (loopback, high-confidence)", matches_b)

    print("\n" + "=" * 72)
    print("SUMMARY — T1021.001 RDP Rules")
    print("=" * 72)
    print(f"EVTX files scanned        : {len(files)}")
    print(f"Security 4624 records     : {total_4624}")
    print(f"Rule A matches (broad)    : {len(matches_a)}")
    print(f"Rule B matches (tunnel)   : {len(matches_b)}")
    unique_a = {p for p, _ in matches_a}
    unique_b = {p for p, _ in matches_b}
    print(f"Files with Rule A matches : {len(unique_a)}")
    print(f"Files with Rule B matches : {len(unique_b)}")

    print("\nRule A matched files:")
    for f in sorted(unique_a):
        print(f"  - {os.path.relpath(f, BASE)}")
    print("\nRule B matched files:")
    for f in sorted(unique_b):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()