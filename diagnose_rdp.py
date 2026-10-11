"""
Diagnostic: enumerate all Security Event ID 4624 records in the dataset.
Extracts LogonType, TargetUserName, IpAddress, WorkstationName,
AuthenticationPackageName, LogonProcessName — so we can see what the
data actually looks like before writing a detection rule.
"""
import glob
import os
from collections import Counter

try:
    import Evtx.Evtx as evtx
    import xml.etree.ElementTree as ET
except ImportError:
    print("[!] Install deps:  pip install python-evtx")
    raise

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

def extract_event(xml_bytes):
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return None
    # System block
    system = root.find(f"{NS}System")
    if system is None:
        return None
    eid_el = system.find(f"{NS}EventID")
    if eid_el is None:
        return None
    event_id = eid_el.text.strip()
    # EventData block
    data = {}
    event_data = root.find(f"{NS}EventData")
    if event_data is not None:
        for d in event_data.findall(f"{NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()
    return event_id, data


def main():
    base = os.path.join("data", "EVTX-ATTACK-SAMPLES")
    evtx_files = glob.glob(os.path.join(base, "**", "*.evtx"), recursive=True)
    print(f"[+] Found {len(evtx_files)} EVTX files\n")

    logon_type_counter = Counter()
    user_counter = Counter()
    ip_counter = Counter()
    authpkg_counter = Counter()
    logonproc_counter = Counter()

    files_with_4624 = []
    total_4624 = 0

    for path in evtx_files:
        file_has_4624 = False
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        parsed = extract_event(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if not parsed:
                        continue
                    event_id, data = parsed
                    if event_id != "4624":
                        continue

                    file_has_4624 = True
                    total_4624 += 1
                    logon_type_counter[data.get("LogonType", "?")] += 1
                    user_counter[data.get("TargetUserName", "?")] += 1
                    ip_counter[data.get("IpAddress", "?")] += 1
                    authpkg_counter[data.get("AuthenticationPackageName", "?")] += 1
                    logonproc_counter[data.get("LogonProcessName", "?")] += 1
        except Exception as e:
            print(f"  [!] {os.path.basename(path)}: {e}")
            continue
        if file_has_4624:
            files_with_4624.append(path)

    print("=" * 70)
    print("SECURITY 4624 DIAGNOSTIC")
    print("=" * 70)
    print(f"Total 4624 records     : {total_4624}")
    print(f"Files containing 4624  : {len(files_with_4624)}\n")

    print("LogonType distribution:")
    for lt, cnt in sorted(logon_type_counter.items()):
        marker = "  <-- RDP (RemoteInteractive)" if lt == "10" else ""
        print(f"  LogonType={lt:<3} : {cnt:>4}{marker}")

    print("\nTop 10 TargetUserName:")
    for u, c in user_counter.most_common(10):
        print(f"  {c:>4}  {u}")

    print("\nTop 10 IpAddress:")
    for ip, c in ip_counter.most_common(10):
        print(f"  {c:>4}  {ip}")

    print("\nAuthenticationPackageName distribution:")
    for a, c in authpkg_counter.most_common():
        print(f"  {c:>4}  {a}")

    print("\nLogonProcessName distribution:")
    for lp, c in logonproc_counter.most_common():
        print(f"  {c:>4}  {lp}")

    print("\nFiles with 4624:")
    for f in files_with_4624:
        print(f"  - {os.path.relpath(f, base)}")


if __name__ == "__main__":
    main()