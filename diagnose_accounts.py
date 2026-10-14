"""
Diagnostic: enumerate Windows Security events 4720, 4722, 4724, 4726,
4728, 4732, 4738, 4756.
"""
import glob, os
from collections import Counter
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

TARGET_EIDS = {"4720", "4722", "4724", "4726", "4728", "4732", "4738", "4756"}


def parse(xml_bytes):
    root = ET.fromstring(xml_bytes)
    system = root.find(f"{NS}System")
    if system is None:
        return None, None
    eid_el = system.find(f"{NS}EventID")
    if eid_el is None:
        return None, None
    data = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for d in ed.findall(f"{NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()
    return eid_el.text.strip(), data


def main():
    files = glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True)
    print(f"[+] Found {len(files)} EVTX files\n")

    counts = Counter()
    new_accounts = []
    group_changes = []
    files_with = set()

    for path in files:
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid not in TARGET_EIDS:
                        continue
                    counts[eid] += 1
                    files_with.add(path)

                    if eid == "4720":
                        new_accounts.append((path, data))
                    elif eid in ("4728", "4732", "4756"):
                        group_changes.append((path, eid, data))
        except Exception:
            continue

    print("=" * 72)
    print("ACCOUNT MANIPULATION DIAGNOSTIC")
    print("=" * 72)
    print(f"Files with account events: {len(files_with)}\n")

    print("Event ID distribution:")
    for eid in sorted(counts):
        print(f"  EventID {eid}: {counts[eid]}")

    print(f"\nNew accounts created (4720): {len(new_accounts)}")
    for path, d in new_accounts[:10]:
        print(f"  {os.path.relpath(path, BASE)}")
        print(f"    TargetUserName : {d.get('TargetUserName','')}")
        print(f"    SubjectUserName: {d.get('SubjectUserName','')}")

    print(f"\nGroup membership changes: {len(group_changes)}")
    for path, eid, d in group_changes[:20]:
        member = d.get("MemberName", "")
        group = d.get("TargetUserName", "")
        subject = d.get("SubjectUserName", "")
        print(f"  [EID {eid}] {os.path.relpath(path, BASE)}")
        print(f"    Member  : {member}")
        print(f"    Group   : {group}")
        print(f"    Actor   : {subject}")

    print("\nFiles with account events:")
    for f in sorted(files_with):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()