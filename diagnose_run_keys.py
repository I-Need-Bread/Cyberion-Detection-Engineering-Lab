"""
Diagnostic: enumerate all Sysmon Event ID 12/13/14 (registry) records
and count TargetObject paths by suffix. Reveals what registry
telemetry exists in the corpus.
"""
import glob, os
from collections import Counter
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")


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


def main():
    files = glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True)
    print(f"[+] Found {len(files)} EVTX files\n")

    counts = Counter()
    obj_counter = Counter()
    files_with_reg = set()

    for path in files:
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid not in ("12", "13", "14"):
                        continue
                    counts[eid] += 1
                    obj = data.get("TargetObject", "")
                    if obj:
                        obj_counter[obj] += 1
                        files_with_reg.add(path)
        except Exception:
            continue

    print("Registry event counts:")
    for eid in sorted(counts):
        label = {"12": "CreateKey/DeleteKey",
                 "13": "SetValue",
                 "14": "RenameKey"}.get(eid, "?")
        print(f"  EventID {eid:<3} ({label:<18}): {counts[eid]}")

    print(f"\nFiles with registry events: {len(files_with_reg)}")

    print(f"\nTop 25 TargetObject paths:")
    for obj, c in obj_counter.most_common(25):
        print(f"  {c:>4}  {obj}")

    print(f"\nRun-key hits (TargetObject contains 'CurrentVersion\\Run'):")
    hits = [(o, c) for o, c in obj_counter.items()
            if "currentversion\\run" in o.lower()]
    if hits:
        for obj, c in sorted(hits, key=lambda x: -x[1]):
            print(f"  {c:>4}  {obj}")
    else:
        print("  (none found)")


if __name__ == "__main__":
    main()