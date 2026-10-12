"""
Diagnostic: print every Sysmon Event ID 8 (CreateRemoteThread) record
in the dataset — unfiltered — so we can see what real injection data
looks like before trusting the rule.
"""
import glob, os
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

FIELDS = [
    "SourceImage", "TargetImage", "SourceProcessId", "TargetProcessId",
    "NewThreadId", "StartAddress", "StartModule", "StartFunction",
    "SourceUser", "TargetUser",
]


def parse(xml_bytes):
    root = ET.fromstring(xml_bytes)
    system = root.find(f"{NS}System")
    if system is None:
        return None, None
    eid_el = system.find(f"{NS}EventID")
    if eid_el is None:
        return None, None
    eid = eid_el.text.strip()
    time_el = system.find(f"{NS}TimeCreated")
    ts = time_el.get("SystemTime") if time_el is not None else "?"
    data = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for d in ed.findall(f"{NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()
    return eid, (ts, data)


def main():
    files = glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True)
    print(f"[+] Found {len(files)} EVTX files\n")

    event8_count = 0
    for path in files:
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, payload = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid != "8":
                        continue
                    ts, data = payload
                    event8_count += 1
                    print("=" * 72)
                    print(f"FILE : {os.path.relpath(path, BASE)}")
                    print(f"TIME : {ts}")
                    print("-" * 72)
                    for k in FIELDS:
                        print(f"  {k:<18}: {data.get(k, '')}")
        except Exception as e:
            continue

    print(f"\n[+] Total Sysmon Event ID 8 records: {event8_count}")


if __name__ == "__main__":
    main()