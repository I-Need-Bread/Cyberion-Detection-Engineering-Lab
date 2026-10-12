"""
Diagnostic: enumerate every Sysmon Event ID 25 (ProcessTampering)
record in the dataset. Prints all fields so we can see what real
process-hollowing telemetry looks like.
"""
import glob, os
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

FIELDS = [
    "Image", "ProcessId", "User", "Type",
    "SourceImage", "SourceProcessId", "TargetImage", "TargetProcessId",
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

    total_25 = 0
    types = {}
    for path in files:
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, payload = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid != "25":
                        continue
                    ts, data = payload
                    total_25 += 1
                    t = data.get("Type", "?")
                    types[t] = types.get(t, 0) + 1
                    print("=" * 72)
                    print(f"FILE : {os.path.relpath(path, BASE)}")
                    print(f"TIME : {ts}")
                    print("-" * 72)
                    for k in FIELDS:
                        if k in data:
                            print(f"  {k:<18}: {data[k]}")
        except Exception:
            continue

    print(f"\n[+] Total Sysmon Event ID 25 records: {total_25}")
    if types:
        print("[+] Type distribution:")
        for t, c in sorted(types.items(), key=lambda x: -x[1]):
            print(f"      {c:>4}  {t}")


if __name__ == "__main__":
    main()