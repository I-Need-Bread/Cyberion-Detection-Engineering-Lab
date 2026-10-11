"""
Drill down: print full details for every LogonType=10 (RDP) 4624 event.
"""
import glob, os
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

FIELDS_OF_INTEREST = [
    "TargetUserName", "TargetDomainName", "LogonType", "LogonProcessName",
    "AuthenticationPackageName", "WorkstationName", "IpAddress", "IpPort",
    "SubjectUserName", "SubjectDomainName", "LogonGuid", "TargetLogonId",
    "ProcessName", "ProcessId",
]

def parse(xml_bytes):
    root = ET.fromstring(xml_bytes)
    system = root.find(f"{NS}System")
    eid = system.find(f"{NS}EventID").text.strip() if system is not None else None
    time_el = system.find(f"{NS}TimeCreated") if system is not None else None
    ts = time_el.get("SystemTime") if time_el is not None else "?"
    data = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for d in ed.findall(f"{NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()
    return eid, ts, data


base = os.path.join("data", "EVTX-ATTACK-SAMPLES")
files = glob.glob(os.path.join(base, "**", "*.evtx"), recursive=True)

found = 0
for path in files:
    try:
        with evtx.Evtx(path) as log:
            for record in log.records():
                try:
                    eid, ts, data = parse(record.xml().encode("utf-8", "ignore"))
                except Exception:
                    continue
                if eid != "4624" or data.get("LogonType") != "10":
                    continue
                found += 1
                print("=" * 72)
                print(f"FILE : {os.path.relpath(path, base)}")
                print(f"TIME : {ts}")
                print("-" * 72)
                for k in FIELDS_OF_INTEREST:
                    if k in data:
                        print(f"  {k:<28} : {data[k]}")
    except Exception:
        continue

print(f"\n[+] Total LogonType=10 records: {found}")