"""Show all EID 11 records in the ransomware sample file."""
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
FILE = "data/EVTX-ATTACK-SAMPLES/AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx"

with evtx.Evtx(FILE) as log:
    for r in log.records():
        root = ET.fromstring(r.xml().encode("utf-8", "ignore"))
        eid = root.find(f"{NS}System").find(f"{NS}EventID").text.strip()
        if eid != "11":
            continue
        ed = root.find(f"{NS}EventData")
        if ed is None:
            continue
        data = {d.get("Name"): (d.text or "").strip() for d in ed.findall(f"{NS}Data") if d.get("Name")}
        print(f"Image       : {data.get('Image','')}")
        print(f"TargetFile  : {data.get('TargetFilename','')}")
        print()