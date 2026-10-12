"""Show every Event ID present in the APT10 hollowing file."""
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
from collections import Counter

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
FILE = "data/EVTX-ATTACK-SAMPLES/Defense Evasion/apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.evtx"

counts = Counter()
with evtx.Evtx(FILE) as log:
    for r in log.records():
        root = ET.fromstring(r.xml().encode("utf-8", "ignore"))
        eid = root.find(f"{NS}System").find(f"{NS}EventID").text.strip()
        counts[eid] += 1

print(f"Event ID distribution in {FILE}:\n")
for eid, c in sorted(counts.items(), key=lambda x: int(x[0])):
    print(f"  EventID {eid:<5}: {c}")