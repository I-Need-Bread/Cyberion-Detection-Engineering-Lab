"""
Diagnostic: find Event ID 1 (ProcessCreate) records where CommandLine
references SAM, SYSTEM, SECURITY hives, or registry-dump tools.
"""
import glob, os
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

KEYWORDS = [
    "reg save", "reg.exe save", "reg  save",
    "\\sam", "hklm\\sam", "\\system32\\config\\sam",
    "\\system32\\config\\system", "\\system32\\config\\security",
    "esentutl", "vssadmin", "wmic shadowcopy", "diskshadow",
    "secretsdump", "regback", "reg export",
]


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

    hits = []
    for path in files:
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid != "1":
                        continue
                    cl = (data.get("CommandLine") or "").lower()
                    if not cl:
                        continue
                    for kw in KEYWORDS:
                        if kw in cl:
                            hits.append((path, data, kw))
                            break
        except Exception:
            continue

    print("=" * 72)
    print("HITS — ProcessCreate with SAM/registry-dump keywords")
    print("=" * 72)
    for path, d, kw in hits:
        print(f"\n  [{kw}] {os.path.relpath(path, BASE)}")
        print(f"      Image       : {d.get('Image','')}")
        print(f"      CommandLine : {d.get('CommandLine','')}")
        print(f"      Parent      : {d.get('ParentImage','')}")
        print(f"      User        : {d.get('User','')}")

    print(f"\n[+] Total hits: {len(hits)}")
    print(f"[+] Unique files: {len({p for p,_,_ in hits})}")


if __name__ == "__main__":
    main()