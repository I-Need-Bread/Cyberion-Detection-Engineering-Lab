"""
Dump the raw EventData field names for the first 5 Event ID 3 records
that have no DestinationPort — reveals what field names are actually used.
"""
import glob, os
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")


def main():
    files = sorted(glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True))
    shown = 0
    for path in files:
        if shown >= 5:
            break
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        root = ET.fromstring(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    system = root.find(f"{NS}System")
                    if system is None:
                        continue
                    eid_el = system.find(f"{NS}EventID")
                    if eid_el is None or eid_el.text.strip() != "3":
                        continue
                    data = {}
                    ed = root.find(f"{NS}EventData")
                    if ed is not None:
                        for d in ed.findall(f"{NS}Data"):
                            name = d.get("Name")
                            if name:
                                data[name] = (d.text or "").strip()
                    # Only show records that lack DestinationPort
                    if "DestinationPort" in data:
                        continue
                    shown += 1
                    print("=" * 72)
                    print(f"FILE : {os.path.relpath(path, BASE)}")
                    print("-" * 72)
                    for k, v in data.items():
                        print(f"  {k:<25}: {v}")
                    # Also try to find provider name
                    provider = system.find(f"{NS}Provider")
                    if provider is not None:
                        print(f"  Provider.Name            : {provider.get('Name')}")
        except Exception as e:
            print(f"[!] {os.path.basename(path)}: {e}")
            continue
    if shown == 0:
        print("[!] No Event ID 3 records lacking DestinationPort found")


if __name__ == "__main__":
    main()