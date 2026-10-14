"""
Diagnostic: enumerate all Sysmon Event ID 3 (NetworkConnect) records
in the corpus. Show destination ports, remote IPs, and process mix.
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

    total_3 = 0
    port_counter = Counter()
    proto_counter = Counter()
    image_counter = Counter()
    remote_ip_counter = Counter()
    files_with_conn = set()
    initi_only = 0

    for path in files:
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid != "3":
                        continue
                    total_3 += 1
                    files_with_conn.add(path)
                    if data.get("Initiated") == "true":
                        initi_only += 1
                    port_counter[data.get("DestinationPort", "?")] += 1
                    proto_counter[data.get("Protocol", "?")] += 1
                    image_counter[data.get("Image", "?")] += 1
                    remote_ip_counter[data.get("DestinationIp", "?")] += 1
        except Exception:
            continue

    print("=" * 72)
    print("SYSMON EVENT ID 3 (NetworkConnect) DIAGNOSTIC")
    print("=" * 72)
    print(f"Total Event ID 3 records    : {total_3}")
    print(f"Files with network events   : {len(files_with_conn)}")
    print(f"Initiated outbound (true)   : {initi_only}")

    print("\nTop 30 destination ports:")
    for p, c in port_counter.most_common(30):
        print(f"  {c:>4}  {p}")

    print("\nProtocol distribution:")
    for p, c in proto_counter.most_common():
        print(f"  {c:>4}  {p}")

    print("\nTop 20 querying processes:")
    for i, c in image_counter.most_common(20):
        print(f"  {c:>4}  {i}")

    print("\nTop 20 destination IPs:")
    for ip, c in remote_ip_counter.most_common(20):
        print(f"  {c:>4}  {ip}")

    print("\nFiles with network events:")
    for f in sorted(files_with_conn):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()