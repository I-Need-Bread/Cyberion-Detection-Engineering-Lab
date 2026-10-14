"""
Diagnostic: Sysmon NetworkConnect only (filter by Provider.Name).
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
        return None, None, None
    eid_el = system.find(f"{NS}EventID")
    if eid_el is None:
        return None, None, None
    provider_el = system.find(f"{NS}Provider")
    provider = provider_el.get("Name") if provider_el is not None else ""
    data = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for d in ed.findall(f"{NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()
    return eid_el.text.strip(), provider, data


def main():
    files = glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True)
    print(f"[+] Found {len(files)} EVTX files\n")

    total_sysmon_3 = 0
    total_other_3 = 0
    providers = Counter()
    port_counter = Counter()
    image_counter = Counter()
    dest_ip_counter = Counter()
    outbound = 0
    inbound = 0

    for path in files:
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, provider, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid != "3":
                        continue
                    if "Sysmon" not in provider:
                        total_other_3 += 1
                        providers[provider] += 1
                        continue
                    total_sysmon_3 += 1
                    if data.get("Initiated", "").lower() == "true":
                        outbound += 1
                    else:
                        inbound += 1
                    port_counter[data.get("DestinationPort", "?")] += 1
                    image_counter[data.get("Image", "?")] += 1
                    dest_ip_counter[data.get("DestinationIp", "?")] += 1
        except Exception:
            continue

    print("=" * 72)
    print("SYSMON NETWORKCONNECT ONLY (Provider.Name contains 'Sysmon')")
    print("=" * 72)
    print(f"Total Sysmon Event ID 3   : {total_sysmon_3}")
    print(f"Non-Sysmon Event ID 3     : {total_other_3}")
    print(f"  Outbound (Initiated=true): {outbound}")
    print(f"  Inbound                  : {inbound}")

    print("\nOther Event ID 3 providers:")
    for p, c in providers.most_common():
        print(f"  {c:>4}  {p}")

    print("\nTop 25 destination ports (Sysmon only):")
    for p, c in port_counter.most_common(25):
        print(f"  {c:>4}  {p}")

    print("\nTop 20 source processes (Sysmon only):")
    for i, c in image_counter.most_common(20):
        print(f"  {c:>4}  {i}")

    print("\nTop 20 destination IPs (Sysmon only):")
    for ip, c in dest_ip_counter.most_common(20):
        print(f"  {c:>4}  {ip}")


if __name__ == "__main__":
    main()