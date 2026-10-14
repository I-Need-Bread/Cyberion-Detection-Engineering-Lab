"""
Diagnostic: enumerate all Sysmon Event ID 22 (DnsQuery) records in the
corpus. Show query distribution, TLD counts, and top domains.
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

    total_22 = 0
    qname_counter = Counter()
    tld_counter = Counter()
    image_counter = Counter()
    files_with_dns = set()
    long_labels = 0
    high_entropy_examples = []

    for path in files:
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid != "22":
                        continue
                    total_22 += 1
                    q = data.get("QueryName", "").rstrip(".")
                    if q:
                        qname_counter[q] += 1
                        files_with_dns.add(path)
                        tld = q.rsplit(".", 1)[-1].lower() if "." in q else "?"
                        tld_counter[tld] += 1
                        # Flag long labels (potential tunneling)
                        labels = q.split(".")
                        if any(len(lbl) > 30 for lbl in labels):
                            long_labels += 1
                            if len(high_entropy_examples) < 20:
                                high_entropy_examples.append(q)
                    img = data.get("Image", "")
                    if img:
                        image_counter[img] += 1
        except Exception:
            continue

    print("=" * 72)
    print("SYSmon EVENT ID 22 (DnsQuery) DIAGNOSTIC")
    print("=" * 72)
    print(f"Total Event ID 22 records   : {total_22}")
    print(f"Files with DNS queries      : {len(files_with_dns)}")
    print(f"Records with long labels    : {long_labels}  (potential tunneling)")

    print("\nTop 30 queried domains:")
    for q, c in qname_counter.most_common(30):
        print(f"  {c:>4}  {q}")

    print("\nTLD distribution (top 25):")
    for tld, c in tld_counter.most_common(25):
        print(f"  {c:>4}  .{tld}")

    print("\nTop 15 querying processes:")
    for img, c in image_counter.most_common(15):
        print(f"  {c:>4}  {img}")

    if high_entropy_examples:
        print("\nExamples with long labels (potential tunneling):")
        for q in high_entropy_examples:
            print(f"  {q}")

    print("\nFiles with DNS queries:")
    for f in sorted(files_with_dns):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()