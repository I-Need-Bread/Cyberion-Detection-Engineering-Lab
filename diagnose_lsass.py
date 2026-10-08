import glob
import os
import xml.etree.ElementTree as ET
from collections import Counter
from Evtx.Evtx import Evtx


def main():
    files = glob.glob("data/**/*.evtx", recursive=True)

    target_counter = Counter()
    access_counter = Counter()
    source_counter = Counter()

    for f in files:
        try:
            with Evtx(f) as log:
                for record in log.records():
                    try:
                        root = ET.fromstring(record.xml())
                    except ET.ParseError:
                        continue

                    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                    eid_el = root.find(".//e:System/e:EventID", ns)
                    event_id = int(eid_el.text) if eid_el is not None else -1
                    if event_id != 10:
                        continue

                    data = {}
                    for d in root.findall(".//e:EventData/e:Data", ns):
                        name = d.attrib.get("Name")
                        if name:
                            data[name] = d.text or ""

                    tgt = data.get("TargetImage", "").lower()
                    ga = data.get("GrantedAccess", "").lower()
                    src = data.get("SourceImage", "").lower()

                    target_counter[os.path.basename(tgt)] += 1
                    access_counter[ga] += 1
                    if "lsass" in tgt:
                        source_counter[src] += 1

        except Exception as exc:
            print("[!] " + f + ": " + str(exc))

    print("=" * 70)
    print("TARGET IMAGES (top 15)")
    print("=" * 70)
    for tgt, cnt in target_counter.most_common(15):
        print("  " + str(cnt).rjust(5) + "  " + tgt)

    print()
    print("=" * 70)
    print("GRANTED ACCESS VALUES (top 20)")
    print("=" * 70)
    for ga, cnt in access_counter.most_common(20):
        print("  " + str(cnt).rjust(5) + "  " + ga)

    print()
    print("=" * 70)
    print("SOURCE IMAGES HITTING LSASS (all)")
    print("=" * 70)
    for src, cnt in source_counter.most_common():
        print("  " + str(cnt).rjust(5) + "  " + src)


if __name__ == "__main__":
    main()