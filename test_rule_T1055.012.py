"""
Test the T1055.012 process hollowing rule against the dataset.
Sysmon Event ID 25 — ProcessTampering.
"""
import glob, os
from collections import Counter
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

SUSPICIOUS_TYPES = {
    "Image is replaced",
    "Image is locked for access",
    "Image is hijacked",
}

KNOWN_LEGIT_SUFFIXES = [
    "\\msmpeng.exe", "\\mpcmdrun.exe",
    "\\sysmon.exe", "\\sysmon64.exe",
    "\\mssense.exe", "\\sensecncproxy.exe",
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
    data = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for d in ed.findall(f"{NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()
    return eid, data


def is_filtered(data):
    img = (data.get("Image") or "").lower()
    user = (data.get("User") or "")
    if any(img.endswith(s) for s in KNOWN_LEGIT_SUFFIXES):
        return True
    if user.endswith("AUTHORITY\\SYSTEM") and "defender" in img:
        return True
    return False


def matches(data):
    if data.get("Type") not in SUSPICIOUS_TYPES:
        return False
    if is_filtered(data):
        return False
    return True


def main():
    files = sorted(glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True))
    print(f"[+] Found {len(files)} EVTX files\n")

    total_25 = 0
    matches = []
    for i, path in enumerate(files, 1):
        if i % 50 == 0:
            print(f"[..] {i}/{len(files)} | EID25={total_25} matches={len(matches)}")
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid != "25":
                        continue
                    total_25 += 1
                    if matches(data):
                        matches.append((path, data))
        except Exception as e:
            print(f"[!] {os.path.basename(path)}: {e}")
            continue

    print("\n" + "=" * 72)
    print("MATCHES — T1055.012 Process Hollowing (Sysmon EID 25)")
    print("=" * 72)
    for path, d in matches:
        print(f"\n  [MATCH] {os.path.relpath(path, BASE)}")
        for k in ("Image", "ProcessId", "User", "Type"):
            print(f"          {k:<12}: {d.get(k, '')}")

    print("\n" + "=" * 72)
    print("SUMMARY — T1055.012 Process Hollowing Rule")
    print("=" * 72)
    print(f"EVTX files scanned          : {len(files)}")
    print(f"Sysmon Event ID 25 records  : {total_25}")
    print(f"Rule matches                : {len(matches)}")
    print(f"Files containing matches    : {len({p for p,_ in matches})}")

    type_counter = Counter()
    for _, d in matches:
        type_counter[d.get("Type", "?")] += 1
    if type_counter:
        print("\nMatches by Type:")
        for t, c in type_counter.most_common():
            print(f"  {t:<30}: {c}")

    print("\nMatched files:")
    for f in sorted({p for p, _ in matches}):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()