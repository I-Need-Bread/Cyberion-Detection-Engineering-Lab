"""
Test the T1003.002 SAM registry dump rule against the dataset.
Sysmon Event ID 1 (ProcessCreate) with reg save / VSS signals.
"""
import glob, os
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

HIVE_KEYWORDS = ["\\sam", "\\security", "\\system"]
LEGIT_BACKUP_IMAGES = [
    "\\wbengine.exe", "\\vssvc.exe",
    "\\backupexec.exe", "\\veeam.exe",
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


def signals(data):
    """Return set of matched signals (A_reg_save, B_vss_copy, C_vss_create)."""
    img = (data.get("Image") or "").lower()
    cl  = (data.get("CommandLine") or "").lower()

    if not cl:
        return set()

    # Exclusion
    if any(img.endswith(s) for s in LEGIT_BACKUP_IMAGES):
        return set()

    tiers = set()

    # Signal A: reg save <hive>
    if img.endswith("\\reg.exe") and "save" in cl and "hklm\\" in cl:
        if any(h in cl for h in HIVE_KEYWORDS):
            tiers.add("A_reg_save")

    # Signal B: VSS copy of hive file
    if "globalroot\\device\\harddiskvolumeshadowcopy" in cl and \
       "\\windows\\system32\\config\\" in cl and "copy" in cl:
        tiers.add("B_vss_copy")

    # Signal C: vssadmin create shadow
    if "vssadmin" in cl and "create shadow" in cl:
        tiers.add("C_vss_create")

    return tiers


def main():
    files = sorted(glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True))
    print(f"[+] Found {len(files)} EVTX files\n")

    total_1 = 0
    matches = []

    for i, path in enumerate(files, 1):
        if i % 50 == 0:
            print(f"[..] {i}/{len(files)} | EID1={total_1} matches={len(matches)}")
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid != "1":
                        continue
                    total_1 += 1
                    tiers = signals(data)
                    if tiers:
                        matches.append((path, data, tiers))
        except Exception:
            continue

    print("\n" + "=" * 72)
    print("MATCHES — T1003.002 SAM Registry Hive Dump")
    print("=" * 72)
    for path, d, tiers in matches:
        print(f"\n  [MATCH | {','.join(sorted(tiers))}] "
              f"{os.path.relpath(path, BASE)}")
        print(f"          Image       : {d.get('Image','')}")
        print(f"          CommandLine : {d.get('CommandLine','')}")
        print(f"          Parent      : {d.get('ParentImage','')}")

    print("\n" + "=" * 72)
    print("SUMMARY — T1003.002 SAM Registry Dump Rule")
    print("=" * 72)
    print(f"EVTX files scanned          : {len(files)}")
    print(f"Sysmon Event ID 1 records   : {total_1}")
    print(f"Rule matches                : {len(matches)}")
    print(f"Files containing matches    : {len({p for p,_,_ in matches})}")

    from collections import Counter
    tier_counter = Counter()
    for _, _, tiers in matches:
        for t in tiers:
            tier_counter[t] += 1
    if tier_counter:
        print("\nMatches per signal:")
        for t, c in tier_counter.most_common():
            print(f"  {t:<20}: {c}")

    print("\nMatched files:")
    for f in sorted({p for p, _, _ in matches}):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()