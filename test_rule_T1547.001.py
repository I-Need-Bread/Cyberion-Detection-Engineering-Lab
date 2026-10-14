"""
Test the T1547.001 Registry Run Key persistence rule against the dataset.
Sysmon Event ID 13 (RegistryValueSet).

Parser mirrors diagnose_run_keys.py (verified to find 223 EID13 records).
"""
import glob, os
from collections import Counter
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

# --- Run-key substrings (add RunOnceEx which the previous version missed) ---
RUN_KEY_SUBSTRINGS = [
    "\\currentversion\\run\\",
    "\\currentversion\\runonce\\",
    "\\currentversion\\runonceex\\",
    "\\currentversion\\policies\\explorer\\run\\",
    "\\currentversion\\runservices\\",
    "\\currentversion\\runservicesonce\\",
]

# --- Known-good writers (installers, Defender, Sysmon) ---
LEGIT_SOURCES = [
    "\\msiexec.exe", "\\trustedinstaller.exe", "\\poqexec.exe",
    "\\msmpeng.exe", "\\mpcmdrun.exe",
    "\\setup.exe", "\\setup64.exe",
    "\\sysmon.exe", "\\sysmon64.exe",
]

# --- Known-good values (default Windows entries) ---
KNOWN_VALUES = ["securityhealth", "onedrivesetup.exe"]


def parse(xml_bytes):
    """Identical structure to diagnose_run_keys.py — no silent failures."""
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


def matches(data):
    tgt = (data.get("TargetObject") or "").lower()
    if not any(s in tgt for s in RUN_KEY_SUBSTRINGS):
        return False
    img = (data.get("Image") or "").lower()
    if any(img.endswith(s) for s in LEGIT_SOURCES):
        return False
    det = (data.get("Details") or "").lower()
    if any(det.endswith(v) for v in KNOWN_VALUES):
        return False
    return True


def main():
    files = sorted(glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True))
    print(f"[+] Found {len(files)} EVTX files\n")

    total_13 = 0
    matches_list = []
    parse_fail = 0

    for i, path in enumerate(files, 1):
        if i % 50 == 0:
            print(f"[..] {i}/{len(files)} | EID13={total_13} matches={len(matches_list)}")
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        parse_fail += 1
                        continue
                    if eid != "13":
                        continue
                    total_13 += 1
                    if matches(data):
                        matches_list.append((path, data))
        except Exception:
            continue

    print("\n" + "=" * 72)
    print("MATCHES — T1547.001 Registry Run Key Persistence")
    print("=" * 72)
    for path, d in matches_list:
        print(f"\n  [MATCH] {os.path.relpath(path, BASE)}")
        print(f"          Image        : {d.get('Image','')}")
        print(f"          TargetObject : {d.get('TargetObject','')}")
        print(f"          Details      : {d.get('Details','')}")
        print(f"          User         : {d.get('User','')}")

    print("\n" + "=" * 72)
    print("SUMMARY — T1547.001 Registry Run Key Rule")
    print("=" * 72)
    print(f"EVTX files scanned          : {len(files)}")
    print(f"Sysmon Event ID 13 records  : {total_13}")
    print(f"Parse failures              : {parse_fail}")
    print(f"Rule matches                : {len(matches_list)}")
    print(f"Files containing matches    : {len({p for p,_ in matches_list})}")

    print("\nMatched files:")
    for f in sorted({p for p, _ in matches_list}):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()