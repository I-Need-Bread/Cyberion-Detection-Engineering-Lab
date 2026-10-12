"""
Test the T1055.012 process hollowing rule against the dataset.

Detects hollowing via Sysmon Event ID 8 (CreateRemoteThread):
  - StartModule is empty (thread starting in unbacked memory)
  - TargetImage is a known hollowable process (svchost, notepad, explorer, ...)
  - SourceImage is not a known-good Windows-internal thread creator
"""
import glob, os
from collections import Counter
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

# --- Targets typically abused for process hollowing ---
SUSPICIOUS_TARGETS = [
    "\\svchost.exe", "\\notepad.exe", "\\rundll32.exe",
    "\\explorer.exe", "\\dllhost.exe",
    "\\regasm.exe", "\\regsvcs.exe", "\\msbuild.exe",
]

# --- Windows-internal thread creators (legitimate) ---
KNOWN_SOURCES_HOLLOW = [
    "\\svchost.exe", "\\csrss.exe", "\\smss.exe", "\\wininit.exe",
    "\\services.exe", "\\lsass.exe",
    "\\msmpeng.exe", "\\mpcmdrun.exe",
    "\\sysmon.exe", "\\sysmon64.exe", "\\mssense.exe",
]


def parse(xml_bytes):
    """Same parser as diagnose_injection.py (verified on 104 records)."""
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
    """Return tier signals for the T1055.012 hollowing rule."""
    src = (data.get("SourceImage") or "").lower()
    tgt = (data.get("TargetImage") or "").lower()
    mod = (data.get("StartModule") or "").strip()

    # Exclusion: known-good source
    if any(src.endswith(s) for s in KNOWN_SOURCES_HOLLOW):
        return set()

    tiers = set()
    if mod == "":
        tiers.add("unbacked")
    if any(tgt.endswith(s) for s in SUSPICIOUS_TARGETS):
        tiers.add("target")
    return tiers


def main():
    files = sorted(glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True))
    print(f"[+] Found {len(files)} EVTX files\n")

    total_8 = 0
    no_signal = 0
    matches = []

    for i, path in enumerate(files, 1):
        if i % 50 == 0:
            print(f"[..] {i}/{len(files)} | EID8={total_8} matches={len(matches)}")
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid != "8":
                        continue
                    total_8 += 1
                    tiers = signals(data)
                    if "unbacked" not in tiers or "target" not in tiers:
                        no_signal += 1
                        continue
                    matches.append((path, data, tiers))
        except Exception as e:
            print(f"[!] {os.path.basename(path)}: {e}")
            continue

    print("\n" + "=" * 72)
    print("MATCHES — T1055.012 Process Hollowing (EID 8 + unbacked thread)")
    print("=" * 72)
    from itertools import groupby
    matches.sort(key=lambda x: x[0])
    for fname, group in groupby(matches, key=lambda x: x[0]):
        group = list(group)
        print(f"\n  [{len(group)} hits] {os.path.relpath(fname, BASE)}")
        for _, d, tiers in group[:3]:
            print(f"      tier={','.join(sorted(tiers))}")
            print(f"      {d.get('SourceImage','?')} -> {d.get('TargetImage','?')}")
            print(f"      StartAddress={d.get('StartAddress','?')} "
                  f"StartModule='{d.get('StartModule','')}'")

    print("\n" + "=" * 72)
    print("SUMMARY — T1055.012 Process Hollowing Rule")
    print("=" * 72)
    print(f"EVTX files scanned          : {len(files)}")
    print(f"Sysmon Event ID 8 records   : {total_8}")
    print(f"  no tier signal            : {no_signal}")
    print(f"Rule matches                : {len(matches)}")
    print(f"Files containing matches    : {len({p for p, _, _ in matches})}")

    tier_counter = Counter()
    for _, _, tiers in matches:
        for t in tiers:
            tier_counter[t] += 1
    print("\nMatches per tier:")
    for t, c in tier_counter.most_common():
        print(f"  {t:<24}: {c}")

    print("\nMatched files:")
    for f in sorted({p for p, _, _ in matches}):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()