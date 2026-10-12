"""
Test the T1055 process injection rule (v2, three-tier) against the dataset.

Uses the same parser as diagnose_injection.py (verified to find 104 records).
"""
import glob, os
from collections import Counter
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

# --- Tier B: unusual injection sources ---
SUSPICIOUS_SOURCES = [
    "\\winword.exe", "\\excel.exe", "\\powerpnt.exe", "\\outlook.exe",
    "\\w3wp.exe",
    "\\powershell.exe", "\\pwsh.exe",
    "\\wscript.exe", "\\cscript.exe", "\\mshta.exe",
    "\\rundll32.exe", "\\regsvr32.exe",
    "\\m.exe",
    "\\keefarce.exe",
    "\\rdrleakdiag.exe",
    ".msg.exe",
]

# --- Exclusions: Windows-internal cross-process thread creators ---
KNOWN_SOURCES = [
    "\\svchost.exe", "\\csrss.exe", "\\smss.exe", "\\wininit.exe",
    "\\services.exe", "\\lsass.exe", "\\winlogon.exe",
    "\\msmpeng.exe", "\\mpcmdrun.exe",
    "\\sysmon.exe", "\\sysmon64.exe",
    "\\mssense.exe", "\\sensecncproxy.exe",
]

SUSPICIOUS_MODULES = ["\\bootstrapdll.dll", "\\bootstrapdll64.dll"]
SUSPICIOUS_FUNCTIONS = {
    "dbguiiremotebreakin", "loadmanagedproject", "loadlibraryw",
}


def parse(xml_bytes):
    """Identical to diagnose_injection.py."""
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


def is_filtered(src):
    s = src.lower()
    return any(s.endswith(suffix) for suffix in KNOWN_SOURCES)


def signals(data):
    src = (data.get("SourceImage") or "").lower()
    tgt = (data.get("TargetImage") or "").lower()
    mod = (data.get("StartModule") or "").lower()
    fn  = (data.get("StartFunction") or "").lower()

    tiers = set()
    if tgt.endswith("\\lsass.exe"):
        tiers.add("A_lsass")
    if any(src.endswith(s) for s in SUSPICIOUS_SOURCES):
        tiers.add("B_suspicious_source")
    if any(mod.endswith(m) for m in SUSPICIOUS_MODULES):
        tiers.add("C_module")
    if fn in SUSPICIOUS_FUNCTIONS:
        tiers.add("C_function")
    return tiers


def main():
    files = sorted(glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True))
    print(f"[+] Found {len(files)} EVTX files\n")

    total_8 = 0
    filtered = 0
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
                    src = data.get("SourceImage", "")
                    if is_filtered(src):
                        filtered += 1
                        continue
                    tiers = signals(data)
                    if not tiers:
                        no_signal += 1
                        continue
                    matches.append((path, data, tiers))
        except Exception as e:
            print(f"[!] {os.path.basename(path)}: {e}")
            continue

    print("\n" + "=" * 72)
    print("MATCHES — T1055 Process Injection Rule v2")
    print("=" * 72)
    # Group matches by file for readability
    from itertools import groupby
    matches.sort(key=lambda x: x[0])
    for fname, group in groupby(matches, key=lambda x: x[0]):
        group = list(group)
        print(f"\n  [{len(group)} hits] {os.path.relpath(fname, BASE)}")
        for _, d, tiers in group[:3]:  # show up to 3 per file
            print(f"      tier={','.join(sorted(tiers))}")
            print(f"      {d.get('SourceImage','?')} -> {d.get('TargetImage','?')}")

    print("\n" + "=" * 72)
    print("SUMMARY — T1055 Process Injection Rule v2")
    print("=" * 72)
    print(f"EVTX files scanned          : {len(files)}")
    print(f"Sysmon Event ID 8 records   : {total_8}")
    print(f"  filtered (known-good src) : {filtered}")
    print(f"  no tier signal            : {no_signal}")
    print(f"Rule matches                : {len(matches)}")
    print(f"Files containing matches    : {len({p for p,_,_ in matches})}")

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