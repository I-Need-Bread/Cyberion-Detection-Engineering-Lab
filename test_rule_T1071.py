"""
Test the T1071 Web C2 rule against the dataset.
Sysmon Event ID 3 (NetworkConnect), filtered to Provider.Name = Sysmon.
"""
import glob, os
from collections import Counter
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

SUSPICIOUS_PORTS = {
    "4444", "4445", "4443", "1337", "31337", "9299", "8888", "9999",
}

SUSPICIOUS_PROCS = [
    "\\mshta.exe", "\\regsvr32.exe", "\\certutil.exe",
    "\\wscript.exe", "\\cscript.exe", "\\rundll32.exe",
    "\\notepad.exe", "\\nc.exe", "\\plink.exe", "\\m.exe",
]

LOOPBACK_IPS = {"127.0.0.1", "::1", "0:0:0:0:0:0:0:1"}
SYSTEM_PROCS = [
    "\\svchost.exe", "\\system", "\\lsass.exe", "\\services.exe",
]


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


def signals(data):
    img = (data.get("Image") or "").lower()
    tgt = (data.get("DestinationPort") or "").strip()
    dst = (data.get("DestinationIp") or "").lower()
    init = (data.get("Initiated") or "").lower()

    if init != "true":
        return set()
    if any(img.endswith(s) for s in SYSTEM_PROCS):
        return set()
    if dst in LOOPBACK_IPS:
        return set()

    tiers = set()
    if tgt in SUSPICIOUS_PORTS:
        tiers.add("A_suspicious_port")
    if any(img.endswith(p) for p in SUSPICIOUS_PROCS):
        tiers.add("B_suspicious_process")
    return tiers


def main():
    files = sorted(glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True))
    print(f"[+] Found {len(files)} EVTX files\n")

    total_sysmon_3 = 0
    matches = []

    for i, path in enumerate(files, 1):
        if i % 50 == 0:
            print(f"[..] {i}/{len(files)} | SysmonEID3={total_sysmon_3} matches={len(matches)}")
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, provider, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid != "3" or "Sysmon" not in provider:
                        continue
                    total_sysmon_3 += 1
                    tiers = signals(data)
                    if tiers:
                        matches.append((path, data, tiers))
        except Exception:
            continue

    print("\n" + "=" * 72)
    print("MATCHES — T1071 Web C2 NetworkConnect")
    print("=" * 72)
    for path, d, tiers in matches:
        print(f"\n  [MATCH | {','.join(sorted(tiers))}] "
              f"{os.path.relpath(path, BASE)}")
        print(f"          Image       : {d.get('Image','')}")
        print(f"          Destination : {d.get('DestinationIp','')}:{d.get('DestinationPort','')}")
        print(f"          Hostname    : {d.get('DestinationHostname','')}")
        print(f"          Protocol    : {d.get('Protocol','')}")

    print("\n" + "=" * 72)
    print("SUMMARY — T1071 Web C2 Rule")
    print("=" * 72)
    print(f"EVTX files scanned          : {len(files)}")
    print(f"Sysmon Event ID 3 records   : {total_sysmon_3}")
    print(f"Rule matches                : {len(matches)}")
    print(f"Files containing matches    : {len({p for p,_,_ in matches})}")

    tier_counter = Counter()
    for _, _, tiers in matches:
        for t in tiers:
            tier_counter[t] += 1
    if tier_counter:
        print("\nMatches per signal:")
        for t, c in tier_counter.most_common():
            print(f"  {t:<24}: {c}")

    print("\nMatched files:")
    for f in sorted({p for p, _, _ in matches}):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()