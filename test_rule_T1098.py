"""
Test the T1098 account manipulation rule against the dataset.
Windows Security Event IDs 4720, 4722, 4724, 4728, 4732, 4756.
"""
import glob, os
from collections import Counter
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

TARGET_EIDS = {"4720", "4722", "4724", "4728", "4732", "4756"}

PRIVILEGED_GROUPS = {
    "administrators", "domain admins", "enterprise admins",
    "schema admins", "account operators", "server operators",
    "backup operators", "remote desktop users",
}

SUSPICIOUS_NAME_PARTS = [
    "admin", "svc", "backup", "test", "temp", "help",
]


def parse(xml_bytes):
    root = ET.fromstring(xml_bytes)
    system = root.find(f"{NS}System")
    if system is None:
        return None, None
    eid_el = system.find(f"{NS}EventID")
    if eid_el is None:
        return None, None
    data = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for d in ed.findall(f"{NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()
    return eid_el.text.strip(), data


def signals(eid, data):
    tiers = set()
    if eid == "4720":
        tiers.add("new_account")
        name = (data.get("TargetUserName") or "").lower()
        if any(p in name for p in SUSPICIOUS_NAME_PARTS):
            tiers.add("suspicious_name")
    if eid in ("4728", "4732", "4756"):
        grp = (data.get("TargetUserName") or "").lower()
        if grp in PRIVILEGED_GROUPS:
            tiers.add("privileged_group")
    return tiers


def main():
    files = sorted(glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True))
    print(f"[+] Found {len(files)} EVTX files\n")

    total = 0
    matches = []

    for i, path in enumerate(files, 1):
        if i % 50 == 0:
            print(f"[..] {i}/{len(files)} | events={total} matches={len(matches)}")
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid not in TARGET_EIDS:
                        continue
                    total += 1
                    tiers = signals(eid, data)
                    if tiers:
                        matches.append((path, eid, data, tiers))
        except Exception:
            continue

    print("\n" + "=" * 72)
    print("MATCHES — T1098 Account Manipulation")
    print("=" * 72)
    for path, eid, data, tiers in matches:
        print(f"\n  [MATCH | EID {eid} | {','.join(sorted(tiers))}] "
              f"{os.path.relpath(path, BASE)}")
        for k in ("SubjectUserName", "TargetUserName", "MemberName",
                  "MemberSid", "SamAccountName"):
            if data.get(k):
                print(f"          {k:<18}: {data[k]}")

    print("\n" + "=" * 72)
    print("SUMMARY — T1098 Account Manipulation Rule")
    print("=" * 72)
    print(f"EVTX files scanned          : {len(files)}")
    print(f"Target Security events      : {total}")
    print(f"Rule matches                : {len(matches)}")
    print(f"Files containing matches    : {len({p for p,_,_,_ in matches})}")

    tier_counter = Counter()
    for _, _, _, tiers in matches:
        for t in tiers:
            tier_counter[t] += 1
    if tier_counter:
        print("\nMatches per signal:")
        for t, c in tier_counter.most_common():
            print(f"  {t:<24}: {c}")

    print("\nMatched files:")
    for f in sorted({p for p, _, _, _ in matches}):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()
    