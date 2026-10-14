"""
Test T1486 (ransomware) + T1490 (recovery inhibition) rules against the
dataset. Combined tester because the two rules together form the
ransomware detection cluster.
"""
import glob, os
from collections import Counter
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

RANSOM_EXTS = {
    ".locked", ".encrypted", ".crypto", ".crypt", ".enc",
    ".ryk", ".ryuk", ".conti", ".lockbit", ".revil", ".sodinokibi",
    ".maze", ".wcry", ".wncry", ".wncrypt", ".cerber", ".zepto",
    ".locky", ".phobos", ".djvu",
}

RANSOM_NOTE_KEYS = [
    "how_to_decrypt", "how_to_recover", "decrypt_instructions",
    "recover_files", "restore_files", "readme_for_decrypt",
    "_readme.txt", "!readme", "_help_instructions",
]

FILTER_ENCRYPT_PROC = [
    "\\cipher.exe", "\\bitlockerdeviceencryption.exe",
    "\\1password.exe", "\\veracrypt.exe", "\\axcrypt.exe",
    "\\7z.exe", "\\7zg.exe", "\\winrar.exe", "\\winzip32.exe",
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


def match_t1486(data):
    fn = (data.get("TargetFilename") or "").lower()
    img = (data.get("Image") or "").lower()
    if any(img.endswith(s) for s in FILTER_ENCRYPT_PROC):
        return None
    _, ext = os.path.splitext(fn)
    if ext in RANSOM_EXTS:
        return "A_ransom_ext"
    for kw in RANSOM_NOTE_KEYS:
        if kw in fn:
            return "B_ransom_note"
    return None


def match_t1490(data):
    img = (data.get("Image") or "").lower()
    cl = (data.get("CommandLine") or "").lower()
    if img.endswith("\\vssadmin.exe") and "delete" in cl and "shadows" in cl:
        return "A_vssadmin_delete"
    if "shadowcopy" in cl and "delete" in cl:
        return "B_wmic_shadowcopy"
    if img.endswith("\\bcdedit.exe"):
        if "recoveryenabled no" in cl or "bootstatuspolicy ignoreallfailures" in cl:
            return "C_bcdedit_recovery"
    if img.endswith("\\wbadmin.exe") and "delete" in cl:
        return "D_wbadmin_delete"
    return None


def main():
    files = sorted(glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True))
    print(f"[+] Found {len(files)} EVTX files\n")

    matches_1486 = []
    matches_1490 = []

    for i, path in enumerate(files, 1):
        if i % 50 == 0:
            print(f"[..] {i}/{len(files)} | T1486={len(matches_1486)} T1490={len(matches_1490)}")
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, provider, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if "Sysmon" not in provider:
                        continue
                    if eid == "11":
                        sig = match_t1486(data)
                        if sig:
                            matches_1486.append((path, data, sig))
                    elif eid == "1":
                        sig = match_t1490(data)
                        if sig:
                            matches_1490.append((path, data, sig))
        except Exception:
            continue

    def dump(title, matches):
        print("\n" + "=" * 72)
        print(title)
        print("=" * 72)
        for path, d, sig in matches:
            print(f"\n  [MATCH | {sig}] {os.path.relpath(path, BASE)}")
            print(f"          Image       : {d.get('Image','')}")
            print(f"          Target/CL   : {d.get('TargetFilename','') or d.get('CommandLine','')}")
            print(f"          Parent      : {d.get('ParentImage','')}")
        print(f"\n  Total: {len(matches)}")

    dump("T1486 — Ransomware File Encryption", matches_1486)
    dump("T1490 — Inhibit System Recovery", matches_1490)

    print("\n" + "=" * 72)
    print("SUMMARY — Ransomware Detection Cluster")
    print("=" * 72)
    print(f"EVTX files scanned          : {len(files)}")
    print(f"T1486 matches               : {len(matches_1486)}")
    print(f"T1490 matches               : {len(matches_1490)}")

    sig_counter_1486 = Counter(s for _, _, s in matches_1486)
    sig_counter_1490 = Counter(s for _, _, s in matches_1490)
    if sig_counter_1486:
        print("\nT1486 signals:")
        for s, c in sig_counter_1486.most_common():
            print(f"  {s:<24}: {c}")
    if sig_counter_1490:
        print("\nT1490 signals:")
        for s, c in sig_counter_1490.most_common():
            print(f"  {s:<24}: {c}")

    print("\nT1486 matched files:")
    for f in sorted({p for p, _, _ in matches_1486}):
        print(f"  - {os.path.relpath(f, BASE)}")
    print("\nT1490 matched files:")
    for f in sorted({p for p, _, _ in matches_1490}):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()