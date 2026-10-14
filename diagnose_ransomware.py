"""
Diagnostic: enumerate Sysmon Event ID 11 (FileCreate) and Event ID 23
(FileDelete) records. Look for ransomware patterns:
  - Mass file writes with new extensions
  - Ransom note filenames
  - Files in sensitive directories (Documents, Desktop, shares)
"""
import glob, os, re
from collections import Counter
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

RANSOM_NOTE_KEYWORDS = [
    "readme", "decrypt", "restore", "how_to", "recover",
    "your_files", "help_decrypt", "unlock", "ransom",
    "_readme", "!!!", ".hta",
]

RANSOM_EXTENSIONS = [
    ".locked", ".encrypted", ".crypto", ".crypt", ".locky",
    ".zepto", ".cerber", ".wncry", ".wcry", ".wcrypt",
    ".ryk", ".ryuk", ".conti", ".lockbit", ".revil",
    ".sodinokibi", ".maze", ".eGregor",
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


def main():
    files = glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True)
    print(f"[+] Found {len(files)} EVTX files\n")

    total_11 = 0
    total_23 = 0
    ext_counter = Counter()
    images_11 = Counter()
    images_23 = Counter()
    target_paths = Counter()
    ransom_notes = []
    ransom_exts = []
    files_with_11 = set()
    files_with_23 = set()

    for path in files:
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
                        total_11 += 1
                        files_with_11.add(path)
                        fn = data.get("TargetFilename", "")
                        img = data.get("Image", "")
                        if fn:
                            target_paths[fn] += 1
                            _, ext = os.path.splitext(fn)
                            ext_counter[ext.lower()] += 1
                            fname_lower = os.path.basename(fn).lower()
                            if any(kw in fname_lower for kw in RANSOM_NOTE_KEYWORDS):
                                ransom_notes.append((path, img, fn))
                            if ext.lower() in RANSOM_EXTENSIONS:
                                ransom_exts.append((path, img, fn))
                        if img:
                            images_11[img] += 1
                    elif eid == "23":
                        total_23 += 1
                        files_with_23.add(path)
                        img = data.get("Image", "")
                        if img:
                            images_23[img] += 1
        except Exception:
            continue

    print("=" * 72)
    print("RANSOMWARE DIAGNOSTIC — Sysmon EID 11 (FileCreate) + 23 (FileDelete)")
    print("=" * 72)
    print(f"Sysmon Event ID 11 records  : {total_11}")
    print(f"Sysmon Event ID 23 records  : {total_23}")
    print(f"Files with EID 11           : {len(files_with_11)}")
    print(f"Files with EID 23           : {len(files_with_23)}")

    print("\nTop 20 file extensions (EID 11):")
    for ext, c in ext_counter.most_common(20):
        print(f"  {c:>4}  {ext or '(none)'}")

    print("\nTop 15 processes creating files (EID 11):")
    for img, c in images_11.most_common(15):
        print(f"  {c:>4}  {img}")

    print("\nTop 15 processes deleting files (EID 23):")
    for img, c in images_23.most_common(15):
        print(f"  {c:>4}  {img}")

    print(f"\nRansom-note-like filenames ({len(ransom_notes)}):")
    for path, img, fn in ransom_notes[:20]:
        print(f"  {os.path.relpath(path, BASE)}")
        print(f"    Image: {img}")
        print(f"    File : {fn}")

    print(f"\nRansom-extension files ({len(ransom_exts)}):")
    for path, img, fn in ransom_exts[:20]:
        print(f"  {os.path.relpath(path, BASE)}")
        print(f"    Image: {img}")
        print(f"    File : {fn}")

    print("\nTop 20 target paths (EID 11):")
    for tp, c in target_paths.most_common(20):
        print(f"  {c:>4}  {tp}")


if __name__ == "__main__":
    main()