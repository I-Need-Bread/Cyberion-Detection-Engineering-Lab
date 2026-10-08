import glob
import os
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

# Suspicious access masks in canonical (no leading zeros) form
SUSPICIOUS_ACCESS = {
    "0x1010",
    "0x1410",
    "0x1438",
    "0x143a",
    "0x1439",
    "0x1f1fff",
    "0x1014c0",
    "0x12367b",
    "0x1452",
    "0x1fffff",
}

KNOWN_SOURCES = [
    "\\msmpeng.exe",
    "\\csrss.exe",
    "\\lsass.exe",
    "\\wininit.exe",
    "\\services.exe",
    "\\svchost.exe",
    "\\taskmgr.exe",
    "\\opera_autoupdate.exe",
    "\\dllhost.exe",
    "\\conhost.exe",
    "\\winlogon.exe",
]

def normalize_access(ga):
    """Normalize a granted-access hex string to canonical form (no leading zeros)."""
    if not ga:
        return ""
    g = ga.lower().strip()
    if g.startswith("0x"):
        g = g[2:]
    g = g.lstrip("0")
    if not g:
        g = "0"
    return "0x" + g

def rule_matches(source_image, target_image, granted_access):
    if not (target_image or "").lower().endswith("\\lsass.exe"):
        return False

    normalized = normalize_access(granted_access)
    if normalized not in SUSPICIOUS_ACCESS:
        return False

    si = (source_image or "").lower()
    for known in KNOWN_SOURCES:
        if si.endswith(known):
            return False

    return True

def extract_event10(evtx_path):
    try:
        with Evtx(evtx_path) as log:
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

                yield (
                    data.get("SourceImage", ""),
                    data.get("TargetImage", ""),
                    data.get("GrantedAccess", ""),
                    data.get("CallTrace", ""),
                )
    except Exception as exc:
        print("[!] Error reading " + evtx_path + ": " + str(exc))

def main():
    files = glob.glob("data/**/*.evtx", recursive=True)
    print("[+] Found " + str(len(files)) + " EVTX files\n")

    total_event10 = 0
    total_matches = 0
    matching_files = []

    for i, f in enumerate(files, 1):
        file_matched = False
        for src, tgt, ga, trace in extract_event10(f):
            total_event10 += 1
            if rule_matches(src, tgt, ga):
                total_matches += 1
                file_matched = True
                print("  [MATCH] " + os.path.basename(f))
                print("          SourceImage   : " + src)
                print("          TargetImage   : " + tgt)
                print("          GrantedAccess : " + ga + "  (normalized: " + normalize_access(ga) + ")")
                print()
        if file_matched:
            matching_files.append(f)
        if i % 25 == 0:
            print("[..] " + str(i) + "/" + str(len(files)) + " files scanned | " + str(total_matches) + " matches")

    print("=" * 70)
    print("SUMMARY - T1003.001 LSASS Memory Access Rule")
    print("=" * 70)
    print("EVTX files scanned       : " + str(len(files)))
    print("Sysmon EventID 10 records: " + str(total_event10))
    print("Rule matches             : " + str(total_matches))
    print("Files containing matches : " + str(len(matching_files)))
    print()
    print("Matched files:")
    for f in matching_files:
        print("  - " + f)

if __name__ == "__main__":
    main()