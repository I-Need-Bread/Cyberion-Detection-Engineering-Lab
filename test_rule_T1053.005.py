import glob
import os
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx


SUSPICIOUS_TRIGGER = [
    "/sc onlogon",
    "/sc onstart",
    "/sc onidle",
    "/ru system",
    '/ru "nt authority\\system"',
    "/rl highest",
]

SUSPICIOUS_ACTION = [
    "powershell",
    "pwsh",
    "cmd.exe /c",
    "cmd /c",
    "http://",
    "https://",
    " -enc ",
    "iex",
    "downloadstring",
    "frombase64string",
    "mshta",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
]

SUSPICIOUS_MASQUERADE = [
    "\\microsoft\\windows\\update",
    "\\microsoft\\windows\\google",
    "\\microsoft\\windows\\microsoftedge",
    "\\microsoft\\windows\\windowsupdate",
]


def rule_matches(cmdline, image, original_filename):
    img_match = (
        (image or "").lower().endswith("\\schtasks.exe")
        or (original_filename or "").lower() == "schtasks.exe"
    )
    if not img_match:
        return False

    cl = (cmdline or "").lower()
    if "/create" not in cl:
        return False

    if any(t in cl for t in SUSPICIOUS_TRIGGER):
        return True
    if any(a in cl for a in SUSPICIOUS_ACTION):
        return True
    if any(m in cl for m in SUSPICIOUS_MASQUERADE):
        return True
    return False


def extract_events(evtx_path):
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
                if event_id != 1:
                    continue

                data = {}
                for d in root.findall(".//e:EventData/e:Data", ns):
                    name = d.attrib.get("Name")
                    if name:
                        data[name] = d.text or ""

                yield (
                    event_id,
                    data.get("Image", ""),
                    data.get("CommandLine", ""),
                    data.get("OriginalFileName", ""),
                    data.get("User", ""),
                )
    except Exception as exc:
        print("[!] Error reading " + evtx_path + ": " + str(exc))


def main():
    files = glob.glob("data/**/*.evtx", recursive=True)
    print("[+] Found " + str(len(files)) + " EVTX files\n")

    total_records = 0
    total_matches = 0
    matching_files = []

    for i, f in enumerate(files, 1):
        file_matched = False
        for eid, image, cmdline, orig, user in extract_events(f):
            total_records += 1
            if rule_matches(cmdline, image, orig):
                total_matches += 1
                file_matched = True
                print("  [MATCH] " + os.path.basename(f))
                print("          Image      : " + image)
                print("          CommandLine: " + cmdline[:200])
                print("          User       : " + user)
                print()
        if file_matched:
            matching_files.append(f)
        if i % 25 == 0:
            print("[..] " + str(i) + "/" + str(len(files)) + " files scanned | " + str(total_matches) + " matches")

    print("=" * 70)
    print("SUMMARY - T1053.005 Scheduled Task Rule")
    print("=" * 70)
    print("EVTX files scanned       : " + str(len(files)))
    print("Sysmon EventID 1 records : " + str(total_records))
    print("Rule matches             : " + str(total_matches))
    print("Files containing matches : " + str(len(matching_files)))
    print()
    print("Matched files:")
    for f in matching_files:
        print("  - " + f)


if __name__ == "__main__":
    main()