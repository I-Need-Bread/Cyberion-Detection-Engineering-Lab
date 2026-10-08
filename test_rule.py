"""
test_rule.py — Apply a Sigma-style detection rule against EVTX samples.

Week 2 deliverable for the Cyberion Detection Engineering Lab.

Usage:
    python test_rule.py

Outputs:
    - Per-file match results
    - Summary: files scanned, records examined, matches, misses
"""

import glob
import json
import os
import re
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

# ---------------------------------------------------------------------------
# Rule logic (mirrors T1059.001_powershell_suspicious.yml)
# ---------------------------------------------------------------------------

SUSPICIOUS_FLAGS = [
    " -enc ",
    " -encodedcommand ",
    " -ec ",
    " -nop ",
    " -noprofile ",
    " -w hidden ",
    " -windowstyle hidden ",
    " -ep bypass ",
    " -executionpolicy bypass ",
]

SUSPICIOUS_LOADERS = [
    "iex",
    "invoke-expression",
    "downloadstring",
    "downloadfile",
    "frombase64string",
    "invoke-webrequest",
    "net.webclient",
    "start-bitstransfer",
]

SUSPICIOUS_REMOTE = [
    "http://",
    "https://",
]


def is_powershell_image(image: str) -> bool:
    if not image:
        return False
    return image.lower().endswith("\\powershell.exe")


def rule_matches(cmdline: str, image: str, original_filename: str) -> bool:
    """Return True if the record triggers the T1059.001 rule."""
    # selection_img
    img_match = is_powershell_image(image) or (
        (original_filename or "").lower() == "powershell.exe"
    )
    if not img_match:
        return False

    cl = (cmdline or "").lower()

    # selection_flags
    if any(flag in cl for flag in SUSPICIOUS_FLAGS):
        return True
    # selection_loader
    if any(loader in cl for loader in SUSPICIOUS_LOADERS):
        return True
    # selection_remote
    if any(remote in cl for remote in SUSPICIOUS_REMOTE):
        return True

    return False


# ---------------------------------------------------------------------------
# EVTX parsing
# ---------------------------------------------------------------------------

def extract_events(evtx_path: str):
    """Yield (event_id, image, cmdline, original_filename, user) tuples."""
    try:
        with Evtx(evtx_path) as log:
            for record in log.records():
                try:
                    xml = record.xml()
                    root = ET.fromstring(xml)
                except ET.ParseError:
                    continue

                ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

                # Event ID
                eid_el = root.find(".//e:System/e:EventID", ns)
                event_id = int(eid_el.text) if eid_el is not None else -1

                if event_id != 1:
                    continue

                # Pull EventData fields
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
        print(f"[!] Error reading {evtx_path}: {exc}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    files = glob.glob("data/**/*.evtx", recursive=True)
    print(f"[+] Found {len(files)} EVTX files\n")

    total_records = 0
    total_matches = 0
    matching_files = []

    for f in files:
        file_matched = False
        for eid, image, cmdline, orig, user in extract_events(f):
            total_records += 1
            if rule_matches(cmdline, image, orig):
                total_matches += 1
                file_matched = True
                print(f"  [MATCH] {os.path.basename(f)}")
                print(f"          Image      : {image}")
                print(f"          CommandLine: {cmdline[:200]}")
                print(f"          User       : {user}")
                print()
        if file_matched:
            matching_files.append(f)

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"EVTX files scanned       : {len(files)}")
    print(f"Sysmon EventID 1 records : {total_records}")
    print(f"Rule matches             : {total_matches}")
    print(f"Files containing matches : {len(matching_files)}")
    print()
    print("Matched files:")
    for f in matching_files:
        print(f"  - {f}")


if __name__ == "__main__":
    main()