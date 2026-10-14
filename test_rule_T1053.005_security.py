"""
Test the T1053.005 (Security 4698) scheduled task rule.
Uses same parser structure as diagnose_4698.py.
"""
import glob, os, re
from collections import Counter
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

SUSPICIOUS_PATTERNS = [
    "powershell", "pwsh", "cmd.exe", "cmd /c", "cmd /k",
    "-enc", "-encodedcommand", "frombase64string",
    "iex", "invoke-expression", "downloadstring", "downloadfile",
    "curl ", "wget ",
    "certutil", "bitsadmin",
    "mshta", "regsvr32", "rundll32", "wscript", "cscript",
    "tasklist", "whoami", "net user", "net group", "ipconfig", "systeminfo",
    "\\appdata\\", "\\temp\\", "\\programdata\\", "\\public\\", "\\users\\",
]

WINDOWS_TASK_PREFIXES = [
    "\\microsoft\\windows\\",
    "\\microsoft\\office\\",
    "\\microsoft\\windows defender\\",
]

CMD_RE = re.compile(r"<Command[^>]*>(.*?)</Command>", re.IGNORECASE | re.DOTALL)
ARG_RE = re.compile(r"<Arguments[^>]*>(.*?)</Arguments>", re.IGNORECASE | re.DOTALL)


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


def evaluate(data):
    task_name = (data.get("TaskName") or "").lower()
    subject = (data.get("SubjectUserName") or "")
    content = (data.get("TaskContent") or "").lower()

    # Exclusions
    if task_name.startswith(tuple(WINDOWS_TASK_PREFIXES)):
        return None
    if subject.endswith("$"):
        return None

    matched = [p for p in SUSPICIOUS_PATTERNS if p.lower() in content]
    if not matched:
        return None
    return matched


def main():
    files = sorted(glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True))
    print(f"[+] Found {len(files)} EVTX files\n")

    total = 0
    matches = []

    for i, path in enumerate(files, 1):
        if i % 50 == 0:
            print(f"[..] {i}/{len(files)} | EID4698={total} matches={len(matches)}")
        try:
            with evtx.Evtx(path) as log:
                for record in log.records():
                    try:
                        eid, data = parse(record.xml().encode("utf-8", "ignore"))
                    except Exception:
                        continue
                    if eid != "4698":
                        continue
                    total += 1
                    matched = evaluate(data)
                    if matched:
                        matches.append((path, data, matched))
        except Exception:
            continue

    print("\n" + "=" * 72)
    print("MATCHES — Security 4698 Suspicious Scheduled Task")
    print("=" * 72)
    for path, data, matched in matches:
        cmd = ""
        content = data.get("TaskContent", "")
        m = CMD_RE.search(content)
        if m:
            cmd = m.group(1).strip()
        args = ""
        m = ARG_RE.search(content)
        if m:
            args = m.group(1).strip()

        print(f"\n  [MATCH] {os.path.relpath(path, BASE)}")
        print(f"          TaskName   : {data.get('TaskName','')}")
        print(f"          Created by : {data.get('SubjectUserName','')}")
        print(f"          Command    : {cmd} {args}")
        print(f"          Matched    : {', '.join(matched[:10])}")

    print("\n" + "=" * 72)
    print("SUMMARY — T1053.005 (Security 4698) Scheduled Task Rule")
    print("=" * 72)
    print(f"EVTX files scanned          : {len(files)}")
    print(f"Security 4698 records       : {total}")
    print(f"Rule matches                : {len(matches)}")
    print(f"Files containing matches    : {len({p for p,_,_ in matches})}")

    print("\nMatched files:")
    for f in sorted({p for p, _, _ in matches}):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()