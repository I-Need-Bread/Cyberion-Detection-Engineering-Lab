"""
Diagnostic: enumerate Windows Security Event ID 4698 (Scheduled task
created) records. Print task name, creator, and the task's Command
executed from TaskContent XML.
"""
import glob, os, re
from collections import Counter
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
BASE = os.path.join("data", "EVTX-ATTACK-SAMPLES")

CMD_RE = re.compile(r"<Command[^>]*>(.*?)</Command>", re.IGNORECASE | re.DOTALL)
ARG_RE = re.compile(r"<Arguments[^>]*>(.*?)</Arguments>", re.IGNORECASE | re.DOTALL)
AUTHOR_RE = re.compile(r"<Author[^>]*>(.*?)</Author>", re.IGNORECASE | re.DOTALL)


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


def main():
    files = glob.glob(os.path.join(BASE, "**", "*.evtx"), recursive=True)
    print(f"[+] Found {len(files)} EVTX files\n")

    total = 0
    files_with = set()
    tasks = []

    for path in files:
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
                    files_with.add(path)

                    task_name = data.get("TaskName", "?")
                    subject = data.get("SubjectUserName", "?")
                    task_xml = data.get("TaskContent", "")

                    cmd = "?"
                    args = ""
                    author = "?"
                    if task_xml:
                        m = CMD_RE.search(task_xml)
                        if m:
                            cmd = m.group(1).strip()
                        m = ARG_RE.search(task_xml)
                        if m:
                            args = m.group(1).strip()
                        m = AUTHOR_RE.search(task_xml)
                        if m:
                            author = m.group(1).strip()

                    tasks.append((path, task_name, subject, author, cmd, args))
        except Exception:
            continue

    print("=" * 72)
    print("SECURITY EVENT ID 4698 — SCHEDULED TASK CREATED")
    print("=" * 72)
    print(f"Total 4698 records         : {total}")
    print(f"Files with 4698            : {len(files_with)}\n")

    for path, task_name, subject, author, cmd, args in tasks:
        print("=" * 72)
        print(f"FILE       : {os.path.relpath(path, BASE)}")
        print(f"TaskName   : {task_name}")
        print(f"Created by : {subject}")
        print(f"Author     : {author}")
        print(f"Command    : {cmd}")
        print(f"Arguments  : {args}")

    print(f"\n[+] Files with 4698 events:")
    for f in sorted(files_with):
        print(f"  - {os.path.relpath(f, BASE)}")


if __name__ == "__main__":
    main()