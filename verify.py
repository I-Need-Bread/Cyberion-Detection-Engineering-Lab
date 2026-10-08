import glob
from Evtx.Evtx import Evtx

files = glob.glob("data/**/*.evtx", recursive=True)
print(f"Found {len(files)} .evtx files")

target = files[0]
print(f"Testing: {target}")

with Evtx(target) as log:
    count = sum(1 for _ in log.records())

print(f"Records parsed: {count}")
print("OK: EVTX parses successfully")