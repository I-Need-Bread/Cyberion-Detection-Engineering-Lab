"""
Validate all Sigma YAML files in rules/.
Exits non-zero if any file fails to parse.
"""
import yaml
import glob
import sys
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rules_dir = os.path.join(BASE, "rules")

files = sorted(glob.glob(os.path.join(rules_dir, "*.yml")))
if not files:
    print(f"[!] No Sigma rules found in {rules_dir}")
    sys.exit(1)

errors = 0
for f in files:
    try:
        with open(f, encoding="utf-8") as fh:
            docs = list(yaml.safe_load_all(fh))
        valid_docs = [d for d in docs if d and "title" in d]
        if not valid_docs:
            print(f"WARN {os.path.basename(f)} :: no document with 'title'")
            continue
        for doc in valid_docs:
            title = doc.get("title", "?")
            print(f"OK   {os.path.basename(f)} :: {title}")
    except Exception as e:
        print(f"FAIL {os.path.basename(f)} :: {e}")
        errors += 1

print()
print(f"Validated {len(files)} file(s), {errors} error(s).")
sys.exit(1 if errors else 0)