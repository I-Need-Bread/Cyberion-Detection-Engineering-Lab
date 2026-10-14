"""
Compile every Sigma rule in rules/ to Splunk SPL and Elastic EQL.
Output goes to conversions/splunk/ and conversions/elastic/.

Run: python scripts/compile_sigma.py
"""
import glob
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(BASE, "rules")
OUT_SPLUNK = os.path.join(BASE, "conversions", "splunk")
OUT_ELASTIC = os.path.join(BASE, "conversions", "elastic")

os.makedirs(OUT_SPLUNK, exist_ok=True)
os.makedirs(OUT_ELASTIC, exist_ok=True)


def load_backends():
    backends = {}
    try:
        from sigma.backends.splunk import SplunkBackend
        backends["splunk"] = SplunkBackend()
    except ImportError as e:
        print(f"[!] Splunk backend unavailable: {e}")
    try:
        from sigma.backends.elasticsearch import LuceneBackend
        backends["elastic"] = LuceneBackend()
    except ImportError as e:
        print(f"[!] Elastic backend unavailable: {e}")
    return backends


def compile_rules():
    from sigma.collection import SigmaCollection

    backends = load_backends()
    if not backends:
        print("[!] No backends available")
        sys.exit(1)

    rule_files = sorted(glob.glob(os.path.join(RULES_DIR, "*.yml")))
    if not rule_files:
        print(f"[!] No Sigma rules found in {RULES_DIR}")
        sys.exit(1)

    written = 0
    for rule_path in rule_files:
        base = os.path.splitext(os.path.basename(rule_path))[0]
        try:
            collection = SigmaCollection.load_ruleset([rule_path])
        except Exception as e:
            print(f"[!] Load failed {base}: {e}")
            continue

        for idx, rule in enumerate(collection.rules):
            suffix = f"_{idx}" if idx > 0 else ""

            for backend_name, backend in backends.items():
                try:
                    queries = backend.convert_rule(rule)
                    if not queries:
                        continue
                    out_dir = OUT_SPLUNK if backend_name == "splunk" else OUT_ELASTIC
                    ext = "spl" if backend_name == "splunk" else "eql"
                    out_file = os.path.join(out_dir, f"{base}{suffix}.{ext}")
                    with open(out_file, "w", encoding="utf-8") as fh:
                        fh.write(f"# Auto-generated from {base}.yml\n")
                        fh.write(f"# Rule: {rule.title}\n\n")
                        for q in queries:
                            fh.write(q.strip() + "\n\n")
                    written += 1
                except Exception as e:
                    print(f"[!] {backend_name} failed {base}: {e}")

    print(f"[+] Wrote {written} conversion file(s)")
    print(f"    Splunk  -> {OUT_SPLUNK}")
    print(f"    Elastic -> {OUT_ELASTIC}")


if __name__ == "__main__":
    compile_rules()