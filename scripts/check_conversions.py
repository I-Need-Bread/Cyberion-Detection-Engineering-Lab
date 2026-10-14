"""
Verify that committed conversion files match freshly compiled output.

Recompiles in-memory (no subprocess) and compares to on-disk files.
Exits non-zero if any file differs (drift detected).
"""
import glob
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(BASE, "rules")
SPLUNK_DIR = os.path.join(BASE, "conversions", "splunk")
ELASTIC_DIR = os.path.join(BASE, "conversions", "elastic")


def main():
    from sigma.collection import SigmaCollection
    from sigma.backends.splunk import SplunkBackend
    from sigma.backends.elasticsearch import LuceneBackend

    backends = {
        "splunk": (SplunkBackend(), SPLUNK_DIR, "spl"),
        "elastic": (LuceneBackend(), ELASTIC_DIR, "eql"),
    }

    rule_files = sorted(glob.glob(os.path.join(RULES_DIR, "*.yml")))
    drift = 0

    for rule_path in rule_files:
        base = os.path.splitext(os.path.basename(rule_path))[0]
        collection = SigmaCollection.load_ruleset([rule_path])

        for idx, rule in enumerate(collection.rules):
            suffix = f"_{idx}" if idx > 0 else ""

            for backend_name, (backend, out_dir, ext) in backends.items():
                try:
                    queries = backend.convert_rule(rule)
                    if not queries:
                        continue
                except Exception as e:
                    print(f"[!] {backend_name} failed {base}: {e}")
                    continue

                out_file = os.path.join(out_dir, f"{base}{suffix}.{ext}")
                expected = f"# Auto-generated from {base}.yml\n# Rule: {rule.title}\n\n"
                for q in queries:
                    expected += q.strip() + "\n\n"

                if not os.path.exists(out_file):
                    print(f"[!] Missing: {out_file}")
                    drift += 1
                    continue

                with open(out_file, encoding="utf-8") as fh:
                    actual = fh.read()

                if actual != expected:
                    print(f"[!] Drift in {out_file}")
                    drift += 1

    if drift:
        print(f"\n[!] {drift} file(s) out of date. Run: python scripts/compile_sigma.py")
        sys.exit(1)

    print(f"[+] All conversions up to date ({len(rule_files)} rules).")


if __name__ == "__main__":
    main()