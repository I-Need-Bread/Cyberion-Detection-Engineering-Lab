"""
Verify that committed conversion files match freshly compiled output.

1. Compiles all Sigma rules to a temp directory
2. Compares each file to the committed version in conversions/
3. Exits non-zero if any file differs (drift detected)

Run: python scripts/check_conversions.py
"""
import glob
import os
import subprocess
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPILED_DIR = os.path.join(BASE, "conversions")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        # Redirect compile output by temporarily moving conversions/
        # Simpler: run compile, then git diff
        result = subprocess.run(
            [sys.executable, os.path.join(BASE, "scripts", "compile_sigma.py")],
            cwd=BASE, capture_output=True, text=True,
        )
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr)
            sys.exit(1)

    # After recompiling, use git to detect drift
    diff = subprocess.run(
        ["git", "diff", "--stat", "conversions/"],
        cwd=BASE, capture_output=True, text=True,
    )
    if diff.stdout.strip():
        print("[!] Conversion drift detected:")
        print(diff.stdout)
        subprocess.run(["git", "diff", "conversions/"], cwd=BASE)
        sys.exit(1)

    print("[+] Conversions are up to date.")


if __name__ == "__main__":
    main()