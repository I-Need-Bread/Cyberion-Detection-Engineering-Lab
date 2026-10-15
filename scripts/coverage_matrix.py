"""
Generate an ATT&CK coverage matrix from all Sigma rule files in rules/.
Parses YAML for title, tags (technique IDs), logsource, level, status.
"""
import glob
import os
import yaml

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def extract_meta(doc):
    title = doc.get("title", "?")
    tags = doc.get("tags", []) or []
    logsource = doc.get("logsource", {}) or {}
    ls = f"{logsource.get('product', '?')}/{logsource.get('service', '?')}"
    level = doc.get("level", "?")
    status = doc.get("status", "?")
    techniques = [t for t in tags if t.startswith("attack.t")]
    tactics = [t for t in tags if t.startswith("attack.") and not t.startswith("attack.t")]
    return {
        "title": title,
        "techniques": techniques,
        "tactics": tactics,
        "logsource": ls,
        "level": level,
        "status": status,
    }


def normalize_tactic(t):
    """Strip 'attack.' prefix and normalize separators."""
    return t.replace("attack.", "").replace("-", "_")


def main():
    files = sorted(glob.glob(os.path.join(BASE, "rules", "*.yml")))
    print("# ATT&CK Coverage Matrix\n")
    print(f"Auto-generated from **{len(files)} rule files** in `rules/`.\n")

    print("| # | Rule | ATT&CK Techniques | Tactic | Log Source | Level | Status |")
    print("|---|------|-------------------|--------|------------|-------|--------|")

    all_techniques = set()
    all_tactics_raw = set()
    all_tactics_normalized = set()

    for i, path in enumerate(files, 1):
        with open(path, encoding="utf-8") as fh:
            docs = list(yaml.safe_load_all(fh))
        for doc in docs:
            if not doc or "title" not in doc:
                continue
            m = extract_meta(doc)
            tech = ", ".join(m["techniques"]) or "—"

            # Normalize each tactic
            normalized = [normalize_tactic(t) for t in m["tactics"]]
            tact = ", ".join(normalized) or "—"

            print(f"| {i} | {m['title']} | {tech} | {tact} | "
                  f"`{m['logsource']}` | {m['level']} | {m['status']} |")

            all_techniques.update(m["techniques"])
            all_tactics_raw.update(m["tactics"])
            all_tactics_normalized.update(normalized)

    print()
    print("## Summary\n")
    print(f"- **Total rules**: {len(files)}")
    print(f"- **Unique techniques**: {len(all_techniques)}")
    print(f"- **Unique tactics**: {len(all_tactics_normalized)}")
    print()
    print("### Techniques covered\n")
    for t in sorted(all_techniques):
        print(f"- {t}")
    print()
    print("### Tactics covered\n")
    for t in sorted(all_tactics_normalized):
        print(f"- {t}")


if __name__ == "__main__":
    main()