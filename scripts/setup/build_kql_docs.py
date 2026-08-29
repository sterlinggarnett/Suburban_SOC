#!/usr/bin/env python3
"""Generate docs/detections/SIEM_KQL_Documentation.md from the Sigma rules.

The previous doc was hand-snapshotted, went stale (covered 9 of 19 rules), and —
worst — emitted process.command_line, which this stack does NOT populate
(configs/detections/suburban-soc-ecs.yml maps to process.args). Generating the doc
from rules/sigma/*.yml through that same ECS pipeline keeps the documented queries
identical to what actually deploys (audit P1-18).

Requires the Sigma toolchain, pinned to match the Detections CI
(.github/workflows/detections.yml) and this doc's own generating versions
(#330 — an unpinned/mismatched install renders some multi-word Lucene terms
differently, e.g. `"Domain Admins"` vs `Domain\\ Admins` — semantically
identical, but enough to make --check report a false "STALE"):
    pip install sigma-cli==3.1.0 pysigma==1.5.0 pysigma-backend-elasticsearch==2.1.1

#330: this doc must also be regenerated under the SAME PYTHON VERSION CI
uses (see .python-version, currently 3.11) — confirmed by direct
reproduction that pySigma's Lucene escaping differs between Python 3.11 and
3.12 even with these exact package versions installed under both. Pinning
the packages alone is not sufficient; the interpreter matters too.

Run (from a venv on the pinned Python version above):
    python scripts/setup/build_kql_docs.py            # write the doc
    python scripts/setup/build_kql_docs.py --check    # fail if the doc is stale
"""
import glob
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RULES = sorted(glob.glob(str(ROOT / "rules" / "sigma" / "*.yml")))
PIPELINE = str(ROOT / "configs" / "detections" / "suburban-soc-ecs.yml")
OUT = ROOT / "docs" / "detections" / "SIEM_KQL_Documentation.md"


def lucene_for(rule_path: str) -> str:
    """Convert a Sigma rule to a Lucene/KQL query via the suburban-soc-ecs pipeline."""
    proc = subprocess.run(
        ["sigma", "convert", "-t", "lucene", "-p", PIPELINE, rule_path],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(f"sigma convert failed for {rule_path}:\n{proc.stderr}")
    # The CLI prints a "Parsing Sigma rules" banner first; the query is the last
    # non-empty line.
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()
             and not ln.startswith("Parsing")]
    return lines[-1].strip() if lines else ""


def render() -> str:
    out = [
        "# Suburban-SOC — SIEM Detection Queries (KQL/Lucene)",
        "",
        "> **Generated** by `scripts/setup/build_kql_docs.py` from `rules/sigma/*.yml`",
        "> through the `configs/detections/suburban-soc-ecs.yml` field pipeline. Do not",
        "> hand-edit — re-run the generator. Queries target **`process.args`** (this",
        "> stack's field), NOT the ECS-standard `process.command_line`.",
        "",
        f"**{len(RULES)} rules.** Each query is the exact Lucene the Sigma rule compiles to.",
        "",
    ]
    for path in RULES:
        with open(path, encoding="utf-8") as fh:
            rule = yaml.safe_load(fh) or {}
        title = rule.get("title", Path(path).stem)
        level = rule.get("level", "?")
        status = rule.get("status", "?")
        tags = [t.upper().replace("ATTACK.", "") for t in rule.get("tags", [])
                if str(t).lower().startswith("attack.t")]
        attack = ", ".join(tags) if tags else "—"
        out += [
            f"## {title}",
            "",
            f"- **Rule:** `{Path(path).name}` · **level:** {level} · "
            f"**status:** {status} · **ATT&CK:** {attack}",
            "",
            "```",
            lucene_for(path),
            "```",
            "",
        ]
    return "\n".join(out)


def main():
    doc = render()
    if "--check" in sys.argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current.strip() != doc.strip():
            print("SIEM_KQL_Documentation.md is STALE — re-run build_kql_docs.py", file=sys.stderr)
            sys.exit(1)
        print("SIEM_KQL_Documentation.md is up to date.")
        return
    OUT.write_text(doc, encoding="utf-8")
    print(f"Wrote {OUT} ({len(RULES)} rules).")


if __name__ == "__main__":
    main()
