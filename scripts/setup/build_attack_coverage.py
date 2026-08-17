#!/usr/bin/env python3
"""
build_attack_coverage.py — WS1.5: publish the ATT&CK coverage matrix (#96).

Harvests detection coverage from the SINGLE SOURCES OF TRUTH:
  * rules/sigma/*.yml         -> endpoint detections (deployed to the Elastic
                                 Detection Engine by deploy_detections.sh, WS1.2)
  * configs/logstash.conf     -> Zeek network detections (Category 5 framework
                                 enrichment, e.g. T1046 / T1110)

and emits:
  * docs/detections/attack-coverage.json  — a MITRE ATT&CK Navigator layer
    (import at https://mitre-attack.github.io/attack-navigator/)
  * docs/detections/attack-coverage.md    — rendered matrix
    (data source -> technique -> rule -> test) + gaps + next-tactic backlog.

Pure stdlib. Run from the repo root:
  python scripts/setup/build_attack_coverage.py            # (re)generate the files
  python scripts/setup/build_attack_coverage.py --check    # CI: fail on drift
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIGMA_DIR = ROOT / "rules" / "sigma"
CONF = (ROOT / "configs" / "logstash.conf").read_text(encoding="utf-8")
OUT_JSON = ROOT / "docs" / "detections" / "attack-coverage.json"
OUT_MD = ROOT / "docs" / "detections" / "attack-coverage.md"

TACTICS = {
    "reconnaissance": ("Reconnaissance", "TA0043"),
    "resource_development": ("Resource Development", "TA0042"),
    "initial_access": ("Initial Access", "TA0001"),
    "execution": ("Execution", "TA0002"),
    "persistence": ("Persistence", "TA0003"),
    "privilege_escalation": ("Privilege Escalation", "TA0004"),
    "defense_evasion": ("Defense Evasion", "TA0005"),
    "credential_access": ("Credential Access", "TA0006"),
    "discovery": ("Discovery", "TA0007"),
    "lateral_movement": ("Lateral Movement", "TA0008"),
    "collection": ("Collection", "TA0009"),
    "command_and_control": ("Command and Control", "TA0011"),
    "exfiltration": ("Exfiltration", "TA0010"),
    "impact": ("Impact", "TA0040"),
}

# Tactics with zero detections today -> explicit gaps / prioritized backlog.
BACKLOG_TACTICS = ["Collection", "Exfiltration", "Command and Control", "Lateral Movement"]

# Human-readable label per Sigma `service:` value (classic Windows Event Log
# channels that aren't identified by `category:`, issue #192).
SERVICE_LABELS = {
    "security": "Winlogbeat (Windows Security)",
    "system": "Winlogbeat (Windows System)",
    "wmi": "Winlogbeat (WMI-Activity/Operational)",
    "powershell": "Winlogbeat (PowerShell/Operational)",
}
ZEEK_SERVICE_LABELS = {
    "notice": "Zeek notice.log",
    "files": "Zeek files.log",
}
LINUX_SERVICE_LABELS = {
    "auth": "Filebeat (Linux auth.log)",
}


def logsource_label(rule_text: str) -> str:
    """Derive a human-readable data-source label from a rule's `logsource:` block.

    Previously hardcoded to "Sysmon/Winlogbeat (process_creation)" for every Sigma
    rule regardless of its actual logsource — silently mislabeling the 3 net_zeek_*
    rules too (issue #192). M13 US7 (#230/#243) found the same shape a second time:
    the 5 auth_linux_* rules (product: linux) fell through to that same Windows-
    specific fallback string with no linux branch to catch them. Falls back to
    that same string only when a rule has no machine-readable logsource at all
    (keeps old behavior for anything truly unanticipated).
    """
    m = re.search(r"^logsource:\n((?:[ \t]+\S.*\n?)+)", rule_text, re.M)
    block = m.group(1) if m else ""
    category = re.search(r"category:\s*(\S+)", block)
    product = re.search(r"product:\s*(\S+)", block)
    service = re.search(r"service:\s*(\S+)", block)
    prod = product.group(1) if product else None
    if prod == "zeek":
        if not service:
            return "Zeek"
        svc = service.group(1)
        return ZEEK_SERVICE_LABELS.get(svc, f"Zeek {svc}")
    if prod == "linux":
        if not service:
            return "Filebeat (Linux)"
        svc = service.group(1)
        return LINUX_SERVICE_LABELS.get(svc, f"Filebeat (Linux {svc})")
    if prod == "windows" and category:
        return f"Sysmon/Winlogbeat ({category.group(1)})"
    if prod == "windows" and service:
        return SERVICE_LABELS.get(service.group(1), f"Winlogbeat ({service.group(1)})")
    return "Sysmon/Winlogbeat (process_creation)"


# #281 security-auditor finding: a title containing either character would
# corrupt a downstream renderer that isn't expecting it — `|` breaks
# markdown()'s table column structure (:238-239), `;` makes
# _merged_comment()'s join ambiguous about where one rule's attribution
# ends and the next begins. No current rule title contains either (verified
# against the real corpus), so failing loudly here catches a future one at
# authoring/CI time instead of silently corrupting a generated doc.
_UNSAFE_TITLE_CHARS = ("|", ";")


def _validate_title(title, source_label):
    if any(c in title for c in _UNSAFE_TITLE_CHARS):
        raise ValueError(
            f"{source_label}: title {title!r} contains one of "
            f"{_UNSAFE_TITLE_CHARS} — would corrupt the generated markdown "
            f"table or merged Navigator comment; rename the rule/entry")
    return title


def harvest():
    rows = []  # each: technique, tactic, source, rule, test, title, status
    # --- Endpoint: Sigma rules -> Elastic Detection Engine ---
    for f in sorted(SIGMA_DIR.glob("*.yml")):
        t = f.read_text(encoding="utf-8")
        tech = re.search(r"attack\.(t\d{4}(?:\.\d{3})?)", t, re.I)
        tac = re.search(r"attack\.([a-z_]+)\s*$", t, re.M)
        title = re.search(r"^title:\s*(.+)$", t, re.M)
        status = re.search(r"^status:\s*(\S+)", t, re.M)
        if not tech:
            continue
        # #281 security-auditor finding: silently falling back to "Unknown"
        # (no TACTICS entry for the rule's own attack.<tactic> tag, or no
        # tactic tag at all) produces a dead Navigator cell — "unknown"
        # matches no real ATT&CK tactic column, so Navigator drops the
        # annotation with no error, the exact silent-drop failure class
        # #281 exists to eliminate, just via a different route (e.g. a typo
        # like attack.privilege-escalation instead of the real
        # attack.privilege_escalation). Fail loudly instead.
        if not tac or tac.group(1).lower() not in TACTICS:
            raise ValueError(
                f"rules/sigma/{f.name}: has an attack.<technique> tag but no "
                f"resolvable attack.<tactic> tag (found: "
                f"{tac.group(1) if tac else None!r}) — every rule with a "
                f"technique tag needs a matching tactic tag from TACTICS, "
                f"or it silently renders as a dead Navigator cell")
        tactic_name = TACTICS[tac.group(1).lower()][0]
        rows.append({
            "technique": tech.group(1).upper(),
            "tactic": tactic_name,
            "source": logsource_label(t),
            "rule": f"rules/sigma/{f.name}",
            "test": "Detections CI: sigma->Lucene conversion + fixture replay (tests/detections/)",
            "title": _validate_title(title.group(1).strip() if title else f.stem, f"rules/sigma/{f.name}"),
            "status": status.group(1) if status else "experimental",
        })
    # --- Network: Zeek detections classified in logstash.conf (Category 5) ---
    # Pair each [threat][technique][id] with the following [threat][tactic][name].
    net = re.findall(
        r'\[threat\]\[technique\]\[id\]"\s*=>\s*"([^"]+)".*?'
        r'\[threat\]\[technique\]\[name\]"\s*=>\s*"([^"]+)".*?'
        r'\[threat\]\[tactic\]\[name\]"\s*=>\s*"([^"]+)"',
        CONF, re.S)
    for tech, name, tactic in net:
        rows.append({
            "technique": tech, "tactic": tactic,
            "source": "Zeek (notice / ssh)",
            "rule": "configs/logstash.conf (Category 5 framework enrichment)",
            "test": "tests/pipeline/test_framework_enrichment.py",
            "title": _validate_title(name, "configs/logstash.conf"), "status": "stable",
        })
    return rows


def unique_technique_count(rows):
    """Distinct ATT&CK technique IDs across `rows` — the number #281 exists
    to report accurately, as opposed to `len(rows)` (rule-to-technique
    mapping count) or `len(navigator_layer(rows)["techniques"])`
    ((technique, tactic) pair count — one technique legitimately spanning
    two tactics, e.g. T1078.003, counts once here but twice there).
    code-reviewer finding: previously computed inline, identically, in both
    markdown() and main() — extracted so the two can't silently drift."""
    return len({r["technique"] for r in rows})


def _merged_comment(group):
    """Navigator tooltip text for a (technique, tactic) group's contributing
    rules (#281). When every rule in the group shares the same `test`
    value — the common case, e.g. every Sigma rule uses the same
    Detections-CI fixture test — states it once instead of repeating the
    identical "(test: ...)" suffix per rule (code-reviewer finding: a
    5-rule merge, T1543.003, bloated to a 949-character tooltip otherwise,
    the primary human-facing consumer of this field)."""
    tests = {r["test"] for r in group}
    titles_and_rules = "; ".join(f"{r['title']} — {r['rule']}" for r in group)
    if len(tests) == 1:
        return f"{titles_and_rules} (test: {group[0]['test']})"
    return "; ".join(f"{r['title']} — {r['rule']} (test: {r['test']})" for r in group)


def navigator_layer(rows):
    # #281: group by (techniqueID, tactic), NOT techniqueID alone. The
    # issue's own suggested fix ("group by techniqueID") would silently
    # break a genuine case already in this corpus: T1078.003 (Valid
    # Accounts: Local Accounts) legitimately appears under BOTH Initial
    # Access (auth_linux_ssh_root_login.yml — a root login IS external
    # access) and Privilege Escalation (auth_linux_su_session_opened.yml —
    # an su session IS local elevation) — two real, distinct MITRE ATT&CK
    # tactic mappings for the same sub-technique, not a duplicate. ATT&CK
    # Navigator's own layer schema supports exactly this: a techniqueID can
    # appear more than once, once per `tactic` it's scored under (each
    # entry already carries its own `tactic` field below), rendering once
    # per matrix column that tactic occupies. Deduping on techniqueID alone
    # would silently drop one of T1078.003's two legitimate tactic-column
    # entries — the EXACT "Navigator typically renders only one, the other
    # is silently dropped" failure #281 itself describes, just moved from
    # "two rules, one tactic" to "one rule set, two tactics". The real
    # invariant is uniqueness per (techniqueID, tactic) PAIR.
    # Plain dict, no separate insertion-order list: pyproject.toml pins
    # Python >=3.11, well past the 3.7 dict-insertion-order guarantee
    # (code-reviewer simplification — the earlier `order` list duplicated
    # what `grouped` already tracks for free).
    grouped = {}
    for r in rows:
        grouped.setdefault((r["technique"], r["tactic"]), []).append(r)

    techs = []
    for (tech, tactic), group in grouped.items():
        # audit P2-18: score reflects the VALIDATION TIER, not a blanket 100. Every
        # technique here is validated at the logic tier (Sigma->Lucene conversion +
        # fixture replay, or the framework-enrichment test) — but NOT yet by live-fire
        # replay against a running index, so 75 ("validated logic"), reserving 100 for
        # a future live-fire tier rather than overstating confidence.
        techs.append({
            "techniqueID": tech,
            "tactic": tactic.lower().replace(" ", "-"),
            "score": 75,
            "color": "#2ca02c",
            # #281: merge every contributing rule's comment into one entry
            # instead of emitting a second, silently-overwritten techniqueID
            # object per rule sharing this exact (technique, tactic) pair.
            # code-reviewer finding: repeating the identical "(test: ...)"
            # suffix per rule bloated a 5-rule merge (T1543.003) to a
            # 949-character tooltip — state it once when every contributing
            # rule shares the same test, which is the common case (most
            # rules in one merge group share the same Detections CI test).
            "comment": _merged_comment(group),
            "enabled": True,
        })
    return {
        "name": "Suburban-SOC Detection Coverage",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": ("Suburban-SOC ATT&CK coverage (WS1.5). Green = a detection "
                        "exists (Sigma->Elastic Detection Engine, or a Zeek network "
                        "detection). Generated by scripts/setup/build_attack_coverage.py."),
        "sorting": 3,
        "hideDisabled": False,
        "techniques": techs,
        "gradient": {"colors": ["#ffffff", "#2ca02c"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "Detection deployed", "color": "#2ca02c"}],
        "metadata": [
            # Deliberately the raw rule-to-technique mapping count, NOT
            # deduped — "detections" means how many rules/mappings
            # contributed, a different (and both legitimate) count from
            # markdown()'s deduped technique total below.
            {"name": "detections", "value": str(len(rows))},
            {"name": "source", "value": "rules/sigma/*.yml + configs/logstash.conf"},
        ],
    }


def markdown(rows):
    by_tactic = {}
    for r in rows:
        by_tactic.setdefault(r["tactic"], []).append(r)
    lines = [
        "# Suburban-SOC — ATT&CK Detection Coverage Matrix (WS1.5)",
        "",
        "> Generated by `scripts/setup/build_attack_coverage.py` from the detection "
        "sources of truth (`rules/sigma/*.yml` + `configs/logstash.conf`). "
        "Import `attack-coverage.json` at "
        "<https://mitre-attack.github.io/attack-navigator/> for the heatmap.",
        "",
        # #281: unique technique IDs, not rule-to-technique mapping rows —
        # several techniques (e.g. T1543.003) have 5 rules mapped to them,
        # which used to inflate this count by 4 each.
        f"**Coverage:** {unique_technique_count(rows)} techniques "
        f"across {len(by_tactic)} tactics.",
        "",
        "## Matrix — data source → technique → rule → test",
        "",
        "| Tactic | Technique | Detection | Data source | Rule | Test |",
        "|---|---|---|---|---|---|",
    ]
    for tactic in sorted(by_tactic):
        for r in sorted(by_tactic[tactic], key=lambda x: x["technique"]):
            lines.append(
                f"| {r['tactic']} | `{r['technique']}` | {r['title']} | "
                f"{r['source']} | `{r['rule']}` | {r['test']} |")
    covered = sorted({r["tactic"] for r in rows})
    gaps = [t for t in BACKLOG_TACTICS if t not in covered]
    lines += [
        "",
        "## Gaps & prioritized backlog",
        "",
        f"**Tactics with coverage:** {', '.join(covered)}.",
        "",
        "**Next tactics to build (prioritized, currently thin/uncovered):**",
    ]
    for t in BACKLOG_TACTICS:
        mark = "⚠️ gap" if t in gaps else "partial"
        lines.append(f"- **{t}** — {mark}.")
    lines += [
        "",
        "Notes:",
        "- Command and Control has T1105 (Ingress Tool Transfer) + the WS1.3 live-intel "
        "match path, but lacks beaconing/protocol-tunnelling detections.",
        "- Lateral Movement, Collection, and Exfiltration have no dedicated detections yet "
        "— top candidates for the next detection-engineering sprint (WS2.x).",
        "- Promotion `experimental → stable` on replayable fixtures is tracked in WS2.1.",
        "",
    ]
    return "\n".join(lines)


def main():
    rows = harvest()
    layer = json.dumps(navigator_layer(rows), indent=2) + "\n"
    md = markdown(rows)
    # #281: unique technique count for console output too, matching
    # markdown()'s own fix — same rule-mapping-vs-technique distinction.
    unique_techniques = unique_technique_count(rows)
    check = "--check" in sys.argv[1:]
    if check:
        cur_json = OUT_JSON.read_text(encoding="utf-8") if OUT_JSON.exists() else ""
        cur_md = OUT_MD.read_text(encoding="utf-8") if OUT_MD.exists() else ""
        if cur_json != layer or cur_md != md:
            print("DRIFT: attack-coverage.{json,md} are stale. Re-run "
                  "scripts/setup/build_attack_coverage.py and commit.", file=sys.stderr)
            sys.exit(1)
        print(f"OK: ATT&CK coverage matrix in sync ({unique_techniques} techniques).")
        return
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(layer, encoding="utf-8")
    OUT_MD.write_text(md, encoding="utf-8")
    print(f"Wrote {OUT_JSON.relative_to(ROOT)} and {OUT_MD.relative_to(ROOT)} "
          f"({unique_techniques} techniques).")


if __name__ == "__main__":
    main()
