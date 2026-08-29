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

# #378 round-3 security review finding: a rule's OWN attack.<tactic> tags
# describe the tactics the rule's author considers the detection relevant
# to (often the broader kill-chain step being watched for), which is not
# the same thing as the specific attack.<technique> tag's OFFICIAL MITRE
# ATT&CK tactic membership. `_technique_tactic_pairs()`'s "broadcast a
# singleton across every other tag" cases assumed every resulting pair was
# real; an adversarial review found 8 real corpus rules where it wasn't —
# 6 carried an extra attack.<tactic> tag that didn't apply to their single
# technique (e.g. proc_creation_win_esentutl_locked_file_copy.yml tagged
# both attack.collection and attack.credential_access alongside its single
# attack.t1005 tag, but T1005 "Data from Local System" is a Collection-only
# technique per MITRE ATT&CK — it has no Credential Access tactic entry),
# and 2 were missing an attack.<tactic> tag their second technique needed
# (see `_technique_tactic_pairs()` for that shape). This table is real
# ATT&CK ground truth (verified against
# https://attack.mitre.org/techniques/<ID>/, ID slashed for sub-techniques,
# e.g. T1078.003 -> techniques/T1078/003/) for exactly the technique IDs
# that `harvest()`'s broadcast cases need to validate against today — not
# an attempt at a complete 78-technique corpus mirror, which would be
# unverified guessing for every technique not actually exercising the
# ambiguity this table exists to close.
TECHNIQUE_TACTICS = {
    "T1005": ("Collection",),
    "T1021": ("Lateral Movement",),
    "T1027": ("Defense Evasion",),
    "T1053.005": ("Execution", "Persistence", "Privilege Escalation"),
    "T1055": ("Defense Evasion", "Privilege Escalation"),
    "T1056.002": ("Collection", "Credential Access"),
    "T1059.001": ("Execution",),
    "T1059.005": ("Execution",),
    "T1059.007": ("Execution",),
    "T1068": ("Privilege Escalation",),
    "T1071.004": ("Command and Control",),
    "T1078": ("Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"),
    "T1078.002": ("Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"),
    "T1078.003": ("Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"),
    "T1098": ("Persistence", "Privilege Escalation"),
    "T1105": ("Command and Control",),
    "T1134": ("Defense Evasion", "Privilege Escalation"),
    "T1543.003": ("Persistence", "Privilege Escalation"),
    "T1546.008": ("Persistence", "Privilege Escalation"),
    "T1550.002": ("Defense Evasion", "Lateral Movement"),
    "T1569.002": ("Execution",),
    "T1574": ("Persistence", "Privilege Escalation", "Defense Evasion"),
    "T1574.002": ("Persistence", "Privilege Escalation", "Defense Evasion"),
}

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


# #425 security-auditor finding: _UNSAFE_TITLE_CHARS previously listed
# "::" as an independent literal, uncoupled from _merged_comment()'s own
# actual delimiter strings below — exactly the kind of decoupling that
# let the ORIGINAL bug (the delimiter was "—", a character several
# shipped titles legitimately contain) go unnoticed through #281, #410,
# and #426 before finally being caught. Defining the delimiters once
# here and deriving the guard from them means a future delimiter change
# can't silently stop being enforced.
_TITLE_RULE_DELIM = " :: "
_GROUP_DELIM = "; "

# #281 security-auditor finding: a title containing any of these
# characters would corrupt a downstream renderer that isn't expecting it
# — `|` breaks markdown()'s table column structure, `;` makes
# _merged_comment()'s join ambiguous about where one rule's attribution
# ends and the next begins. No current rule title contains any of these
# (verified against the real corpus), so failing loudly here catches a
# future one at authoring/CI time instead of silently corrupting a
# generated doc. The stripped _TITLE_RULE_DELIM entry guards
# _merged_comment()'s own title<->rule delimiter (#425, security-auditor
# finding): an em-dash title collided with the ORIGINAL " — " delimiter
# in a live, shipped Navigator tooltip (T1110, a 5-rule group with 2
# em-dash titles) before this fix — "—" itself can't be banned
# retroactively (7+ rule titles already ship with one), so the delimiter
# moved to a character no title uses instead, and that character is now
# enforced the same way "|"/";" already were.
_UNSAFE_TITLE_CHARS = ("|", _GROUP_DELIM.strip(), _TITLE_RULE_DELIM.strip())


def _validate_title(title, source_label):
    # security-auditor finding (#425): this corpus is unusually "::"-dense
    # in DESCRIPTIONS and detection blocks (Zeek notice names like
    # SSH::Password_Guessing, Mimikatz module syntax like sekurlsa::,
    # lsadump::), so a future TITLE hitting this ban is a realistic
    # authoring mistake, not a hypothetical — name the offending
    # character and the safe scope explicitly rather than a bare
    # "rename it" that doesn't say why.
    hit = next((c for c in _UNSAFE_TITLE_CHARS if c in title), None)
    if hit:
        raise ValueError(
            f"{source_label}: title {title!r} contains {hit!r}, which "
            f"this generator uses as a delimiter ({_UNSAFE_TITLE_CHARS} "
            f"are all reserved) — would corrupt the generated markdown "
            f"table or merged Navigator comment. This restriction is on "
            f"the rule's title only; {hit!r} is fine in its description "
            f"or detection block. Use a different character in the "
            f"title instead.")
    return title


def _technique_tactic_pairs(techs, tacs, rule_name):
    """#378: pair a rule's (possibly several) attack.<technique> tags with
    its (possibly several) attack.<tactic> tags. Sigma's `tags:` list has no
    schema for expressing "this technique goes with that tactic specifically"
    when a rule carries more than one of each — tactics and techniques are
    just two flat, separately-ordered runs in the same list (confirmed
    against the real corpus: every rule lists all its tactic tags first,
    then all its technique tags, never interleaved).

    The old `re.search()` (first-match-only) implementation silently
    discarded every secondary tag. The issue's own suggested fix — always
    emit the full (techniques x tactics) cross-product — is WRONG for at
    least one real rule in this corpus: posh_ps_obfuscated_scriptblock.yml
    tags execution+defense_evasion / t1059.001+t1027, where T1059.001
    (PowerShell) is only a real Execution technique and T1027 (Obfuscated
    Files) is only a real Defense Evasion technique per MITRE ATT&CK's own
    published mappings — a blind cross-product would assert two false
    technique-tactic pairs (T1059.001+defense_evasion, T1027+execution) on
    a published compliance/coverage artifact, the exact kind of inaccuracy
    M22 exists to eliminate, not just move.

    So: broadcast a SINGLE technique/tactic across every one of the other
    (this is exactly #281's own T1078.003 case: one technique legitimately
    scored under several tactic columns); POSITION-pair when both lists are
    the same length > 1 (the corpus convention of listing tactic tags and
    technique tags in corresponding order — verified against both rules in
    this corpus that currently have this shape: pairing tactic[i] with
    technique[i] in listed order produces only mappings that are
    independently real per MITRE ATT&CK, unlike the cross-product); and
    fail loudly rather than guess if the lists are both >1 and unequal
    length, since there is no way to infer intended pairing from the tags
    alone in that shape (not currently reachable by any rule in this corpus,
    but a future rule could hit it).

    #378 round-3 security review finding: a broadcast is only "unambiguous"
    in the sense that every OTHER tag gets paired with the singleton — it
    is not automatically ATT&CK-real (see TECHNIQUE_TACTICS' own comment
    for the real corpus example that exposed this). So every broadcast pair
    is now checked against TECHNIQUE_TACTICS before being emitted — a
    technique missing from that table raises rather than broadcasting
    unverified (closes the loophole for a future rule, the same way the
    unequal-length case already refuses to guess); the positional-zip case
    doesn't require table coverage (dropping/guessing there was never this
    function's assumption to begin with — it already trusts the corpus's
    own listed order), but still gets checked opportunistically when the
    table does cover the technique.
    """
    if len(techs) == 1 and len(tacs) == 1:
        # The common case (~89 of 108 rules): nothing to broadcast, no
        # ambiguity to verify — this IS the pair the rule's author wrote.
        return [(techs[0], tacs[0])]
    if len(techs) == 1:
        return _verify_pairs([(techs[0], tac) for tac in tacs], rule_name, require_known=True)
    if len(tacs) == 1:
        return _verify_pairs([(tech, tacs[0]) for tech in techs], rule_name, require_known=True)
    if len(techs) == len(tacs):
        return _verify_pairs(list(zip(techs, tacs)), rule_name, require_known=False)
    raise ValueError(
        f"{rule_name}: {len(techs)} attack.<technique> tags and "
        f"{len(tacs)} attack.<tactic> tags — can't infer which technique "
        f"pairs with which tactic from an unequal, both->1 tag count; "
        f"Sigma's tags: list has no way to express that pairing explicitly, "
        f"so this needs a human decision, not a guessed cross-product or "
        f"positional pairing")


def _verify_pairs(pairs, rule_name, require_known):
    """Check each (technique, tactic) pair `_technique_tactic_pairs()` is
    about to emit against TECHNIQUE_TACTICS' real ATT&CK ground truth.

    `require_known=True` (the broadcast cases) raises when the technique
    has no TECHNIQUE_TACTICS entry at all — a broadcast pairing must be
    verified, not assumed, so an uncatalogued technique blocks generation
    until a human adds it rather than silently repeating #378's original
    bug for a rule this table doesn't cover yet. `require_known=False` (the
    positional-zip case) passes an uncatalogued technique through
    unchecked, since that case never assumed table coverage to begin with;
    it still raises on a pair the table actively contradicts.
    """
    for technique, tactic in pairs:
        valid_tactics = TECHNIQUE_TACTICS.get(technique)
        if valid_tactics is None:
            if require_known:
                raise ValueError(
                    f"{rule_name}: broadcasting technique {technique} across "
                    f"tactic {tactic!r} needs verifying against MITRE ATT&CK's "
                    f"real tactic assignment for {technique}, but it has no "
                    f"entry in TECHNIQUE_TACTICS — add {technique}'s real "
                    f"tactic set there (see https://attack.mitre.org/techniques/"
                    f"{technique.replace('.', '/')}/) rather than assuming the "
                    f"broadcast is safe")
            continue
        if tactic not in valid_tactics:
            raise ValueError(
                f"{rule_name}: pairing technique {technique} with tactic "
                f"{tactic!r} is not a real MITRE ATT&CK pairing — "
                f"{technique}'s real tactics are {sorted(valid_tactics)}. "
                f"This rule's own attack.<tactic> tag describes the "
                f"detection's broader relevance, not {technique}'s official "
                f"tactic membership, so this pair must not be emitted; fix "
                f"the rule's tags instead of guessing a pairing here")
    return pairs


def harvest():
    rows = []  # each: technique, tactic, source, rule, test, title, status
    # --- Endpoint: Sigma rules -> Elastic Detection Engine ---
    for f in sorted(SIGMA_DIR.glob("*.yml")):
        t = f.read_text(encoding="utf-8")
        # #378: findall (not search) — a rule can legitimately carry more
        # than one attack.<technique> and/or attack.<tactic> tag; the old
        # first-match-only search() silently discarded every secondary tag.
        # Dedup (preserving first-seen order) so an accidental duplicate tag
        # in a rule's own tags: list doesn't produce a duplicate row.
        techs = list(dict.fromkeys(m.upper() for m in re.findall(r"attack\.(t\d{4}(?:\.\d{3})?)", t, re.I)))
        tacs_raw = list(dict.fromkeys(m.lower() for m in re.findall(r"attack\.([a-z_]+)\s*$", t, re.M)))
        title = re.search(r"^title:\s*(.+)$", t, re.M)
        status = re.search(r"^status:\s*(\S+)", t, re.M)
        if not techs:
            continue
        # #281 security-auditor finding: silently falling back to "Unknown"
        # (no TACTICS entry for the rule's own attack.<tactic> tag, or no
        # tactic tag at all) produces a dead Navigator cell — "unknown"
        # matches no real ATT&CK tactic column, so Navigator drops the
        # annotation with no error, the exact silent-drop failure class
        # #281 exists to eliminate, just via a different route (e.g. a typo
        # like attack.privilege-escalation instead of the real
        # attack.privilege_escalation). Fail loudly instead.
        # #378: validates EVERY tactic tag on the rule, not just the first —
        # the old code only ever inspected tac.group(1), so a rule with a
        # valid first tactic tag and a typo'd SECOND one shipped silently.
        unresolved = [tac for tac in tacs_raw if tac not in TACTICS]
        if not tacs_raw or unresolved:
            raise ValueError(
                f"rules/sigma/{f.name}: has an attack.<technique> tag but no "
                f"resolvable attack.<tactic> tag (found: "
                f"{tacs_raw or None!r}, unresolved: {unresolved!r}) — every "
                f"rule with a technique tag needs a matching tactic tag from "
                f"TACTICS, or it silently renders as a dead Navigator cell")
        tactic_names = [TACTICS[tac][0] for tac in tacs_raw]
        source = logsource_label(t)
        rule_label = f"rules/sigma/{f.name}"
        validated_title = _validate_title(title.group(1).strip() if title else f.stem, rule_label)
        status_value = status.group(1) if status else "experimental"
        for technique, tactic_name in _technique_tactic_pairs(techs, tactic_names, rule_label):
            rows.append({
                "technique": technique,
                "tactic": tactic_name,
                "source": source,
                "rule": rule_label,
                "test": "Detections CI: sigma->Lucene conversion + fixture replay (tests/detections/)",
                "title": validated_title,
                "status": status_value,
            })
    # --- Network: Zeek detections classified in logstash.conf (Category 5) ---
    # Pair each [threat][technique][id] with the [threat][tactic][id]/[name]
    # that follow it within the SAME add_field block.
    #
    # security-auditor finding (#430): the original pattern used `.*?`
    # between fields, unanchored to the enclosing `add_field { ... }`
    # block. Because Logstash imposes no field ordering within an
    # add_field hash, a future block could legally write its fields in a
    # different order, or a new block inserted ahead of an existing one
    # could let `.*?` skip straight past a block boundary and pair a
    # technique with the WRONG tactic (or swallow a whole block,
    # silently dropping it from coverage) - a real-but-wrong pairing
    # that would pass this function's own validation below, since both
    # halves ARE individually valid, just mis-paired. `[^}]*?` (not
    # crossing a `}`) keeps the match inside one add_field block -
    # verified against the real corpus: no `}` occurs between any two
    # fields within either of the two real blocks. Comments are stripped
    # first so a commented-out example mapping block can't be harvested
    # as live coverage (the same silent-overstatement failure mode, via
    # a different route).
    conf_code = re.sub(r"(?m)^\s*#.*$", "", CONF)
    net = re.findall(
        r'\[threat\]\[technique\]\[id\]"\s*=>\s*"([^"]+)"[^}]*?'
        r'\[threat\]\[technique\]\[name\]"\s*=>\s*"([^"]+)"[^}]*?'
        r'\[threat\]\[tactic\]\[id\]"\s*=>\s*"([^"]+)"[^}]*?'
        r'\[threat\]\[tactic\]\[name\]"\s*=>\s*"([^"]+)"',
        conf_code, re.S)
    # The Sigma path above fails loudly on an unresolvable tactic tag
    # (the #281 guard) - this path had no equivalent. A malformed
    # [threat][tactic][id]/[name] pair here (typo, wrong casing, a name
    # that doesn't match ATT&CK's exact wording, or an id/name pair that
    # individually resolve but don't actually go together) would produce
    # a Navigator-layer key matching no real tactic column, so Navigator
    # silently drops the entry — the identical dead-cell failure the
    # Sigma-path guard exists to prevent, just reachable from configs/
    # logstash.conf instead of a rule file. Validated as a (name, id)
    # PAIR against TACTICS' own values (not just the name alone) so a
    # copy-paste edit that changes one half but not the other is also
    # caught, not just a wholly-unresolvable value — this also puts
    # TACTICS' own TA-ID half back into live use instead of being dead
    # data referenced by nothing.
    valid_tactic_pairs = set(TACTICS.values())
    for tech, name, tactic_id, tactic in net:
        if (tactic, tactic_id) not in valid_tactic_pairs:
            raise ValueError(
                f"configs/logstash.conf: [threat][tactic] (id={tactic_id!r}, "
                f"name={tactic!r}) (paired with technique {tech!r} / {name!r}) "
                f"does not match any real ATT&CK tactic (id, name) pair in "
                f"TACTICS — it would silently render as a dead Navigator cell "
                f"rather than a resolvable technique-tactic pairing. Valid "
                f"pairs: {sorted(valid_tactic_pairs)}")
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", tech):
            raise ValueError(
                f"configs/logstash.conf: [threat][technique][id] {tech!r} "
                f"(paired with tactic {tactic!r}) is not a well-formed ATT&CK "
                f"technique id (T#### or T####.###) — the Sigma path already "
                f"normalizes/validates this shape; a malformed or "
                f"differently-cased id here would produce a duplicate or "
                f"unresolvable Navigator cell instead of merging with the "
                f"real technique")
        rows.append({
            "technique": tech.upper(), "tactic": tactic,
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
    the primary human-facing consumer of this field).

    Uses "::" (not "—") as the title<->rule delimiter (#425, security-
    auditor finding): an em-dash title made this boundary genuinely
    ambiguous in a live, shipped multi-rule group (T1110 — 5 rules, 2 of
    which carry an em-dash title) before this fix. "::" is enforced via
    _UNSAFE_TITLE_CHARS above so a future title can't reintroduce the
    same ambiguity.

    security-auditor finding (#425): _validate_title() only ever runs on
    `title` at harvest() time, at the two current row-construction call
    sites — this function has no way to know that happened, and `rule`/
    `test` are never validated at all. Asserted directly here instead of
    trusting the caller, so a third future ingest path (or a `rule`/
    `test` value that happens to contain a delimiter) fails loudly at
    generation time rather than silently reproducing the exact ambiguity
    this fix exists to close."""
    for r in group:
        assert _TITLE_RULE_DELIM.strip() not in r["title"] and _GROUP_DELIM.strip() not in r["title"], (
            f"{r['rule']}: title {r['title']!r} contains a comment delimiter — "
            f"should have been caught by _validate_title() at harvest() time")
        assert _TITLE_RULE_DELIM.strip() not in r["rule"] and _GROUP_DELIM.strip() not in r["rule"], (
            f"{r['rule']!r}: rule path itself contains a comment delimiter")
        assert _TITLE_RULE_DELIM.strip() not in r["test"] and _GROUP_DELIM.strip() not in r["test"], (
            f"{r['rule']}: test description {r['test']!r} contains a comment delimiter")
    tests = {r["test"] for r in group}
    titles_and_rules = _GROUP_DELIM.join(f"{r['title']}{_TITLE_RULE_DELIM}{r['rule']}" for r in group)
    if len(tests) == 1:
        return f"{titles_and_rules} (test: {group[0]['test']})"
    return _GROUP_DELIM.join(
        f"{r['title']}{_TITLE_RULE_DELIM}{r['rule']} (test: {r['test']})" for r in group)


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
            # #379: the UNIQUE technique count (unique_technique_count(rows),
            # same figure markdown()'s "Coverage: N techniques" line reports)
            # — deliberately NOT len(techs)/len(this JSON's own "techniques"
            # array), which is a (techniqueID, tactic) PAIR count (#281) and
            # over-reports by one per technique that legitimately spans more
            # than one tactic (T1078.003 today). Named "unique_techniques",
            # not "techniques", specifically so it can't be confused with
            # the top-level "techniques" array above — the exact two
            # different "technique counts" this fix exists to disambiguate
            # (code-reviewer follow-up). slo_metrics.py's metric_coverage()
            # reads this field instead of re-deriving it, so the two can't
            # silently drift apart.
            {"name": "unique_techniques", "value": str(unique_technique_count(rows))},
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
