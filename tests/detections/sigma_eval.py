#!/usr/bin/env python3
r"""
sigma_eval.py — a minimal, dependency-light Sigma detection evaluator (WS2.1).

Evaluates a Sigma rule's `detection:` block against a single event (a dict of
process_creation fields, e.g. {"Image": ..., "CommandLine": ...}) so detections can
be unit-tested against fixtures in CI without a live Elasticsearch.

SCOPE (audit P2-21): this is a re-implementation of Sigma matching for fast fixture
tests — it validates rule *logic*, NOT the compiled Lucene query that actually
deploys (tokenization, process.args array semantics, etc. can differ). The
Detections CI also runs the real `sigma convert` (proving every rule compiles and
targets process.args); live-fire firing against an index is not asserted here.

Supports exactly what the Suburban-SOC rule corpus uses (asserted by
test_sigma_detections.py, which fails if a rule introduces an unsupported feature):
  * field modifiers: contains, endswith, startswith, all (and bare equality)
  * string OR list values (list = OR, unless `all` -> AND)
  * multiple keys in a selection block = AND
  * a selection that is a LIST of maps = OR across those maps (#232)
  * condition over named blocks with and / or / not / parentheses
  * re: regex match (#228) - FULL-STRING match, not substring search, and
    CASE-SENSITIVE, matching how the real Elasticsearch `regexp` query
    behaves against this stack's keyword-mapped fields (confirmed empirically
    against the real Lucene backend: `field:/pattern/` requires the pattern
    to match the entire term, and keyword fields carry no analyzer to fold
    case). Do not write `^`/`$` anchors - Lucene's regexp syntax has no
    anchor operator; a literal `^` in a pattern is a character to match, not
    a metacharacter, so an anchored-looking pattern silently never matches
    real data (verified the anchor-then-realize trap firsthand while writing
    the #228 DNS rules - full-match semantics make anchors redundant, not
    optional).
  * gt/gte/lt/lte: numeric comparison (#228), for Zeek count fields
    (orig_bytes, request_body_len, trans_depth) that have no string modifier
    equivalent - Sigma has no native "value is a number" type, so the target
    is coerced to float for comparison regardless of how it's written in the
    rule YAML.
  * cidr: IP-in-network membership (#228 round 2, security-auditor), for
    internal/external address scoping (conn_external_rdp_inbound,
    conn_smb_lateral_admin) - confirmed compiling to a native Elasticsearch
    IP-range query against `ip`-typed fields, not a pipeline transformation,
    so no configs/detections/suburban-soc-ecs.yml entry is needed for it.
  * bare equality (no modifier) against a field in _TEXT_MAPPED_FIELDS
    (#229/#243) matches if the target is a WHOLE WORD anywhere in the
    value, not whole-string equality - see _TEXT_MAPPED_FIELDS' own comment
    for why this is a real backend-behavior difference (Elasticsearch
    `text` mapping vs `keyword`), not an evaluator quirk invented here.
  * Sigma's OWN wildcard/escape syntax inside values, independent of any
    modifier (live-ES verification session, 2026-08-08): `*` = any
    sequence, `?` = any single char, `\*`/`\?`/`\\` = literal *, ?, \, and
    `\` before any OTHER character passes both through literally.
    contains/endswith/startswith/bare-equality all honor this via
    _sigma_wildcard_to_regex() instead of plain Python string ops. This
    was NOT modeled before this fix and could not have caught two real,
    pre-existing rule-authoring bugs this exact gap let through silently:
    system_win_service_installed.yml's `\??\` NT-path filters had their
    leading backslash silently eaten by Sigma's own escape processing
    (`\?` consumes the backslash to produce a literal `?`, not a literal
    `\` followed by a wildcard), so those filters never matched real
    `\??\`-prefixed paths - a false positive (over-alert), not a coverage
    gap. proc_creation_win_psexec_client_side_launch.yml's `contains: '\\'`
    UNC-path check collapsed to matching any single backslash instead of
    two, making its "remote" filter an effective no-op against any local
    file path. Both found only by running the real compiled query against
    a real, running Elasticsearch and comparing results - not by reasoning
    about it, and not catchable by this evaluator before this fix.

All string matching is case-insensitive (Sigma's default) except `re`, which
is case-sensitive (see above).
"""

import ipaddress
import re
from typing import Optional

_SUPPORTED_MODS = {"contains", "endswith", "startswith", "all", "cased", "re", "gt", "gte", "lt", "lte", "cidr"}
_NUMERIC_MODS = {"gt", "gte", "lt", "lte"}

# Fields mapped `text` (analyzed, tokenized) rather than `keyword` (exact,
# unanalyzed) in configs/elasticsearch/logstash-security-template.json.
# Every field the other 100+ rules in this corpus select on is `keyword`
# (or a Sigma-native raw name later renamed to one), where bare Sigma field
# equality and real Elasticsearch's `field:value` query_string term both
# mean the SAME thing: the whole value equals the target. `message` (#229
# US7, first rule batch to select on it) is the first exception: Elastic-
# search's query_string DOES run bare (non-wildcard) terms through the
# field's analyzer at query time, so `message:invalid` matches any
# document where "invalid" is ONE OF THE TOKENS in message, not where
# message's entire value literally equals "invalid" - confirmed via a real
# `sigma convert` probe showing bare equality compiles to a plain
# query_string term (`message:su`), distinct from `contains`'s unanalyzed
# wildcard (`message:*su*`), which is unsafe here for a different reason
# (wildcard/regexp queries are NOT analyzed, so they'd need to match
# already-tokenized, already-lowercased index terms exactly - see the
# per-rule descriptions in rules/sigma/auth_linux_*.yml for the full
# reasoning). This set exists so sigma_eval.py can mirror THAT specific
# real-backend behavior for `message` without changing bare-equality
# semantics for every other (keyword-mapped) field a bare match already
# correctly treats as exact equality.
_TEXT_MAPPED_FIELDS = {"message"}


def _match_one(value: Optional[str], mods, target, field: str = "") -> bool:
    numeric_mods = _NUMERIC_MODS & set(mods)
    if numeric_mods:
        if len(numeric_mods) > 1:
            raise ValueError(f"conflicting numeric modifiers: {numeric_mods}")
        mod = numeric_mods.pop()
        if isinstance(target, list):
            raise ValueError(f"the {mod} modifier does not support list values")
        if value is None:
            return False
        try:
            v = float(value)
            t = float(target)
        except (TypeError, ValueError):
            # Zeek emits "-" for unset count fields; production ES (dynamic
            # mapping) simply doesn't match a non-numeric value against a
            # numeric range query rather than erroring - a fixture with a
            # non-numeric value should fail the same way, not abort the
            # whole test run (security-auditor, #228 round 2).
            return False
        return {"gt": v > t, "gte": v >= t, "lt": v < t, "lte": v <= t}[mod]

    if "cidr" in mods:
        # IP-in-network membership. Matches Elasticsearch's native IP-range
        # query behavior against `ip`-typed fields (source.ip/destination.ip
        # here) - confirmed via a real `sigma convert` probe, not a pipeline
        # transformation, so there is no configs/detections/suburban-soc-
        # ecs.yml entry backing this the way string field renames need one.
        if value is None:
            return False
        try:
            addr = ipaddress.ip_address(str(value))
        except ValueError:
            return False
        nets = target if isinstance(target, list) else [target]
        return any(addr in ipaddress.ip_network(str(n), strict=False) for n in nets)

    if "re" in mods:
        # Case-sensitive, full-string match - see module docstring. `target`
        # must be a plain string (Sigma's `re` modifier doesn't support list
        # values); a rule using `re|all`/`re` with a list is a rule-authoring
        # error, not something to silently OR/AND together.
        if isinstance(target, list):
            raise ValueError("the re modifier does not support list values")
        s = str(value if value is not None else "")
        return re.fullmatch(target, s) is not None

    s = str(value if value is not None else "")
    cased = "cased" in mods
    if not cased:
        s = s.lower()

    def cmp(t):
        t = str(t)
        if not cased:
            t = t.lower()
        # Sigma's OWN value syntax supports wildcards independent of any
        # modifier: `*` = any sequence, `?` = any single char, `\*`/`\?`/`\\`
        # = literal *, ?, \. A plain (unescaped) `\` before any OTHER
        # character passes both through literally - confirmed empirically
        # against the real pySigma/Lucene backend (live-ES verification
        # session, 2026-08-08): `\psexec.exe` compiles to a literal
        # `\psexec.exe`, but `\\` (one escaped pair) collapses to ONE
        # literal backslash, not two - see module docstring for the two
        # real rule bugs this gap let through silently. Plain Python string
        # ops (the old `t in s` / `.endswith` / `.startswith` / `s == t`)
        # have no awareness of this Sigma-level escaping at all.
        pattern = _sigma_wildcard_to_regex(t)
        if "contains" in mods:
            return re.search(pattern, s) is not None
        if "endswith" in mods:
            return re.search(pattern + "$", s) is not None
        if "startswith" in mods:
            return re.match(pattern, s) is not None
        if not mods and field in _TEXT_MAPPED_FIELDS:
            # Word-boundary match, not whole-string equality - see
            # _TEXT_MAPPED_FIELDS' comment for why this field is different.
            # Python's \b is defined by \w ([A-Za-z0-9_]); a target that
            # doesn't start/end on a word character makes \b anchor to the
            # WRONG side (security-auditor review: e.g. '.ssh' would compile
            # to \b\.ssh\b, whose leading \b demands a word char immediately
            # before the dot - the opposite of "standalone token"). Fail
            # loudly at test time rather than silently mismatching.
            if not re.match(r"^(\w.*\w|\w)$", t):
                raise ValueError(
                    f"text-field target {t!r} must start and end with a word "
                    f"character for \\b word-boundary matching to mean what "
                    f"it looks like it means - rephrase the target or add a "
                    f"cased/contains modifier instead")
            return re.search(rf"\b{re.escape(t)}\b", s) is not None
        return re.fullmatch(pattern, s) is not None

    if isinstance(target, list):
        return all(cmp(t) for t in target) if "all" in mods else any(cmp(t) for t in target)
    return cmp(target)


def _sigma_wildcard_to_regex(value: str) -> str:
    """Translate a Sigma value string's OWN wildcard/escape syntax into a
    Python regex fragment (unanchored - callers anchor as needed for their
    modifier). Per the Sigma spec: `*` = any sequence, `?` = any single
    char, `\\*`/`\\?`/`\\\\` = literal *, ?, \\. A `\\` before any OTHER
    character passes both through literally - confirmed empirically (see
    _match_one's cmp() comment) against the real backend, not assumed."""
    out = []
    i, n = 0, len(value)
    while i < n:
        c = value[i]
        if c == "\\" and i + 1 < n and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def _block_match(block, event: dict) -> bool:
    # Sigma allows a selection to be a LIST of maps, meaning OR across them —
    # the idiomatic way to write "Image endswith X OR OriginalFileName is X"
    # without a second named block. Added for M13 US2 (#232); before this the
    # evaluator raised AttributeError on the form, which silently pushed rule
    # authors toward contorted single-map rules instead. Each element is itself
    # a map whose keys still AND together.
    if isinstance(block, list):
        if not block:
            raise ValueError("empty list selection block")
        return any(_block_match(sub, event) for sub in block)
    if not isinstance(block, dict):
        raise ValueError(f"unsupported Sigma selection shape: {block!r}")
    for key, target in block.items():
        field, *mods = key.split("|")
        bad = [m for m in mods if m not in _SUPPORTED_MODS]
        if bad:
            raise ValueError(f"unsupported Sigma modifier(s) {bad} in '{key}'")
        if not _match_one(event.get(field), mods, target, field):
            return False
    return True


def detection_matches(detection: dict, event: dict) -> bool:
    """Return True if the Sigma `detection` block fires for `event`."""
    blocks = {k: v for k, v in detection.items() if k != "condition"}
    condition = str(detection.get("condition", "")).strip()
    results = {name: _block_match(b, event) for name, b in blocks.items()}

    # Substitute each named block with its Python bool, then safe-eval the
    # remaining and/or/not/parenthesis expression.
    expr = condition
    for name in sorted(results, key=len, reverse=True):
        expr = re.sub(rf"\b{re.escape(name)}\b", str(results[name]), expr)
    if not re.fullmatch(r"[\sA-Za-z()]+", expr or ""):
        raise ValueError(f"unsupported Sigma condition: {condition!r}")
    # Only True/False/and/or/not/() remain.
    leftover = set(re.findall(r"[A-Za-z]+", expr)) - {"True", "False", "and", "or", "not"}
    if leftover:
        raise ValueError(f"unsupported tokens in condition {condition!r}: {leftover}")
    return bool(eval(expr, {"__builtins__": {}}, {"True": True, "False": False}))
