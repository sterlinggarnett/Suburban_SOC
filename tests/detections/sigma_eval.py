#!/usr/bin/env python3
"""
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

All string matching is case-insensitive (Sigma's default) except `re`, which
is case-sensitive (see above).
"""

import ipaddress
import re
from typing import Optional

_SUPPORTED_MODS = {"contains", "endswith", "startswith", "all", "cased", "re", "gt", "gte", "lt", "lte", "cidr"}
_NUMERIC_MODS = {"gt", "gte", "lt", "lte"}


def _match_one(value: Optional[str], mods, target) -> bool:
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
        if "contains" in mods:
            return t in s
        if "endswith" in mods:
            return s.endswith(t)
        if "startswith" in mods:
            return s.startswith(t)
        return s == t

    if isinstance(target, list):
        return all(cmp(t) for t in target) if "all" in mods else any(cmp(t) for t in target)
    return cmp(target)


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
        if not _match_one(event.get(field), mods, target):
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
