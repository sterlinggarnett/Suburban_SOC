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

All matching is case-insensitive (Sigma's default).
"""

import re
from typing import Optional

_SUPPORTED_MODS = {"contains", "endswith", "startswith", "all", "cased"}


def _match_one(value: Optional[str], mods, target) -> bool:
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
