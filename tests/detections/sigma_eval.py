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
    optional). `all` combined with `re` raises ValueError (#386) - a single
    regex target has nothing to AND against. `.` matches a literal newline
    (Python's `re.DOTALL`) - live-verified against a real running
    Elasticsearch (#387) that Lucene's compiled `regexp` query behaves this
    way with no DOTALL-equivalent toggle needed; a newline-containing value
    (dns.answers, #292/#351, can legally carry embedded control characters)
    previously reported "does not fire" here while the real deployed query
    fired.
  * gt/gte/lt/lte: numeric comparison (#228), for Zeek count fields
    (orig_bytes, request_body_len, trans_depth) that have no string modifier
    equivalent - Sigma has no native "value is a number" type, so the target
    is coerced to float for comparison regardless of how it's written in the
    rule YAML. `all` combined with a numeric modifier raises ValueError
    (#386) - it's meaningless against the single-target comparison these
    modifiers require, not silently accepted and ignored.
  * multi-valued event fields (#351): if the event's field VALUE (not the
    Sigma rule's target) is itself a list, matched per-element with OR
    semantics - mirrors Elasticsearch's real behavior against a multi-value
    keyword field (a doc matches if ANY element matches), confirmed via
    test_live_fire.py's own note that a 1-element array and a bare scalar
    index identically (no distinct array type in Elasticsearch), so N>1
    elements is the only shape this can differ on. EXCEPT `all`: Sigma's
    `all` expands one selector into several ANDed query clauses, each
    evaluated independently per-element against the SAME multi-value field
    (a doc matches `field:*a* AND field:*b*` if either element satisfies
    *a* and a possibly DIFFERENT element satisfies *b* - not one element
    satisfying both), so `|all` against a list value is
    AND-over-targets(OR-over-elements), not a uniform per-element
    recursion (security-auditor, #351 review). A dict-shaped value raises
    TypeError rather than silently regex-matching its Python repr -
    dns.answers's real shape is a flat string array, not ECS-canonical
    dns.answers.data/type/ttl objects (configs/logstash.conf and configs/
    detections/suburban-soc-ecs.yml both call this out explicitly); if a
    future producer ever writes that object shape, failing loudly beats
    silently matching a dict's repr, the same class of bug #351 itself
    fixed for lists.
    dns.answers (Zeek's `answers`, added #292) is the first field in this
    corpus any rule selects on that is genuinely multi-valued in practice
    - every other field selected on to date (query, qtype_name, mime_type,
    orig_bytes, ...) is scalar, which is why this gap shipped silently for
    #292's own rule (its fixtures.json entry models `answers` as a scalar,
    matching every other fixture's convention, so it never exercised the
    N>1 case). process.args (Sysmon CommandLine, ECS-array-typed by
    definition) is scalar in THIS pipeline only by an unrelated
    implementation accident - configs/logstash.conf renames the whole
    CommandLine string wholesale rather than tokenizing it - not a schema
    guarantee; if that ever changes, every `contains|all`/`endswith|all`
    rule selecting on CommandLine needs the `all` semantics above, not
    the naive per-element-AND a first read of this note might suggest
    (security-auditor, #351 review).
  * cidr: IP-in-network membership (#228 round 2, security-auditor), for
    internal/external address scoping (conn_external_rdp_inbound,
    conn_smb_lateral_admin) - confirmed compiling to a native Elasticsearch
    IP-range query against `ip`-typed fields, not a pipeline transformation,
    so no configs/detections/suburban-soc-ecs.yml entry is needed for it.
    `all` combined with `cidr` raises ValueError (#386) rather than
    silently ORing across the target list the same as plain `cidr` would -
    Sigma's documented AND semantics (address in every listed network) are
    well-defined (unlike `re`+list-target, which has no defined meaning at
    all) but UNVERIFIED against a real compiled query/live Elasticsearch,
    unlike every other semantic branch in this module built under real
    confidence (each cites a live probe - see the #292/#351 postmortems
    above). Rejected rather than implemented on an unverified assumption;
    a rule needing this today should use separate selection blocks ANDed
    in the condition instead (see the error message itself).
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
# already-tokenized, already-lowercased index terms exactly). This set
# exists so sigma_eval.py can mirror THAT specific real-backend behavior
# for `message` without changing bare-equality semantics for every other
# (keyword-mapped) field a bare match already correctly treats as exact
# equality.
#
# Two consequences that follow from the above, both load-bearing for rules
# in this corpus (code-reviewer follow-up, #299 round 2 — previously stated
# only inline in individual rule descriptions, now migrated here since both
# are general properties of `text`-field analysis, not specific to any one
# rule):
#   - A rule needing multiple words to co-occur in `message` MUST use
#     several single-token bare-equality selectors ANDed together, NOT one
#     bare-equality value containing multiple words. This repo has NOT
#     verified how Elasticsearch's query_string parser treats an unquoted
#     multi-token bare-equality value (as an implicit phrase requiring
#     token order/adjacency, silently narrowing the match; or as an
#     implicit OR, silently broadening it) — that would need a real
#     cluster to confirm, which this repo doesn't have on hand. Several
#     single-token selectors sidestep the ambiguity entirely rather than
#     resting on an unverified assumption. Do not "simplify" a multi-
#     selector AND back into one multi-word bare-equality value without
#     first verifying that combining behavior against a real cluster.
#   - Two different words never collide as the same matched token after
#     analysis (e.g. 'su', 'sudo', and 'sshd' are three distinct tokens) —
#     the standard analyzer lowercases and splits on whitespace/most
#     punctuation, but does not merge or truncate distinct words into one
#     token, so a bare-equality selector for one can't accidentally also
#     match log lines only containing the others.
#
# #299: this comment is the canonical explanation of why the 4 rules that
# select on `message` (auth_linux_ssh_authorized_keys_change.yml,
# auth_linux_sudo_privilege_escalation.yml,
# auth_linux_invalid_user_ssh_attempt.yml, auth_linux_su_session_opened.yml
# — NOT auth_linux_ssh_root_login.yml, which selects on keyword-mapped ECS
# fields instead and never had this problem) use bare equality here
# instead of contains — those 4 rules used to repeat this reasoning inline
# in their own analyst-facing `description:` field. Sigma's description
# field renders VERBATIM in the Kibana Detection Engine alert flyout —
# it's runtime text an analyst reads at triage, not a code comment — so
# 15-30 lines of ES-analyzer internals were shipping straight to a 3am
# analyst who doesn't need them to act on the alert. Those rules now carry
# a short pointer back here instead; genuinely operational content (scope-
# limit disclosures, a specific rule's own verified selector-value
# behavior) stays in that rule's own description, since an analyst does
# need the former at triage time and a rule reviewer needs the latter.
_TEXT_MAPPED_FIELDS = {"message"}


def _match_one(value, mods, target, field: str = "") -> bool:
    if isinstance(value, dict):
        # #351 review (security-auditor): dns.answers is documented (this
        # module's docstring, configs/logstash.conf, configs/detections/
        # suburban-soc-ecs.yml) as a flat string array, NOT ECS-canonical
        # dns.answers.data/type/ttl objects - if a future producer ever
        # writes that shape, silently regex-matching str({...})'s repr
        # would be the exact class of bug #351 fixed, one level down. Fail
        # loudly instead.
        raise TypeError(
            f"{field!r}: object/dict-shaped event field values are not "
            f"modeled by this evaluator (got {value!r}) - this evaluator "
            f"only supports scalar and flat-list Sigma field values")
    if isinstance(value, list):
        # #351: Elasticsearch evaluates a query against a multi-value
        # keyword field per-element (OR) - a doc matches if ANY element
        # matches. Recurse per element rather than stringifying the list
        # (the old behavior: str(["a", "b"]) matched against the literal
        # repr "['a', 'b']", not either real element).
        if not value:
            # Zero elements can never match - but a malformed rule (e.g.
            # `re|all` on a list target, a numeric modifier on a list
            # target) must still fail loudly rather than silently return
            # False just because THIS event happens to carry an empty
            # array (security-auditor finding: the naive any([]) below
            # would otherwise skip every raise-ValueError shape guard
            # further down whenever value is []). Validate shape via a
            # scalar call and discard its (irrelevant) match result.
            _match_one(None, mods, target, field)
            return False
        if "all" in mods and isinstance(target, list):
            # Sigma's `all` expands one selector into several ANDed query
            # clauses. Elasticsearch evaluates each clause independently
            # against a multi-value field: a document matches
            # `field:*a* AND field:*b*` if EITHER element satisfies *a*
            # and (possibly a DIFFERENT) element satisfies *b* - it does
            # NOT require one single element to satisfy every target.
            # Security-auditor finding (#351 review): a blanket
            # any(_match_one(v, mods, target, ...) for v in value) gets
            # this backwards - it pushes `all` INSIDE the per-element
            # check (OR-over-elements(AND-over-targets): one element must
            # satisfy every target by itself), the opposite of what real
            # Elasticsearch does (AND-over-targets(OR-over-elements)).
            # Not live-exploitable today (no rule combines `contains|all`
            # with a genuinely multi-valued field in this corpus - see
            # module docstring), but wrong in exactly the code this fix
            # adds, so corrected here rather than shipped latent.
            if not target:
                # #386 (security-auditor): an empty TARGET list makes the
                # `all(...)` below vacuously True without ever recursing
                # into _match_one - for a multi-valued event field, this
                # silently bypasses every one of the cidr/numeric/re `all`
                # ValueErrors above (a malformed `field|cidr|all: []` would
                # return a match instead of failing loudly). Same shape as
                # the empty-VALUE guard just above and _block_match's own
                # "empty list selection block" rejection - a degenerate
                # rule shape, not something to match successfully via a
                # vacuous truth.
                raise ValueError(f"empty target list for {mods} on field {field!r}")
            return all(any(_match_one(v, mods, t, field) for v in value) for t in target)
        return any(_match_one(v, mods, target, field) for v in value)
    numeric_mods = _NUMERIC_MODS & set(mods)
    if numeric_mods:
        if len(numeric_mods) > 1:
            raise ValueError(f"conflicting numeric modifiers: {numeric_mods}")
        mod = numeric_mods.pop()
        if isinstance(target, list):
            raise ValueError(f"the {mod} modifier does not support list values")
        if "all" in mods:
            # #386 (security-auditor, #351 review): `all` is meaningless
            # against a single-target numeric comparison - the list-target
            # guard above already rejects a list target outright, so `all`
            # here was accepted syntactically but never validated as
            # meaningless. Fail loudly rather than silently ignore it,
            # matching this module's established convention (see the re+
            # list-target and text-field word-boundary ValueErrors above).
            raise ValueError(f"the {mod} modifier does not support the all modifier")
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
        if "all" in mods:
            # #386 (security-auditor, #351 review): the branch below always
            # ORs across a target list regardless of `all` - `field|cidr|
            # all: [net1, net2]` silently evaluated identically to
            # `field|cidr` without `all` instead of Sigma's documented AND
            # semantics (address must be in every listed network). That AND
            # semantics IS well-defined (`any` -> `all` in the return below)
            # - unlike `re`+list-target, which has no defined meaning at
            # all - but it is UNVERIFIED against a real compiled Lucene
            # query/live Elasticsearch, and every other semantic branch this
            # module implements under real confidence cites exactly that
            # kind of live probe (see module docstring). Zero live use in
            # this corpus (confirmed via corpus grep); fail loudly rather
            # than silently evaluate the wrong boolean, matching this
            # module's established convention.
            raise ValueError(
                "the cidr modifier does not support the all modifier - use "
                "separate selection blocks ANDed in the condition instead")
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
        # DOTALL (#387): live-verified against a real running Elasticsearch
        # (this stack's pinned 9.3.2) that Lucene's compiled `regexp` query
        # matches `.` against a literal newline in the field value - Python's
        # `re` module does NOT do this by default. Without DOTALL, a
        # newline-containing value (e.g. a DNS TXT answer, which can legally
        # carry embedded control characters) could report "rule does not
        # fire" here while the real deployed query fires - a CI-fidelity
        # gap, not a production evasion path (production ES always behaved
        # correctly; only this fixture-test reimplementation was wrong).
        if isinstance(target, list):
            raise ValueError("the re modifier does not support list values")
        if "all" in mods:
            # #386 (code-reviewer, live-confirmed): `all` against a single
            # regex target is meaningless (there's only one pattern to
            # satisfy) and was silently accepted and ignored, the same gap
            # class as the cidr/numeric guards above - issue #386's own
            # title names `re` alongside `cidr`.
            raise ValueError("the re modifier does not support the all modifier")
        s = str(value if value is not None else "")
        return re.fullmatch(target, s, re.DOTALL) is not None

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
        # DOTALL (#387 follow-up, code-reviewer, live-verified): Sigma's own
        # `*`/`?` wildcard syntax (see comment above) compiles to `.`/`.*`
        # here exactly like the `re` modifier's pattern does, and has the
        # identical newline-crossing gap - live-confirmed against the real
        # dev-stack Elasticsearch that a Lucene wildcard query (`msg:ab?cd`/
        # `msg:ab*cd`, the real compiled form of `contains`/`endswith`/
        # `startswith`) matches across an embedded literal newline the same
        # way the `regexp` query's `.` does. Currently latent (no rule in
        # the corpus embeds a bare `*`/`?` in a contains/endswith/startswith/
        # bare-equality target - confirmed via corpus grep), but the same
        # bug class as #387's `re`-modifier fix, in the same file.
        if "contains" in mods:
            return re.search(pattern, s, re.DOTALL) is not None
        if "endswith" in mods:
            # security-auditor finding (#428's own review, same bug class
            # as #387): bare "$" also matches immediately before a
            # trailing newline in Python re - "\Z" (true end-of-string)
            # doesn't. A value ending in a literal newline (e.g. an
            # embedded control character in a Zeek dns.answers TXT
            # record - already documented as legal in
            # tests/detections/test_live_fire.py) would report "fires"
            # here while the deployed Lucene keyword-field wildcard query
            # requires the term to literally end at the pattern, with no
            # such leniency - a CI-green/production-blind divergence.
            return re.search(pattern + r"\Z", s, re.DOTALL) is not None
        if "startswith" in mods:
            return re.match(pattern, s, re.DOTALL) is not None
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
        return re.fullmatch(pattern, s, re.DOTALL) is not None

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
