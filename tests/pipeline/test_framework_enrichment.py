#!/usr/bin/env python3
"""
Detection-framework consistency tests (MITRE ATT&CK + NIST CSF).

WS1.2 changed the model: endpoint detection logic is no longer inlined in
configs/logstash.conf as sigma_* regex. The Sigma rules (rules/sigma/*.yml) are the
single source of truth, deployed to the Elastic Detection Engine by
scripts/setup/deploy_detections.sh (pySigma + the suburban-soc-ecs field pipeline).

These tests therefore guard:

  * every Sigma rule is VALID detection-as-code — stable id, status, a `detection:`
    block, and an ATT&CK technique tag — so pySigma converts it to a SIEM rule with
    a MITRE threat mapping;
  * the inline sigma_* detection/enrichment has been REMOVED from logstash.conf
    (no duplicated logic in the pipeline) — the WS1.2 acceptance;
  * the pySigma pipeline maps Sigma's Sysmon fields to THIS stack's ECS fields
    (process.executable / process.args), so converted queries match real data;
  * the NETWORK detections (Zeek port scan T1046, SSH brute force T1110) remain
    classified in the pipeline with a tactic + NIST CSF function.

Pure stdlib (no pyyaml / no running stack) so it runs in any CI.

Run:  python tests/pipeline/test_framework_enrichment.py     (or: pytest tests/pipeline)
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONF = (ROOT / "configs" / "logstash.conf").read_text(encoding="utf-8")
SIGMA_DIR = ROOT / "rules" / "sigma"
THRESHOLD_DIR = ROOT / "rules" / "elastic" / "threshold"
PIPELINE = (ROOT / "configs" / "detections" / "suburban-soc-ecs.yml").read_text(encoding="utf-8")

# Network detections that must stay classified in the pipeline (non-Sigma source).
NETWORK_TECHNIQUES = {"T1046", "T1110"}

# #267: the ingest-time SOAR trigger's exact condition shape, expected to appear
# twice (filter-stage HMAC signing + output-stage http dispatch) and identically.
# T1110 only, deliberately NOT T1046 — see test_soar_trigger_excludes_spoofable_t1046.
SOAR_TRIGGER_CONDITIONS_RE = re.compile(
    r'if \(\[event\]\[dataset\] == "zeek\.intel" and \[threat\]\[indicator\]\[value\]\)'
    r' or \[threat\]\[technique\]\[id\] == "T1110" \{'
)

_TECH_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_ID_ASSIGN_RE = re.compile(r"\[threat\]\[technique\]\[id\]\"\s*=>\s*\"([^\"]+)\"")
_TACTIC_ASSIGN_RE = re.compile(r"\[threat\]\[tactic\]\[name\]\"\s*=>")
_NIST_ASSIGN_RE = re.compile(r"\[nist\]\[function\]\"\s*=>")

# #328: a `rename => { ... }` target that is a dotted string ("process.args")
# rather than Logstash bracket notation ("[process][args]") creates a FLAT
# field with a literal dot in the key, not real nesting — this file already
# documents the footgun at its network-rename block, but the Sysmon block
# had it anyway (#328) until a live splice test caught it. This shape has
# now occurred twice in this file; check every rename block, not just the
# two already found, so a third occurrence fails CI instead of needing
# another live-verification pass to notice.
_RENAME_BLOCK_RE = re.compile(r"rename\s*=>\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}", re.DOTALL)
_RENAME_PAIR_RE = re.compile(r'"([^"]+)"\s*=>\s*"([^"]+)"')

# #290 security-auditor follow-up: a stray apostrophe inside a multi-line
# `code => '...'` ruby filter block — even just in a comment — closes the
# Logstash single-quoted string literal early and breaks the WHOLE pipeline
# config at startup, not just that filter. Requires the closing quote on its
# own line, matching this file's own established multi-line-block
# convention — reliably finds the TRUE delimiter even if a stray apostrophe
# is present inside (which a naive non-greedy match-to-first-quote would not).
_RUBY_MULTILINE_CODE_RE = re.compile(r"code\s*=>\s*'\n(.*?)\n\s*'\n", re.DOTALL)

# #297: Winlogbeat's own ECS mapping types winlog.event_id as `keyword` (a
# string) — a bare integer literal never matches it in Logstash's Ruby-backed
# conditionals. Captures the compared value up to the next whitespace/paren
# rather than anchoring on a trailing "{" (security-auditor + code-reviewer,
# independently: the "{" anchor misses a bare-integer comparison folded into
# a compound condition, e.g. "== 4624 and [...] {", where the literal isn't
# immediately followed by the brace). `==`/`!=`/`in` are the only comparison
# forms Sigma/Logstash conditionals in this file use; does not cover the
# literal written on the LEFT (e.g. "4625 == [winlog][event_id]" — not used
# anywhere in this file today).
_EVENT_ID_COMPARISON_RE = re.compile(r"\[winlog\]\[event_id\]\s*(?:==|!=|in)\s*([^\s{)]+)")

# #342: isolates just the Windows Security-channel if-block, not the whole
# file — the Sysmon block immediately above it legitimately `rename`s a
# same-shaped field NAME (TargetUserName) under a DIFFERENT channel, so a
# whole-file scan for "is TargetUserName ever renamed" would conflate the
# two and false-positive on the Sysmon block's own correct behavior.
# Non-greedy up to the first 4-space-indented closing brace, matching this
# block's own indentation in configs/logstash.conf.
_SECURITY_CHANNEL_BLOCK_RE = re.compile(
    r'if \[winlog\]\[channel\] == "Security" \{(.*?)\n    \}', re.DOTALL
)
_COPY_BLOCK_RE = re.compile(r"copy\s*=>\s*\{([^{}]*)\}", re.DOTALL)
_REMOVE_FIELD_START_RE = re.compile(r"remove_field\s*=>\s*\[")
_QUOTED_STRING_RE = re.compile(r'"([^"]*)"')


def _remove_field_array_bodies(text):
    """Every `remove_field => [...]` array body in `text` (the text
    BETWEEN the brackets, quotes and commas untouched). `[^\\]]*` (a naive
    "stop at the first ]") is WRONG here: this file's own remove_field
    arrays hold bracket-notation field names that contain `]` themselves
    (e.g. ["[user_agent]", "[host][ip]"], configs/logstash.conf ~line
    449) — a first-`]`-wins capture would stop mid-array. A single regex
    that instead skips over quoted strings to find the TRUE closing `]`
    needs nested/overlapping quantifiers (`(?:\\s*"[^"]*"\\s*,?)*`) that
    CodeQL correctly flagged as a catastrophic-backtracking risk (HIGH
    severity) — that shape lets whitespace be distributed across
    repetitions in exponentially many equivalent ways on malformed input.
    A plain linear scan that tracks quote state has no such ambiguity: a
    `]` only closes the array when it is not inside a quoted string."""
    bodies = []
    for start_match in _REMOVE_FIELD_START_RE.finditer(text):
        i = start_match.end()
        body_start = i
        in_quotes = False
        while i < len(text):
            ch = text[i]
            if ch == '"':
                in_quotes = not in_quotes
            elif ch == "]" and not in_quotes:
                bodies.append(text[body_start:i])
                break
            i += 1
    return bodies

# #342 security-auditor review: 3 hand-authored native Elastic threshold
# rules (outside the pySigma pipeline, so no Sigma fixture test covers
# them) bucket/cardinality-count directly on these raw winlog.event_data.*
# field names by literal string. A `rename` in the Security-channel block
# above would silently break all of them.
SECURITY_CHANNEL_RAW_FIELDS = {
    "[winlog][event_data][IpAddress]": ("source.ip", "[source][ip]"),
    "[winlog][event_data][TargetUserName]": ("user.target.name", "[user][target][name]"),
}


def _dotted(bracket_path):
    """"[winlog][event_data][IpAddress]" -> "winlog.event_data.IpAddress"."""
    return ".".join(re.findall(r"\[([^\]]*)\]", bracket_path))


def _threshold_rule_dependents(dotted_field):
    """Rule basenames whose threshold.field or threshold.cardinality[].field
    — the actual bucket/cardinality configuration, not just prose — names
    the given raw dotted field. JSON-parsed, not a substring scan, so a
    rule that only MENTIONS the field in its description (but doesn't
    actually bucket on it) is correctly excluded."""
    dependents = []
    for path in sorted(THRESHOLD_DIR.glob("*.ndjson")):
        # One JSON object per non-blank line, not one object per file — an
        # Elastic UI export can append a trailing summary line, and a
        # single-object file (every current one) is just the N=1 case of
        # this same shape. Lines without a "threshold" key (e.g. such a
        # summary line) are skipped rather than treated as a parse error.
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rule = json.loads(line)
            if "threshold" not in rule:
                continue
            threshold = rule["threshold"]
            field = threshold.get("field", [])
            configured_fields = field if isinstance(field, list) else [field]
            configured_fields += [c.get("field") for c in threshold.get("cardinality", [])]
            if dotted_field in configured_fields:
                dependents.append(path.name)
    return dependents


def rule_technique(text: str):
    m = _TECH_RE.search(text)
    return m.group(1).upper() if m else None


class DetectionAsCodeTests(unittest.TestCase):
    def setUp(self):
        self.rules = sorted(SIGMA_DIR.glob("*.yml"))
        self.mapped_ids = set(_ID_ASSIGN_RE.findall(CONF))

    def test_sigma_rules_present(self):
        self.assertGreaterEqual(len(self.rules), 10,
                                f"expected >=10 Sigma rules, found {len(self.rules)}")

    def test_every_rule_is_valid_detection_as_code(self):
        # Each rule must carry the fields pySigma + the Detection Engine need: a
        # stable id (-> rule_id, idempotent import), a status, a detection block,
        # and an ATT&CK technique tag (-> the rule's MITRE threat mapping).
        problems = []
        for rule in self.rules:
            t = rule.read_text(encoding="utf-8")
            if not re.search(r"^id:\s*\S+", t, re.MULTILINE):
                problems.append(f"{rule.name}: missing `id`")
            if not re.search(r"^status:\s*\S+", t, re.MULTILINE):
                problems.append(f"{rule.name}: missing `status`")
            if "detection:" not in t or "condition:" not in t:
                problems.append(f"{rule.name}: missing detection/condition")
            if rule_technique(t) is None:
                problems.append(f"{rule.name}: no attack.tXXXX tag")
        self.assertEqual([], problems, f"invalid Sigma rules: {problems}")

    def test_inline_sigma_detection_removed(self):
        # WS1.2 acceptance: detection logic lives in the rules, not the pipeline.
        # No sigma_* tags or conditionals may remain in logstash.conf.
        self.assertNotIn("sigma_", CONF,
                         "inline sigma_* detection/enrichment still present in logstash.conf")

    def test_pipeline_maps_sysmon_to_our_ecs(self):
        # Conversion must target THIS stack's fields (process.args, NOT the
        # ECS-standard process.command_line) or the rules never match real data.
        self.assertRegex(PIPELINE, r"Image:\s*process\.executable")
        self.assertRegex(PIPELINE, r"CommandLine:\s*process\.args")

    def test_sysmon_hashes_extracts_sha256_not_the_raw_prefixed_string(self):
        # #339: the Hashes rename (#328) only fixed the NESTING - without
        # this grok, file.hash.sha256 holds Sysmon's raw algorithm-prefixed
        # string ("SHA256=<hex>", or a composite "SHA1=...,MD5=...,
        # SHA256=...,IMPHASH=..." string), which no IOC hunt on a bare
        # hash value could ever match. A custom tag_on_failure (not the
        # default _grokparsefailure) keeps a Hashes value with no SHA256
        # component - a normal condition, not a pipeline error - out of
        # the #169/NIST SC-24 parse-error-rate SLO.
        block_start = CONF.index('"[winlog][event_data][Hashes]"            => "[file][hash][sha256]"')
        following = CONF[block_start:block_start + 3000]
        self.assertIn('match => { "[file][hash][sha256]" => "SHA256=', following,
                       "Sysmon Hashes rename has no SHA256-extraction grok following it")
        self.assertIn('overwrite => ["[file][hash][sha256]"]', following,
                       "grok must overwrite the raw prefixed string with the extracted hash")
        self.assertIn('tag_on_failure => ["_sysmon_hash_no_sha256"]', following,
                       "grok must use a custom failure tag, not the default "
                       "_grokparsefailure (would pollute the parse-error-rate SLO "
                       "with a normal, expected condition)")
        self.assertIn('remove_field => ["[file][hash][sha256]"]', following,
                       "a Hashes value with no SHA256 component must clear the "
                       "field, not leave the raw prefixed string mislabeled as "
                       "a parsed hash")

    def test_network_detections_still_mapped(self):
        for tech in NETWORK_TECHNIQUES:
            self.assertIn(tech, self.mapped_ids,
                          f"network technique {tech} not mapped in logstash.conf")

    def test_network_mappings_have_tactic_and_nist(self):
        # Every remaining technique assignment (network) must carry a tactic name
        # and a NIST CSF function so dashboards never aggregate half-classified events.
        n_ids = len(_ID_ASSIGN_RE.findall(CONF))
        n_tactic = len(_TACTIC_ASSIGN_RE.findall(CONF))
        n_nist = len(_NIST_ASSIGN_RE.findall(CONF))
        self.assertEqual(n_ids, n_tactic, f"{n_ids} technique ids but {n_tactic} tactic names")
        self.assertEqual(n_ids, n_nist, f"{n_ids} technique ids but {n_nist} nist functions")

    def test_t1110_is_notice_based_not_per_event(self):
        # #261: T1110 must key on the aggregated SSH::Password_Guessing/
        # Login_By_Password_Guesser notice.log entry (mirroring T1046's own
        # Scan::Port_Scan match), not on every individual auth_success=false
        # connection event — an unauthenticated actor could otherwise inflate
        # raw_alert_volume's zeek_notices count at will with a failed-login burst.
        # Only the conditional itself is checked, from its `if` through to the
        # mapping block (not surrounding prose comments, which are free to
        # mention the old field by name) — spans multi-line conditionals too,
        # unlike a single-line `startswith("if ")` scan, which a reflow
        # (e.g. wrapping onto a second line) would silently defeat.
        block_start = CONF.index('"[threat][technique][id]"   => "T1110"')
        preceding = CONF[max(0, block_start - 400):block_start]
        self.assertIn("if ", preceding, "no `if` conditional found ahead of the T1110 mapping")
        condition = preceding[preceding.rindex("if "):]
        self.assertNotIn("auth_success", condition,
                         "T1110 branch regressed to per-event auth_success matching")
        self.assertIn("SSH::Password_Guessing", condition,
                      "T1110 branch no longer matches the aggregated Zeek notice")
        self.assertIn("SSH::Login_By_Password_Guesser", condition,
                      "T1110 branch dropped the Login_By_Password_Guesser notice type")

    def test_soar_trigger_covers_t1110_not_t1046(self):
        # #267: the live SOAR trigger (the ingest-time replacement for the
        # now-retired rules/elastic_watcher/retired/soar_quarantine_alert.json
        # Watcher) previously only fired on zeek.intel IOC hits — T1046/T1110
        # Zeek detections were tagged for dashboards but never reached
        # automated response. T1110 was wired in directly: it requires a
        # completed TCP+SSH handshake (detect-bruteforcing.zeek's SumStats
        # over real ssh_auth_failed events), not spoofable by a bare
        # source-IP forger. T1046 was deliberately left OUT of live dispatch
        # (security-auditor review): scan-detection.zeek fired on the
        # initial SYN alone, no handshake required, so wiring it in would
        # have turned a spoofed-source SYN sweep into an unrate-limited
        # automated-response amplifier against an attacker-chosen victim IP
        # — this repo has no rate limiting anywhere in the /alert path.
        # #331 investigated two sensor-side fixes for the metric-gaming
        # concern and rejected both after live security review: gating on
        # connection_established/connection_rejected doesn't defend against
        # spoofing at all at this deployment's capture vantage point
        # (zeek-host-capture.service captures at the monitored host's OWN
        # interface, so that host's real reply to a spoofed SYN is exactly
        # as visible to Zeek as a reply to a genuine one), and a global
        # per-hour notice-volume cap introduced a cheap, silent denial-of-
        # detection primitive instead. scan-detection.zeek is UNCHANGED by
        # #331 as a result - the actual fix is a distinct-source
        # cardinality dimension on slo_metrics.py's raw_alert_volume
        # metric, not anything at the sensor. T1046 STILL isn't wired into
        # live dispatch, for the same original reason as before #331: no
        # source-authenticity signal exists for this notice, and this repo
        # still has no rate limiting anywhere in the /alert path either.
        # T1046 still gets pipeline-tagged for dashboards, unaffected.
        matches = SOAR_TRIGGER_CONDITIONS_RE.findall(CONF)
        self.assertTrue(matches, "T1110 SOAR trigger condition not found in configs/logstash.conf")
        self.assertNotIn('[threat][technique][id] in ["T1046"', CONF,
                         "T1046 must not be wired into live SOAR dispatch - #331 found no "
                         "sensor-side fix that makes Scan::Port_Scan spoof-proof, and /alert "
                         "still has no rate limiting")
        self.assertNotIn('[threat][technique][id] in ["T1046", "T1110"]', CONF,
                         "T1046 must not be wired into live SOAR dispatch - #331 found no "
                         "sensor-side fix that makes Scan::Port_Scan spoof-proof, and /alert "
                         "still has no rate limiting")

    def test_soar_trigger_signing_and_dispatch_conditions_match(self):
        # #267: the filter-stage HMAC-signing block and the output-stage http
        # dispatch block each gate on their own copy of the same condition —
        # Logstash has no way to share one across filter{}/output{}. A
        # signed-but-never-dispatched event is a silent no-op (the exact
        # failure mode #267 found for T1110), so these two must never be
        # allowed to drift apart again.
        matches = SOAR_TRIGGER_CONDITIONS_RE.findall(CONF)
        self.assertEqual(2, len(matches),
                         f"expected exactly 2 SOAR trigger conditions (signing + dispatch), found {len(matches)}")
        self.assertEqual(matches[0], matches[1],
                         "SOAR signing and dispatch trigger conditions have desynced")

    def test_zeek_notice_src_fallback_for_source_ip(self):
        # #267: some zeek.notice types (e.g. detect-bruteforcing's
        # Password_Guessing) set Zeek's Notice::Info$src without $conn, so
        # notice.log carries a bare top-level src field but no id sub-record
        # — the generic id.orig_h rename never fires for them, leaving
        # source.ip empty and any SOAR dispatch targeting nothing. Guard
        # both that the fallback exists and that it never overwrites a
        # value the generic rename already set (the ![source][ip] guard).
        self.assertIn('"[src]" => "[source][ip]"', CONF,
                      "zeek.notice src -> source.ip fallback rename is missing")
        idx = CONF.index('"[src]" => "[source][ip]"')
        preceding = CONF[max(0, idx - 300):idx]
        self.assertIn('== "zeek.notice"', preceding)
        self.assertIn("![source][ip]", preceding,
                      "src fallback must not unconditionally overwrite an already-set source.ip")

    def test_no_rename_block_uses_a_dotted_string_target(self):
        # #328: a rename target must be Logstash bracket notation
        # ("[process][args]"), never a bare dotted string ("process.args") —
        # the latter creates a FLAT field with a literal dot in the key, not
        # real nesting, silently breaking any later filter that reads the
        # bracket path. Found live in the Sysmon block despite this file
        # already documenting the footgun at its network-rename block —
        # check every rename block in the file, not just those two, so a
        # third occurrence fails CI instead of needing another live splice
        # test to notice.
        #
        # security-auditor review: a bare dotted string is not the only bad
        # shape. A dot INSIDE one bracket pair ("[process.args]") is the
        # identical bug — Logstash treats everything inside a single [ ]
        # pair as one literal field name, dot included, so this also
        # creates a flat "process.args" field, not nested [process][args].
        # This file already uses that exact single-bracket-with-a-dot form
        # deliberately elsewhere, but only as a rename SOURCE (e.g.
        # "[id.orig_h]", referencing a real flat field Zeek emits) - never
        # as a target. A future edit mirroring that existing source-side
        # idiom onto a rename's target side would reintroduce #328 with a
        # green build unless this checks both shapes.
        blocks = _RENAME_BLOCK_RE.findall(CONF)
        self.assertGreaterEqual(len(blocks), 2,
                                "expected to find multiple rename blocks in configs/logstash.conf")
        bad = []
        for block in blocks:
            for source, target in _RENAME_PAIR_RE.findall(block):
                bracket_segments = re.findall(r"\[([^\]]*)\]", target)
                bare_dotted = not target.startswith("[") and "." in target
                dotted_inside_brackets = any("." in seg for seg in bracket_segments)
                if bare_dotted or dotted_inside_brackets:
                    bad.append((source, target))
        self.assertEqual([], bad,
                         f"dotted (non-bracket) rename targets create flat fields, not nested: {bad}")

    def test_no_apostrophe_inside_a_ruby_single_quoted_code_block(self):
        # #290 security-auditor follow-up: hit this live while adding that
        # fix's byte-clamp comment — an apostrophe in "#263's Lucene..."
        # inside a `code => '...'` block closed the Logstash string literal
        # early, breaking the ENTIRE pipeline config at startup
        # (LogStash::ConfigurationError), not just that one filter. Even a
        # comment-only apostrophe does this; Logstash does not know or care
        # that the text is a comment once it is inside its own string
        # literal. Turns that hard-won lesson into a CI gate instead of
        # relying on every future editor remembering it by hand.
        blocks = _RUBY_MULTILINE_CODE_RE.findall(CONF)
        self.assertGreaterEqual(len(blocks), 2,
                                "expected to find multiple multi-line ruby code => '...' blocks "
                                "in configs/logstash.conf")
        bad = [i for i, block in enumerate(blocks) if "'" in block]
        self.assertEqual([], bad,
                         f"multi-line ruby code block(s) at index {bad} contain a single-quote/"
                         f"apostrophe character (comments included) — this closes the Logstash "
                         f"string literal early and breaks the whole pipeline config at startup")

    def test_windows_security_event_id_compared_as_string(self):
        # #297: [winlog][event_id] == 4625 (bare integer) never matches the
        # real string-typed field Winlogbeat sends — live-confirmed against
        # the real logstash:9.3.2 binary that the pre-fix comparison left
        # [event][outcome] unset for both the 4625 (failure) and 4624
        # (success) login-tracking branches. Pins the exact expected set (not
        # just "quoted") so a typo'd event id can't silently pass by
        # coincidentally still looking like a quoted string.
        comparisons = _EVENT_ID_COMPARISON_RE.findall(CONF)
        self.assertEqual({'"4624"', '"4625"'}, set(comparisons),
                         f"expected exactly the 4624/4625 [winlog][event_id] comparisons "
                         f"(quoted), found {comparisons}")
        bad = [v for v in comparisons
               if not ((v.startswith('"') and v.endswith('"'))
                       or (v.startswith("'") and v.endswith("'")))]
        self.assertEqual([], bad,
                         f"[winlog][event_id] compared against a bare (non-string) literal: {bad} — "
                         f"Winlogbeat emits event_id as keyword/string, so this comparison silently "
                         f"never matches in Logstash's Ruby-backed conditional evaluation")

    def test_windows_security_event_id_maps_to_correct_outcome(self):
        # security-auditor review: the quoting check above proves SHAPE, not
        # CORRECTNESS — a transposed mapping (4625->success, 4624->failure)
        # or a swap with a third event id would still pass it, and would be
        # worse than #297's original bug: an actively INVERTED outcome
        # (every real logon failure stamped "success") is more misleading
        # than an absent field. Pin the actual id->outcome mapping, and that
        # each comparison sits inside the Security-channel gate.
        for event_id, outcome in (('"4625"', "failure"), ('"4624"', "success")):
            idx = CONF.index(f"[winlog][event_id] == {event_id}")
            preceding = CONF[max(0, idx - 700):idx]
            self.assertIn('[winlog][channel] == "Security"', preceding,
                          f"{event_id} comparison is not inside the Security channel gate")
            following = CONF[idx:idx + 200]
            self.assertIn(f'"[event][outcome]" => "{outcome}"', following,
                          f"{event_id} does not map to [event][outcome] = {outcome!r}")

    def test_security_channel_threshold_dependents_actually_exist(self):
        # #342: sanity check on this test class's own premise. If these
        # threshold rules are ever rewritten to bucket on something else,
        # the copy-not-rename requirement below no longer has teeth for
        # that field — better to fail loudly here than silently test
        # nothing.
        for raw_bracket in SECURITY_CHANNEL_RAW_FIELDS:
            raw_dotted = _dotted(raw_bracket)
            dependents = _threshold_rule_dependents(raw_dotted)
            self.assertGreater(
                len(dependents), 0,
                f"expected at least one rules/elastic/threshold/*.ndjson rule's "
                f"threshold.field/cardinality to configure {raw_dotted!r} — if none do "
                f"anymore, the copy-not-rename requirement for {raw_bracket} may be "
                f"stale; verify and update"
            )

    def test_security_channel_copies_not_renames_or_removes_raw_fields(self):
        # #342: winlog.event_data.IpAddress/TargetUserName are never
        # ECS-renamed by this channel (documented in configs/detections/
        # suburban-soc-ecs.yml's field-mapping-windows-security transform,
        # confirmed by test_ecs_yml_still_documents_the_raw_shape below) —
        # every deployed Security-channel Sigma rule AND the 3 threshold
        # rules confirmed by the test above query the RAW field by name.
        # A `rename` (which REMOVES the source) or `remove_field` on
        # either raw field would silently break all of them; this repo has
        # hit the "silent break, nothing catches it" shape of bug multiple
        # times (#217, #233) so it's checked directly rather than trusted.
        match = _SECURITY_CHANNEL_BLOCK_RE.search(CONF)
        self.assertIsNotNone(match, 'could not find the Security-channel if-block in configs/logstash.conf')
        block = match.group(1)

        rename_pairs = [
            pair for rename_body in _RENAME_BLOCK_RE.findall(block)
            for pair in _RENAME_PAIR_RE.findall(rename_body)
        ]
        removed_fields = [
            f for remove_body in _remove_field_array_bodies(block)
            for f in _QUOTED_STRING_RE.findall(remove_body)
        ]
        copy_pairs = [
            pair for copy_body in _COPY_BLOCK_RE.findall(block)
            for pair in _RENAME_PAIR_RE.findall(copy_body)
        ]

        for raw_bracket, (_ecs_dotted, expected_ecs_bracket) in SECURITY_CHANNEL_RAW_FIELDS.items():
            renamed_away = [p for p in rename_pairs if p[0] == raw_bracket]
            self.assertEqual(
                [], renamed_away,
                f"{raw_bracket} must not be `rename`d in the Security-channel block — "
                f"that REMOVES the raw field, which "
                f"{_threshold_rule_dependents(_dotted(raw_bracket))} depend on directly. "
                f"Use mutate `copy` instead: {renamed_away}"
            )
            self.assertNotIn(
                raw_bracket, removed_fields,
                f"{raw_bracket} must not be `remove_field`d in the Security-channel block "
                f"— same reason a `rename` is disallowed above"
            )
            self.assertIn(
                (raw_bracket, expected_ecs_bracket), copy_pairs,
                f"expected a `copy` from {raw_bracket} to {expected_ecs_bracket} in the "
                f"Security-channel block — #342 enrichment missing, reverted, or pointed "
                f"at the wrong target (found copy pairs: {copy_pairs})"
            )

    def test_security_channel_ip_copy_gated_and_geoip_handles_v4_mapped_v6(self):
        # #342 security-auditor follow-up: two guards were added after
        # live-fire testing found real gaps, neither of which the copy-
        # direction test above exercises. Pins both as literal-string
        # checks (same style as test_mac_correlation.py's guard-predicate
        # pin) so a future "simplify this" edit can't silently drop either
        # one with CI still green — this repo has no other test coverage
        # for these two guards at all.
        match = _SECURITY_CHANNEL_BLOCK_RE.search(CONF)
        self.assertIsNotNone(match, 'could not find the Security-channel if-block in configs/logstash.conf')
        block = match.group(1)

        # Gap 1: "0.0.0.0"/"::" are BOTH valid values for the ES `ip` field
        # type (unlike "-"), so an ungated copy would silently populate
        # source.ip with a legitimate-looking but meaningless bucket value
        # instead of failing loudly — live-confirmed via a real
        # logstash:9.3.2 container that source.ip stays unset for both.
        self.assertIn(
            'not in ["-", "0.0.0.0", "::", ""]', block,
            "the IpAddress copy's sentinel guard is missing or changed — "
            "0.0.0.0/::/empty-string would silently populate source.ip with "
            "a meaningless value instead of being excluded"
        )

        # Gap 2: domain controllers commonly log the Kerberos Client
        # Address (4768/4769, both collected per
        # configs/endpoint/winlogbeat.yml) in "::ffff:x.x.x.x" form, which
        # the plain RFC1918 alternation doesn't match — live-confirmed
        # that without this, internal DC-to-DC Kerberos traffic silently
        # attempted (and failed) a geoip lookup.
        v4_mapped_guards = [m.start() for m in re.finditer(r"\(::ffff:\)\?", block)]
        self.assertGreaterEqual(
            len(v4_mapped_guards), 1,
            "the Security-channel geoip guard no longer handles IPv4-mapped "
            "IPv6 (::ffff:x.x.x.x) — internal DC Kerberos traffic would "
            "silently attempt a doomed geoip lookup again"
        )

    def test_ecs_yml_still_documents_the_raw_shape(self):
        # If suburban-soc-ecs.yml is ever changed to map these fields to an
        # ECS name instead (matching the Sysmon transformation's style),
        # the copy-vs-rename distinction stops mattering for Sigma-
        # compiled rules specifically — but the threshold rules (native
        # Lucene, not pySigma-compiled) would still need the raw field to
        # survive. Documents that dependency explicitly so a future editor
        # of ecs.yml sees this test fail with the reason, not a cryptic
        # mismatch.
        self.assertIn(
            "IpAddress: winlog.event_data.IpAddress", PIPELINE,
            "suburban-soc-ecs.yml no longer maps Sigma's IpAddress field to the raw "
            "winlog.event_data.IpAddress shape — if this changed intentionally, "
            "re-verify rules/elastic/threshold/*.ndjson's dependency on the raw field "
            "name still holds before touching the copy-not-rename logic in "
            "configs/logstash.conf's Security-channel block"
        )
        self.assertIn(
            "TargetUserName: winlog.event_data.TargetUserName", PIPELINE,
            "suburban-soc-ecs.yml no longer maps Sigma's TargetUserName field to the raw "
            "winlog.event_data.TargetUserName shape — same re-verification as the "
            "IpAddress case above"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
