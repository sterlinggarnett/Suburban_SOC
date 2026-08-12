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

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONF = (ROOT / "configs" / "logstash.conf").read_text(encoding="utf-8")
SIGMA_DIR = ROOT / "rules" / "sigma"
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
        # (security-auditor review): scan-detection.zeek fires on the
        # initial SYN alone, no handshake required, so wiring it in would
        # have turned a spoofed-source SYN sweep into an unrate-limited
        # automated-response amplifier against an attacker-chosen victim IP
        # — this repo has no rate limiting anywhere in the /alert path.
        # Deferred until #331 (a source-spoofing defense) actually exists.
        # T1046 still gets pipeline-tagged for dashboards, unaffected.
        matches = SOAR_TRIGGER_CONDITIONS_RE.findall(CONF)
        self.assertTrue(matches, "T1110 SOAR trigger condition not found in configs/logstash.conf")
        self.assertNotIn('[threat][technique][id] in ["T1046"', CONF,
                         "T1046 must not be wired into live SOAR dispatch until #331 is fixed")
        self.assertNotIn('[threat][technique][id] in ["T1046", "T1110"]', CONF,
                         "T1046 must not be wired into live SOAR dispatch until #331 is fixed")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
