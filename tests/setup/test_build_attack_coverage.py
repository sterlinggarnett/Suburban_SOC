#!/usr/bin/env python3
"""
build_attack_coverage.py — #281 Navigator-layer dedup tests.

navigator_layer() emitted one ATT&CK Navigator technique object per RULE
mapping with no dedup at all; two rules tagging the same technique under
the same tactic produced two techniqueID objects, which Navigator
typically renders as one, silently dropping the other's score/comment.
markdown()'s "Coverage: N techniques" line double-counted the same shape
(it was really counting rule-to-technique rows, not distinct techniques).

The real corpus has BOTH shapes at once, which is why the fix dedups by
the (techniqueID, tactic) PAIR, not techniqueID alone (the issue's own
suggested fix): 19 genuine duplicate pairs (e.g. T1543.003 mapped by 5
different rules, all under Persistence) collapse 108 rule-mappings down to
75 unique techniques — but T1078.003 (Valid Accounts: Local Accounts)
legitimately appears under BOTH Initial Access (a direct SSH root login —
external access) and Privilege Escalation (an `su` session — local
elevation), two real, distinct MITRE ATT&CK tactic mappings for the same
sub-technique. ATT&CK Navigator's own layer schema scores a techniqueID
per TACTIC COLUMN (each entry carries its own `tactic` field), so
collapsing on techniqueID alone would silently drop one of T1078.003's two
legitimate tactic-column entries — the exact "Navigator renders only one,
the other is silently dropped" failure #281 describes, just inverted.

Run:  pytest tests/setup/test_build_attack_coverage.py
"""
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import build_attack_coverage as bac


def _row(technique, tactic, rule="rules/sigma/x.yml", title="X",
         test="test", status="stable"):
    return {"technique": technique, "tactic": tactic, "source": "src",
            "rule": rule, "test": test, "title": title, "status": status}


class NavigatorLayerDedupTests(unittest.TestCase):
    def test_two_rules_same_technique_same_tactic_collapse_to_one_entry(self):
        rows = [
            _row("T1003.001", "Credential Access", rule="rules/sigma/a.yml", title="A"),
            _row("T1003.001", "Credential Access", rule="rules/sigma/b.yml", title="B"),
        ]
        layer = bac.navigator_layer(rows)
        matching = [t for t in layer["techniques"] if t["techniqueID"] == "T1003.001"]
        self.assertEqual(len(matching), 1)

    def test_collapsed_entry_merges_both_rules_comments(self):
        rows = [
            _row("T1003.001", "Credential Access", rule="rules/sigma/a.yml", title="A"),
            _row("T1003.001", "Credential Access", rule="rules/sigma/b.yml", title="B"),
        ]
        layer = bac.navigator_layer(rows)
        comment = layer["techniques"][0]["comment"]
        self.assertIn("rules/sigma/a.yml", comment)
        self.assertIn("rules/sigma/b.yml", comment)

    def test_same_technique_different_tactic_stays_as_two_entries(self):
        # T1078.003's real shape — see module docstring for why "group by
        # techniqueID alone" (the issue's own suggested fix) is wrong.
        rows = [
            _row("T1078.003", "Initial Access", rule="rules/sigma/ssh_root.yml"),
            _row("T1078.003", "Privilege Escalation", rule="rules/sigma/su.yml"),
        ]
        layer = bac.navigator_layer(rows)
        matching = [t for t in layer["techniques"] if t["techniqueID"] == "T1078.003"]
        self.assertEqual(len(matching), 2)
        tactics = {t["tactic"] for t in matching}
        self.assertEqual(tactics, {"initial-access", "privilege-escalation"})

    def test_a_single_rule_technique_is_unaffected(self):
        rows = [_row("T1046", "Discovery")]
        layer = bac.navigator_layer(rows)
        self.assertEqual(len(layer["techniques"]), 1)
        self.assertNotIn(";", layer["techniques"][0]["comment"])

    def test_navigator_metadata_detections_count_is_the_raw_row_count_not_deduped(self):
        # "detections" (rule-to-technique mappings) and the deduped
        # technique count are both legitimate, DIFFERENT numbers — this
        # metadata field is deliberately the former.
        rows = [
            _row("T1003.001", "Credential Access", rule="rules/sigma/a.yml"),
            _row("T1003.001", "Credential Access", rule="rules/sigma/b.yml"),
        ]
        layer = bac.navigator_layer(rows)
        detections_meta = next(m for m in layer["metadata"] if m["name"] == "detections")
        self.assertEqual(detections_meta["value"], "2")

    def test_navigator_metadata_techniques_count_is_unique_techniques_not_pairs(self):
        # #379: T1078.003's real shape (see module docstring) produces TWO
        # (techniqueID, tactic) entries in layer["techniques"] but is only
        # ONE unique technique — slo_metrics.py's metric_coverage() reads
        # this "unique_techniques" metadata field instead of
        # len(layer["techniques"]) specifically to avoid over-reporting by
        # one in exactly this case. Named "unique_techniques", not
        # "techniques", so it can't be confused with the array above.
        rows = [
            _row("T1078.003", "Initial Access", rule="rules/sigma/ssh_root.yml"),
            _row("T1078.003", "Privilege Escalation", rule="rules/sigma/su.yml"),
            _row("T1046", "Discovery", rule="rules/sigma/discover.yml"),
        ]
        layer = bac.navigator_layer(rows)
        self.assertEqual(len(layer["techniques"]), 3, "sanity: 3 pair-entries expected")
        techniques_meta = next(m for m in layer["metadata"] if m["name"] == "unique_techniques")
        self.assertEqual(techniques_meta["value"], "2",
                          "T1078.003 + T1046 = 2 unique techniques, not 3 pair-entries")
        self.assertEqual(techniques_meta["value"], str(bac.unique_technique_count(rows)))

    def test_output_order_is_deterministic_first_seen_order(self):
        rows = [
            _row("T1046", "Discovery"),
            _row("T1003.001", "Credential Access"),
            _row("T1003.001", "Credential Access"),  # duplicate, must not re-insert
        ]
        layer = bac.navigator_layer(rows)
        ids = [t["techniqueID"] for t in layer["techniques"]]
        self.assertEqual(ids, ["T1046", "T1003.001"])


class MarkdownCoverageCountTests(unittest.TestCase):
    def test_coverage_count_is_unique_techniques_not_row_count(self):
        rows = [
            _row("T1003.001", "Credential Access", rule="rules/sigma/a.yml"),
            _row("T1003.001", "Credential Access", rule="rules/sigma/b.yml"),
            _row("T1046", "Discovery"),
        ]
        md = bac.markdown(rows)
        self.assertIn("**Coverage:** 2 techniques", md)

    def test_coverage_count_matches_row_count_when_no_duplicates(self):
        rows = [_row("T1046", "Discovery"), _row("T1110", "Credential Access")]
        md = bac.markdown(rows)
        self.assertIn("**Coverage:** 2 techniques", md)


class RealCorpusRegressionTests(unittest.TestCase):
    """Guards the exact real-data shape #281 was filed over — not just
    synthetic fixtures. harvest() reads the real rules/sigma/*.yml +
    configs/logstash.conf, so these exercise the actual corpus."""

    def test_no_duplicate_technique_tactic_pairs_in_the_real_layer(self):
        rows = bac.harvest()
        layer = bac.navigator_layer(rows)
        pairs = [(t["techniqueID"], t["tactic"]) for t in layer["techniques"]]
        self.assertEqual(len(pairs), len(set(pairs)),
                          "navigator_layer() emitted a duplicate (techniqueID, tactic) pair")

    def test_layer_has_exactly_one_entry_per_unique_technique_tactic_pair(self):
        # security-auditor finding: the no-duplicates test above would still
        # PASS under a techniqueID-only regression (fewer, not just
        # non-duplicate, entries) — it only catches OVER-merging, not
        # UNDER-merging. This pins both directions at once, corpus-
        # independent of which specific rules happen to produce multi-tactic
        # techniques: every (technique, tactic) pair the real corpus
        # produces must appear in the layer, and nothing else must.
        rows = bac.harvest()
        layer = bac.navigator_layer(rows)
        emitted = {(t["techniqueID"], t["tactic"]) for t in layer["techniques"]}
        expected = {(r["technique"], r["tactic"].lower().replace(" ", "-")) for r in rows}
        self.assertEqual(emitted, expected)

    def test_t1078_003_keeps_all_legitimate_tactic_entries(self):
        # Regression guard for the exact case that makes "dedup by
        # techniqueID alone" wrong — see module docstring.
        # #378: auth_linux_ssh_root_login.yml tags BOTH attack.initial_access
        # AND attack.persistence alongside its single attack.t1078.003 tag —
        # before #378 fixed harvest()'s first-match-only extraction, only
        # Initial Access survived; Persistence was silently discarded (one
        # of the 21 secondary-tactic-mapping drops #378 itself is about).
        # So T1078.003 now legitimately appears 3 times: Initial Access +
        # Persistence (both from root_login) + Privilege Escalation (su).
        rows = bac.harvest()
        layer = bac.navigator_layer(rows)
        matching = [t for t in layer["techniques"] if t["techniqueID"] == "T1078.003"]
        self.assertEqual(len(matching), 3,
                          "T1078.003 should appear once per legitimate tactic "
                          "(Initial Access + Persistence via SSH root login, "
                          "Privilege Escalation via su) — collapsing entries "
                          "would silently drop a real tactic-column score in "
                          "ATT&CK Navigator")
        tactics = {t["tactic"] for t in matching}
        self.assertEqual(tactics, {"initial-access", "persistence", "privilege-escalation"})

    def test_real_corpus_currently_has_duplicate_mappings_this_fix_dedups(self):
        # Not a correctness requirement of the fix itself — if this ever
        # goes to 0 (every rule pruned to a unique technique+tactic pair),
        # that's fine, it just means the dedup path above stops being
        # exercised by real data. Documents the fix's real-world impact.
        rows = bac.harvest()
        technique_tactic_pairs = [(r["technique"], r["tactic"]) for r in rows]
        self.assertGreater(len(technique_tactic_pairs), len(set(technique_tactic_pairs)))

    def test_markdown_coverage_count_is_less_than_raw_row_count_for_real_corpus(self):
        rows = bac.harvest()
        md = bac.markdown(rows)
        unique_count = len({r["technique"] for r in rows})
        self.assertIn(f"**Coverage:** {unique_count} techniques", md)
        self.assertLess(unique_count, len(rows))

    def test_network_row_count_matches_the_real_conf_technique_assignment_count(self):
        # security-auditor finding (#430): a cross-block regex mis-pairing
        # or block-swallow (see MergedCommentTests-adjacent unit tests for
        # the synthetic reproduction) could silently DROP a network entry
        # while every individual field still resolves — count-parity
        # against the real config's own literal technique-id assignment
        # count is the one check that would catch a silent drop against
        # real data, not just a synthetic fixture.
        rows = bac.harvest()
        network_rows = [r for r in rows if r["rule"].startswith("configs/logstash.conf")]
        expected_count = len(re.findall(r'\[threat\]\[technique\]\[id\]"\s*=>', bac.CONF))
        self.assertEqual(len(network_rows), expected_count,
                          "harvest() emitted a different number of network rows than "
                          "there are [threat][technique][id] assignments in the real "
                          "configs/logstash.conf — a block was mis-paired or dropped")


class UniqueTechniqueCountTests(unittest.TestCase):
    def test_counts_distinct_technique_ids_not_rows(self):
        rows = [
            _row("T1003.001", "Credential Access", rule="rules/sigma/a.yml"),
            _row("T1003.001", "Credential Access", rule="rules/sigma/b.yml"),
            _row("T1046", "Discovery"),
        ]
        self.assertEqual(bac.unique_technique_count(rows), 2)

    def test_matches_markdown_and_main_console_output(self):
        # code-reviewer finding: markdown() and main() used to compute this
        # inline, identically, in two places — pins that both now delegate
        # to the same helper rather than re-diverging silently.
        rows = bac.harvest()
        expected = len({r["technique"] for r in rows})
        self.assertEqual(bac.unique_technique_count(rows), expected)
        self.assertIn(f"**Coverage:** {expected} techniques", bac.markdown(rows))


class MergedCommentTests(unittest.TestCase):
    """#281 code-reviewer finding: a naive per-rule "(test: ...)" suffix
    repeated once per contributing rule bloated a 5-rule real merge
    (T1543.003) to a 949-character Navigator tooltip."""

    def test_states_the_shared_test_once_when_all_rules_match(self):
        group = [
            _row("T1543.003", "Persistence", rule="rules/sigma/a.yml", title="A"),
            _row("T1543.003", "Persistence", rule="rules/sigma/b.yml", title="B"),
        ]
        comment = bac._merged_comment(group)
        self.assertEqual(comment.count("(test:"), 1)
        self.assertIn("A :: rules/sigma/a.yml", comment)
        self.assertIn("B :: rules/sigma/b.yml", comment)

    def test_states_each_test_separately_when_they_differ(self):
        group = [
            _row("T1046", "Discovery", rule="rules/sigma/a.yml", title="A", test="test-a"),
            _row("T1046", "Discovery", rule="net_zeek.yml", title="B", test="test-b"),
        ]
        comment = bac._merged_comment(group)
        self.assertEqual(comment.count("(test:"), 2)
        self.assertIn("(test: test-a)", comment)
        self.assertIn("(test: test-b)", comment)

    def test_single_rule_group_is_unaffected(self):
        group = [_row("T1046", "Discovery", title="A", test="test-a")]
        self.assertEqual(bac._merged_comment(group), "A :: rules/sigma/x.yml (test: test-a)")

    def test_em_dash_title_does_not_collide_with_the_delimiter(self):
        """#425/#426, security-auditor finding: the ORIGINAL " — " delimiter
        collided with an em-dash-containing title in a real, shipped
        multi-rule group (T1110) — the title<->rule boundary became
        ambiguous by inspection. Uses the real corpus title verbatim
        (net_zeek_ssh_session_cadence.yml) and gives the two rows
        different `test` values (code-reviewer finding: an earlier draft
        of this test used the shared-test-value default, which only
        exercises _merged_comment()'s len(tests)==1 short path — the
        REAL T1110 group spans two distinct test values, hitting the
        `else` branch instead, which is the branch this exact bug lived
        in; a fix applied to only one of the two branches would have
        passed this test silently otherwise)."""
        group = [
            _row("T1110", "Credential Access", rule="rules/sigma/net_zeek_ssh_session_cadence.yml",
                 title="SSH Session Cadence — Complementary Brute-Force Coverage Below "
                       "detect-bruteforcing's Threshold",
                 test="Detections CI: sigma->Lucene conversion + fixture replay (tests/detections/)"),
            _row("T1110", "Credential Access", rule="configs/logstash.conf",
                 title="B", test="tests/pipeline/test_framework_enrichment.py"),
        ]
        comment = bac._merged_comment(group)
        self.assertIn(
            "SSH Session Cadence — Complementary Brute-Force Coverage Below "
            "detect-bruteforcing's Threshold :: rules/sigma/net_zeek_ssh_session_cadence.yml",
            comment)
        self.assertIn("B :: configs/logstash.conf", comment)

    def test_output_structurally_decomposes_back_to_one_segment_per_rule(self):
        """security-auditor finding: the sibling tests above (including
        test_em_dash_title_does_not_collide_with_the_delimiter) all assert
        a literal delimiter STRING — they'd re-pass trivially if the
        delimiter changed again to something else that merely doesn't
        happen to appear in this particular test's fixture titles, without
        actually proving the general non-ambiguity property. This test
        checks the STRUCTURAL invariant instead: splitting the output on
        _GROUP_DELIM must yield exactly one segment per input rule, and
        each segment must contain exactly one _TITLE_RULE_DELIM — so ANY
        future delimiter choice that collides with real title/rule/test
        content fails here, not just a reversion to the one delimiter
        already fixed."""
        group = [
            _row("T1110", "Credential Access", rule="rules/sigma/net_zeek_ssh_session_cadence.yml",
                 title="SSH Session Cadence — Complementary Brute-Force Coverage Below "
                       "detect-bruteforcing's Threshold"),
            _row("T1110", "Credential Access", rule="rules/sigma/net_zeek_ssh_session_cadence_sustained.yml",
                 title="Sustained Low-and-Slow SSH Session Cadence — Below detect-bruteforcing "
                       "AND net_zeek_ssh_session_cadence's Own Rate Floor"),
            _row("T1110", "Credential Access", rule="configs/logstash.conf", title="Brute Force"),
        ]
        comment = bac._merged_comment(group)
        segments = comment.split(bac._GROUP_DELIM)
        self.assertEqual(len(segments), len(group))
        for segment in segments:
            self.assertEqual(segment.count(bac._TITLE_RULE_DELIM), 1)

    def test_no_real_title_rule_or_test_contains_a_comment_delimiter(self):
        """security-auditor finding: guards the invariant _merged_comment()
        actually depends on directly against the real corpus, rather than
        only against synthetic fixtures — harvest() reads the real
        rules/sigma/*.yml + configs/logstash.conf, same as
        RealCorpusRegressionTests elsewhere in this file."""
        for r in bac.harvest():
            for field in ("title", "rule", "test"):
                self.assertNotIn(bac._TITLE_RULE_DELIM.strip(), r[field])
                self.assertNotIn(bac._GROUP_DELIM.strip(), r[field])


class ValidateTitleTests(unittest.TestCase):
    def test_passes_through_a_safe_title(self):
        self.assertEqual(bac._validate_title("A Safe Title", "src"), "A Safe Title")

    def test_rejects_a_pipe_character(self):
        with self.assertRaises(ValueError) as ctx:
            bac._validate_title("Bad | Title", "rules/sigma/x.yml")
        self.assertIn("rules/sigma/x.yml", str(ctx.exception))
        self.assertIn("Bad | Title", str(ctx.exception))

    def test_rejects_a_semicolon(self):
        with self.assertRaises(ValueError):
            bac._validate_title("Bad; Title", "rules/sigma/x.yml")

    def test_rejects_a_double_colon(self):
        # #425: guards _merged_comment()'s own "::" title<->rule delimiter
        # the same way "|"/";" already guard the markdown table/Navigator
        # merge delimiters.
        with self.assertRaises(ValueError):
            bac._validate_title("Bad :: Title", "rules/sigma/x.yml")


class HarvestFailsLoudlyOnBadInputTests(unittest.TestCase):
    """#281 security-auditor finding: a technique tag with no resolvable
    tactic used to silently render as a dead "Unknown" Navigator cell —
    the exact silent-drop failure class #281 exists to eliminate, just via
    a different route. Constructs a temp rule corpus rather than touching
    the real one, so these don't depend on (or risk mutating) real rules."""

    def _harvest_with_rule(self, rule_text):
        with tempfile.TemporaryDirectory() as d:
            sigma_dir = Path(d)
            (sigma_dir / "test_rule.yml").write_text(rule_text, encoding="utf-8")
            with mock.patch.object(bac, "SIGMA_DIR", sigma_dir), \
                 mock.patch.object(bac, "CONF", ""):
                return bac.harvest()

    def test_raises_when_technique_tag_has_no_tactic_tag_at_all(self):
        rule_text = "title: Test Rule\ntags:\n    - attack.t1046\n"
        with self.assertRaises(ValueError) as ctx:
            self._harvest_with_rule(rule_text)
        self.assertIn("test_rule.yml", str(ctx.exception))

    def test_raises_when_tactic_tag_does_not_resolve_in_tactics_map(self):
        # A plausible authoring typo: hyphen instead of underscore.
        rule_text = "title: Test Rule\ntags:\n    - attack.t1046\n    - attack.privilege-escalation\n"
        with self.assertRaises(ValueError) as ctx:
            self._harvest_with_rule(rule_text)
        self.assertIn("test_rule.yml", str(ctx.exception))

    def test_does_not_raise_when_tactic_tag_resolves_correctly(self):
        rule_text = "title: Test Rule\ntags:\n    - attack.t1046\n    - attack.discovery\n"
        rows = self._harvest_with_rule(rule_text)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["tactic"], "Discovery")

    def test_raises_on_unsafe_title_from_a_sigma_rule(self):
        rule_text = "title: Bad | Title\ntags:\n    - attack.t1046\n    - attack.discovery\n"
        with self.assertRaises(ValueError):
            self._harvest_with_rule(rule_text)

    def test_raises_on_unsafe_title_from_a_logstash_conf_network_entry(self):
        conf = ('"[threat][technique][id]" => "T1046",'
                '"[threat][technique][name]" => "Bad; Title",'
                '"[threat][tactic][id]" => "TA0007",'
                '"[threat][tactic][name]" => "Discovery"')
        with tempfile.TemporaryDirectory() as d:
            sigma_dir = Path(d)
            with mock.patch.object(bac, "SIGMA_DIR", sigma_dir), \
                 mock.patch.object(bac, "CONF", conf):
                with self.assertRaises(ValueError):
                    bac.harvest()

    def test_raises_when_network_entrys_tactic_name_does_not_resolve(self):
        # #430 security-auditor finding: the Sigma-rule path above fails
        # loudly on an unresolvable tactic; the network (configs/
        # logstash.conf) path had no equivalent, so a typo'd or malformed
        # [threat][tactic][name] would silently render as a dead
        # Navigator cell rather than failing the build. A plausible
        # authoring typo: "Cred Access" instead of the real ATT&CK
        # tactic name "Credential Access" - correct id, wrong name.
        conf = ('"[threat][technique][id]" => "T1110",'
                '"[threat][technique][name]" => "Test Technique",'
                '"[threat][tactic][id]" => "TA0006",'
                '"[threat][tactic][name]" => "Cred Access"')
        with tempfile.TemporaryDirectory() as d:
            sigma_dir = Path(d)
            with mock.patch.object(bac, "SIGMA_DIR", sigma_dir), \
                 mock.patch.object(bac, "CONF", conf):
                with self.assertRaises(ValueError) as ctx:
                    bac.harvest()
        self.assertIn("logstash.conf", str(ctx.exception))
        self.assertIn("Cred Access", str(ctx.exception))

    def test_raises_when_network_entrys_tactic_id_and_name_are_individually_valid_but_mismatched(self):
        # security-auditor finding (#430): validating the tactic NAME
        # alone would pass a copy-paste mistake where the id and name
        # are each individually a real ATT&CK value, just not the SAME
        # tactic's id/name — e.g. Discovery's real id (TA0007) paired
        # with a different tactic's real name ("Credential Access").
        # Both halves resolve individually; the PAIR does not.
        conf = ('"[threat][technique][id]" => "T1046",'
                '"[threat][technique][name]" => "Test Technique",'
                '"[threat][tactic][id]" => "TA0007",'
                '"[threat][tactic][name]" => "Credential Access"')
        with tempfile.TemporaryDirectory() as d:
            sigma_dir = Path(d)
            with mock.patch.object(bac, "SIGMA_DIR", sigma_dir), \
                 mock.patch.object(bac, "CONF", conf):
                with self.assertRaises(ValueError):
                    bac.harvest()

    def test_does_not_raise_when_network_entrys_tactic_name_resolves(self):
        conf = ('"[threat][technique][id]" => "T1110",'
                '"[threat][technique][name]" => "Test Technique",'
                '"[threat][tactic][id]" => "TA0006",'
                '"[threat][tactic][name]" => "Credential Access"')
        with tempfile.TemporaryDirectory() as d:
            sigma_dir = Path(d)
            with mock.patch.object(bac, "SIGMA_DIR", sigma_dir), \
                 mock.patch.object(bac, "CONF", conf):
                rows = bac.harvest()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["tactic"], "Credential Access")

    def test_raises_on_malformed_network_technique_id(self):
        # security-auditor finding (#430): the Sigma path uppercases and
        # regex-constrains its technique id; the network path took it
        # verbatim. A malformed/differently-cased id (lowercase 't1046',
        # a missing 'T' prefix) would produce a Navigator cell that
        # doesn't merge with the real technique's cell.
        conf = ('"[threat][technique][id]" => "t1046",'
                '"[threat][technique][name]" => "Test Technique",'
                '"[threat][tactic][id]" => "TA0007",'
                '"[threat][tactic][name]" => "Discovery"')
        with tempfile.TemporaryDirectory() as d:
            sigma_dir = Path(d)
            with mock.patch.object(bac, "SIGMA_DIR", sigma_dir), \
                 mock.patch.object(bac, "CONF", conf):
                with self.assertRaises(ValueError):
                    bac.harvest()

    def test_network_pairing_does_not_cross_an_add_field_block_boundary(self):
        # security-auditor finding (#430): the original `.*?` between
        # fields was unanchored to the enclosing add_field block, so a
        # block missing its own tactic fields could let the pattern
        # reach past the closing "}" into the NEXT block's tactic fields
        # and silently mis-pair them. Block 1 here deliberately has no
        # tactic fields at all; a real add_field-block-crossing match
        # would incorrectly pair T1046 with block 2's Credential Access.
        # The fix ([^}]*? instead of .*?) must find ONLY block 2's
        # complete quadruple, not a cross-block mis-pairing for block 1.
        conf = (
            'mutate { add_field => {\n'
            '  "[threat][technique][id]" => "T1046"\n'
            '  "[threat][technique][name]" => "Network Service Discovery"\n'
            '} }\n'
            'mutate { add_field => {\n'
            '  "[threat][technique][id]" => "T1110"\n'
            '  "[threat][technique][name]" => "Brute Force"\n'
            '  "[threat][tactic][id]" => "TA0006"\n'
            '  "[threat][tactic][name]" => "Credential Access"\n'
            '} }\n'
        )
        with tempfile.TemporaryDirectory() as d:
            sigma_dir = Path(d)
            with mock.patch.object(bac, "SIGMA_DIR", sigma_dir), \
                 mock.patch.object(bac, "CONF", conf):
                rows = bac.harvest()
        self.assertEqual(len(rows), 1,
                          "block-boundary anchoring regressed — T1046 (which has no "
                          "tactic fields of its own) matched across the block boundary "
                          "into block 2's tactic fields instead of not matching at all")
        self.assertEqual(rows[0]["technique"], "T1110")

    def test_commented_out_network_mapping_is_not_harvested_as_coverage(self):
        # security-auditor finding (#430): the parser operated on raw
        # file text with no comment awareness — a commented-out example
        # mapping would be silently counted as live coverage, overstating
        # what's actually deployed.
        conf = (
            '# "[threat][technique][id]" => "T1046",\n'
            '# "[threat][technique][name]" => "Network Service Discovery",\n'
            '# "[threat][tactic][id]" => "TA0007",\n'
            '# "[threat][tactic][name]" => "Discovery",\n'
        )
        with tempfile.TemporaryDirectory() as d:
            sigma_dir = Path(d)
            with mock.patch.object(bac, "SIGMA_DIR", sigma_dir), \
                 mock.patch.object(bac, "CONF", conf):
                rows = bac.harvest()
        self.assertEqual(rows, [])


class TechniqueTacticPairingTests(unittest.TestCase):
    """#378: harvest() used to re.search() (first-match-only) a rule's
    attack.<technique>/attack.<tactic> tags, silently discarding every
    secondary tag — 21 of the 106-then rules carry two attack.<tactic> tags,
    6 carry two attack.<technique> tags. Switched to re.findall() plus
    _technique_tactic_pairs(), which broadcasts a lone technique/tactic
    across the others (unambiguous — #281's own T1078.003 case), positionally
    pairs same-length lists > 1 (the corpus's own listing convention, and the
    only choice that doesn't assert an unverified cross-tactic mapping — see
    module docstring for the real posh_ps_obfuscated_scriptblock.yml
    counter-example to a blind cross-product), and fails loudly on an
    unequal both->1 shape rather than guessing."""

    def _harvest_with_rule(self, rule_text):
        with tempfile.TemporaryDirectory() as d:
            sigma_dir = Path(d)
            (sigma_dir / "test_rule.yml").write_text(rule_text, encoding="utf-8")
            with mock.patch.object(bac, "SIGMA_DIR", sigma_dir), \
                 mock.patch.object(bac, "CONF", ""):
                return bac.harvest()

    def test_pairs_function_broadcasts_single_technique_across_multiple_tactics(self):
        self.assertEqual(
            bac._technique_tactic_pairs(["T1078.003"], ["Initial Access", "Persistence"], "r"),
            [("T1078.003", "Initial Access"), ("T1078.003", "Persistence")])

    def test_pairs_function_broadcasts_single_tactic_across_multiple_techniques(self):
        self.assertEqual(
            bac._technique_tactic_pairs(["T1059.001", "T1027"], ["Execution"], "r"),
            [("T1059.001", "Execution"), ("T1027", "Execution")])

    def test_pairs_function_positionally_pairs_equal_length_lists(self):
        self.assertEqual(
            bac._technique_tactic_pairs(["T1059.001", "T1027"], ["Execution", "Defense Evasion"], "r"),
            [("T1059.001", "Execution"), ("T1027", "Defense Evasion")])

    def test_pairs_function_raises_on_unequal_both_multi_lists(self):
        # No rule in the real corpus has this shape today, but the function
        # must never guess at a pairing it can't actually infer from the
        # tags alone.
        with self.assertRaises(ValueError) as ctx:
            bac._technique_tactic_pairs(["T1059.001", "T1027", "T1105"], ["Execution", "Defense Evasion"], "r.yml")
        self.assertIn("r.yml", str(ctx.exception))

    def test_harvest_emits_a_row_per_technique_when_one_tactic_is_shared(self):
        rule_text = ("title: Test Rule\ntags:\n    - attack.execution\n"
                     "    - attack.t1059.001\n    - attack.t1027\n")
        rows = self._harvest_with_rule(rule_text)
        pairs = {(r["technique"], r["tactic"]) for r in rows}
        self.assertEqual(pairs, {("T1059.001", "Execution"), ("T1027", "Execution")})

    def test_harvest_emits_a_row_per_tactic_when_one_technique_is_shared(self):
        rule_text = ("title: Test Rule\ntags:\n    - attack.initial_access\n"
                     "    - attack.persistence\n    - attack.t1078.003\n")
        rows = self._harvest_with_rule(rule_text)
        pairs = {(r["technique"], r["tactic"]) for r in rows}
        self.assertEqual(pairs, {("T1078.003", "Initial Access"), ("T1078.003", "Persistence")})

    def test_harvest_positionally_pairs_equal_length_tags_not_a_cross_product(self):
        # The real posh_ps_obfuscated_scriptblock.yml shape: T1059.001
        # (PowerShell) is only a real Execution technique, T1027 (Obfuscated
        # Files) is only a real Defense Evasion technique per MITRE ATT&CK —
        # a cross-product would assert two FALSE pairs here.
        rule_text = ("title: Test Rule\ntags:\n    - attack.execution\n"
                     "    - attack.defense_evasion\n    - attack.t1059.001\n"
                     "    - attack.t1027\n")
        rows = self._harvest_with_rule(rule_text)
        pairs = {(r["technique"], r["tactic"]) for r in rows}
        self.assertEqual(pairs, {("T1059.001", "Execution"), ("T1027", "Defense Evasion")})
        self.assertNotIn(("T1059.001", "Defense Evasion"), pairs)
        self.assertNotIn(("T1027", "Execution"), pairs)

    def test_harvest_validates_every_tactic_tag_not_just_the_first(self):
        # #378: the old code only ever inspected the FIRST tactic match —
        # a rule with a valid first tactic tag and a typo'd second one
        # shipped silently. "made_up_tactic" is tactic-SHAPED (matches the
        # [a-z_]+ tag regex, unlike a hyphenated typo, which the regex
        # doesn't even capture as a candidate tag at all) but isn't a real
        # key in TACTICS, so it must fail the "does it resolve" check
        # specifically, not just the "was anything found" check.
        rule_text = ("title: Test Rule\ntags:\n    - attack.initial_access\n"
                     "    - attack.made_up_tactic\n    - attack.t1078.003\n")
        with self.assertRaises(ValueError) as ctx:
            self._harvest_with_rule(rule_text)
        self.assertIn("test_rule.yml", str(ctx.exception))
        self.assertIn("made_up_tactic", str(ctx.exception))

    def test_harvest_dedups_an_accidentally_repeated_tag(self):
        rule_text = ("title: Test Rule\ntags:\n    - attack.discovery\n"
                     "    - attack.t1046\n    - attack.t1046\n")
        rows = self._harvest_with_rule(rule_text)
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
