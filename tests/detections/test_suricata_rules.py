#!/usr/bin/env python3
"""
test_suricata_rules.py — issue #445 (M23 Stage 2): the Suricata detection-
as-code CI lane — SID registry, syntax gate, pcap-replay promotion gate.

Mirrors the Sigma lane's own contract (test_sigma_detections.py): an
enabled rule with no fixture cannot ship, a fixture that doesn't actually
fire the rule is a broken test, and a duplicate or out-of-range SID is a
hard CI failure. #445's own "done when": a PR adding a broken or
duplicate-SID Suricata rule fails CI, and a well-formed one with a passing
pcap fixture goes green.

Two groups of tests here:

  1. Real-repo tests, run against the actual rules/suricata/*.rules tree.
     #446 (Stage 3) hasn't landed yet, so today this is mostly a vacuous
     pass over an empty ruleset — that's expected, not a weakness: once
     Stage 3 lands real (disabled) rules, these same tests immediately
     start enforcing the registry/promotion-gate contract on them with no
     further engineering.
  2. Harness meta-tests, run against synthetic in-memory/tmp_path rule
     text, that prove the checker itself actually catches a duplicate SID,
     an out-of-range SID, and an enabled-rule-without-fixture — the exact
     failure modes #445 exists to catch — independent of whether any real
     content exists yet. The final meta-test (ReplayHarnessRealSuricataTests)
     goes one step further: a REAL suricata binary replays a REAL
     scapy-built pcap against a REAL rule, genuine local verification the
     same way test_suricata_config.py's ConfigSyntaxTests is, not a mock
     of Suricata's match semantics.

SKIPS (does not fail) the suricata-binary-dependent checks if `suricata`
isn't on PATH, and the scapy-dependent ones if `scapy` isn't importable —
same convention as test_suricata_config.py's ConfigSyntaxTests and
test_zeek_mime_detection.py's real-binary checks. CI installs both (see
.github/workflows/detections.yml and lint.yml) so they actually run there.

Run:  pytest tests/detections/test_suricata_rules.py -v
"""

from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from suricata_rules_eval import (
    RuleRecord,
    check_syntax_including_disabled,
    find_duplicate_sids,
    find_out_of_range,
    fixture_paths,
    load_records,
    promotion_gate_violations,
    replay_pcap,
    sid_range_name,
)

ROOT = Path(__file__).resolve().parents[2]
SURICATA_RULES_DIR = ROOT / "rules" / "suricata"
SURICATA_YAML = ROOT / "configs" / "suricata" / "suricata.yaml"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "suricata"
SURICATA_BIN = shutil.which("suricata")

try:
    from scapy.all import IP, UDP, Raw  # noqa: F401
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


def _real_rule_files() -> list[Path]:
    return sorted(SURICATA_RULES_DIR.glob("*.rules"))


class SidRegistryRealRepoTests(unittest.TestCase):
    """Against the actual rules/suricata/ tree."""

    def setUp(self):
        self.records = load_records(_real_rule_files())

    def test_no_duplicate_sids_repo_wide(self):
        dupes = find_duplicate_sids(self.records)
        self.assertEqual(
            {}, dupes,
            f"duplicate SIDs across rules/suricata/: "
            f"{ {sid: [f'{r.file.name}:{r.line_no}' for r in recs] for sid, recs in dupes.items()} }",
        )

    def test_all_sids_within_registered_ranges(self):
        offenders = find_out_of_range(self.records)
        self.assertEqual(
            [], offenders,
            "SIDs outside every registered range (see suricata_rules_eval.SID_RANGES): "
            + ", ".join(f"{r.file.name}:{r.line_no} sid={r.sid}" for r in offenders),
        )


class RuleFilesWiredIntoConfigTests(unittest.TestCase):
    """A landed .rules file that's never added to suricata.yaml's
    `rule-files:` list would load in this test's own glob-based checks
    above but never actually run on the production sensor — the exact
    "looks like coverage, detects nothing" gap #445/#446 both warn about
    for placeholders. Catches the file-level version of that mistake."""

    def test_every_rules_file_is_referenced_in_suricata_yaml(self):
        yaml_text = SURICATA_YAML.read_text(encoding="utf-8")
        idx = yaml_text.index("rule-files:")
        block = yaml_text[idx:]
        missing = [p.name for p in _real_rule_files() if p.name not in block]
        self.assertEqual(
            [], missing,
            f"rules/suricata/ files not referenced under suricata.yaml's rule-files: {missing}",
        )


class PromotionGateRealRepoTests(unittest.TestCase):
    """Enabled rules in the real tree must have a passing pcap fixture.
    Vacuously passes today (no enabled rules exist pre-#446) — starts
    enforcing the instant Stage 3 lands a rule with the leading '#'
    removed."""

    def test_enabled_rules_have_passing_fixtures(self):
        records = load_records(_real_rule_files())
        violations = promotion_gate_violations(records, FIXTURES_DIR, SURICATA_BIN)
        self.assertEqual([], violations, "promotion-gate violations:\n" + "\n".join(violations))


class SyntaxGateRealRepoTests(unittest.TestCase):
    """The full aggregate ruleset, not just local.rules, loads cleanly
    under a real `suricata -T`. Runs the exact production `-c
    configs/suricata/suricata.yaml` path with no `-S` override — Suricata
    7.0.3 rejects multiple `-S` flags (confirmed by hand), so this
    deliberately does NOT glob rule_files itself; it validates that
    whatever `rule-files:` lists in the real config loads clean, which is
    the true production path. RuleFilesWiredIntoConfigTests (above)
    separately catches a landed `.rules` file that was never added to
    that list — together the two checks cover both halves of "a new
    category file is both present and wired in.\""""

    def test_suricata_dash_t_loads_every_rules_file(self):
        if not SURICATA_BIN:
            self.skipTest("suricata binary not installed in this environment")
        import subprocess
        import tempfile
        if not _real_rule_files():
            self.skipTest("no .rules files under rules/suricata/ yet")
        with tempfile.TemporaryDirectory() as log_dir:
            cmd = [SURICATA_BIN, "-T", "-c", str(SURICATA_YAML), "-l", log_dir, "--af-packet=lo"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            self.assertEqual(
                result.returncode, 0,
                f"suricata -T failed on the aggregate ruleset:\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}",
            )

    def test_suricata_dash_t_validates_every_rule_even_disabled(self):
        # #-commented lines are invisible to Suricata's rule loader (see
        # check_syntax_including_disabled's own docstring) — the test
        # above only proves the ENABLED subset parses, which for #446's
        # "land all 100, disabled until tuned" set is zero rules today.
        # This validates the real Suricata syntax of every landed rule,
        # disabled or not, by stripping the leading '#' before parsing.
        if not SURICATA_BIN:
            self.skipTest("suricata binary not installed in this environment")
        records = load_records(_real_rule_files())
        if not records:
            self.skipTest("no rules under rules/suricata/ yet")
        ok, stdout, stderr = check_syntax_including_disabled(records, SURICATA_BIN)
        self.assertTrue(ok, f"suricata -T failed on the uncommented ruleset:\nstdout: {stdout}\nstderr: {stderr}")


# --- Harness meta-tests: prove the checker itself works, independent of
# whether rules/suricata/ has any real content yet (#446 not landed). ---

RULE_TEMPLATE = 'alert udp any any -> any any (msg:"{msg}"; content:"{needle}"; sid:{sid}; rev:1;)'


class SidRegistryMetaTests(unittest.TestCase):
    def _rec(self, sid: int, enabled: bool = True, path: Path = Path("synthetic.rules"), line_no: int = 1) -> RuleRecord:
        raw = RULE_TEMPLATE.format(msg="synthetic", needle="x", sid=sid)
        if not enabled:
            raw = "# " + raw
        return RuleRecord(file=path, line_no=line_no, raw=raw, sid=sid, enabled=enabled)

    def test_duplicate_sid_across_two_files_is_detected(self):
        recs = [
            self._rec(9500001, path=Path("a.rules")),
            self._rec(9500001, path=Path("b.rules")),
        ]
        dupes = find_duplicate_sids(recs)
        self.assertIn(9500001, dupes)
        self.assertEqual(2, len(dupes[9500001]))

    def test_unique_sids_are_not_flagged(self):
        recs = [self._rec(9500001), self._rec(9500002)]
        self.assertEqual({}, find_duplicate_sids(recs))

    def test_vendor_range_sid_is_out_of_range(self):
        # A real Emerging Threats SID range (2xxxxxx) copy-pasted by
        # mistake must be rejected, not silently accepted as "local".
        rec = self._rec(2001219)
        self.assertIsNone(sid_range_name(rec.sid))
        self.assertEqual([rec], find_out_of_range([rec]))

    def test_starter_set_and_local_ranges_are_accepted(self):
        self.assertIsNotNone(sid_range_name(9000050))
        self.assertIsNotNone(sid_range_name(9500001))

    def test_range_boundaries_are_exact(self):
        self.assertIsNone(sid_range_name(9000000))
        self.assertIsNone(sid_range_name(9000101))
        self.assertIsNone(sid_range_name(9500000))
        self.assertIsNone(sid_range_name(9600000))

    def test_parser_ignores_prose_comment_mentioning_sid(self):
        # A pure explanatory comment (this file's own header style) must
        # never be mistaken for a disabled rule.
        from suricata_rules_eval import parse_rule_line
        rec = parse_rule_line(
            Path("x.rules"), 1,
            "# Local SIDs use the 9500001-9599999 range; sid: is assigned per rule.",
        )
        self.assertIsNone(rec)

    def test_parser_detects_commented_out_rule_as_disabled(self):
        from suricata_rules_eval import parse_rule_line
        raw = "#" + RULE_TEMPLATE.format(msg="m", needle="x", sid=9500005)
        rec = parse_rule_line(Path("x.rules"), 1, raw)
        self.assertIsNotNone(rec)
        self.assertFalse(rec.enabled)
        self.assertEqual(9500005, rec.sid)
        self.assertTrue(rec.uncommented.startswith("alert"))


class PromotionGateMetaTests(unittest.TestCase):
    def test_enabled_rule_without_fixture_is_a_violation(self):
        rec = RuleRecord(
            file=Path("synthetic.rules"), line_no=1,
            raw=RULE_TEMPLATE.format(msg="m", needle="x", sid=9500010),
            sid=9500010, enabled=True,
        )
        with_no_fixtures_dir = Path("/nonexistent/fixtures/dir")
        violations = promotion_gate_violations([rec], with_no_fixtures_dir, suricata_bin=None)
        self.assertEqual(1, len(violations))
        self.assertIn("9500010", violations[0])
        self.assertIn("cannot enter the enabled set", violations[0])

    def test_disabled_rule_without_fixture_is_not_a_violation(self):
        rec = RuleRecord(
            file=Path("synthetic.rules"), line_no=1,
            raw="#" + RULE_TEMPLATE.format(msg="m", needle="x", sid=9500011),
            sid=9500011, enabled=False,
        )
        violations = promotion_gate_violations([rec], Path("/nonexistent"), suricata_bin=None)
        self.assertEqual([], violations)


class ReplayHarnessRealSuricataTests(unittest.TestCase):
    """Real suricata + real scapy-built pcaps — genuine verification that
    the replay engine's match/no-match determination is correct, not a
    mock of Suricata's own detection logic."""

    def setUp(self):
        if not SURICATA_BIN:
            self.skipTest("suricata binary not installed in this environment")
        if not _SCAPY_AVAILABLE:
            self.skipTest("scapy not installed in this environment")

    def _build_pcap(self, tmp_path: Path, name: str, payload: bytes) -> Path:
        from scapy.all import IP, UDP, Raw, wrpcap
        pkt = IP(src="192.168.1.50", dst="93.184.216.34") / UDP(sport=51000, dport=53535) / Raw(load=payload)
        path = tmp_path / name
        wrpcap(str(path), [pkt])
        return path

    def test_true_positive_pcap_fires_and_true_negative_does_not(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            rule_text = RULE_TEMPLATE.format(msg="canary", needle="malicious-canary-token", sid=9999999)
            tp_pcap = self._build_pcap(tmp_path, "tp.pcap", b"malicious-canary-token")
            tn_pcap = self._build_pcap(tmp_path, "tn.pcap", b"totally-benign-payload")

            fired_tp = replay_pcap(rule_text, tp_pcap, SURICATA_BIN)
            self.assertEqual({9999999}, fired_tp)

            fired_tn = replay_pcap(rule_text, tn_pcap, SURICATA_BIN)
            self.assertEqual(set(), fired_tn)

    def test_commented_out_rule_text_can_still_be_replayed_via_uncommented(self):
        # Authoring workflow: a rule is written disabled (leading '#')
        # until its fixture passes; RuleRecord.uncommented is what
        # promotion_gate_violations() actually replays.
        import tempfile
        rec = RuleRecord(
            file=Path("synthetic.rules"), line_no=1,
            raw="# " + RULE_TEMPLATE.format(msg="canary", needle="another-canary", sid=9999998),
            sid=9999998, enabled=False,
        )
        with tempfile.TemporaryDirectory() as tmp:
            tp_pcap = self._build_pcap(Path(tmp), "tp.pcap", b"another-canary")
            fired = replay_pcap(rec.uncommented, tp_pcap, SURICATA_BIN)
            self.assertEqual({9999998}, fired)


class SyntaxIncludingDisabledMetaTests(unittest.TestCase):
    def setUp(self):
        if not SURICATA_BIN:
            self.skipTest("suricata binary not installed in this environment")

    def test_valid_disabled_rule_passes(self):
        rec = RuleRecord(
            file=Path("synthetic.rules"), line_no=1,
            raw="#" + RULE_TEMPLATE.format(msg="m", needle="x", sid=9500020),
            sid=9500020, enabled=False,
        )
        ok, stdout, stderr = check_syntax_including_disabled([rec], SURICATA_BIN)
        self.assertTrue(ok, f"stdout: {stdout}\nstderr: {stderr}")

    def test_broken_disabled_rule_is_caught(self):
        # Same shape confirmed by hand: a plain -S/-T pass over the
        # AS-SHIPPED (still '#'-prefixed) file silently ignores this —
        # Suricata's loader never even looks at a commented line. Only
        # the uncommented form here catches it.
        rec = RuleRecord(
            file=Path("synthetic.rules"), line_no=1,
            raw='# alert udp any any -> any any (msg:"broken"; sid:9500021)',  # missing content/rev, unbalanced
            sid=9500021, enabled=False,
        )
        ok, _stdout, _stderr = check_syntax_including_disabled([rec], SURICATA_BIN)
        self.assertFalse(ok)


class FixturePathConventionTests(unittest.TestCase):
    def test_fixture_paths_use_sid_prefixed_naming(self):
        tp, tn = fixture_paths(Path("/x"), 9000042)
        self.assertEqual(Path("/x/9000042_tp.pcap"), tp)
        self.assertEqual(Path("/x/9000042_tn.pcap"), tn)


if __name__ == "__main__":
    unittest.main()
