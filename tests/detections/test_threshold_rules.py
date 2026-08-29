#!/usr/bin/env python3
"""
test_threshold_rules.py — issue #192: validate the Elastic threshold-rule companions.

Two Sigma rules (auth_win_bruteforce_failed_logons.yml, T1110; and
auth_win_explicit_cred_account_sweep.yml, T1110.003) need count/cardinality logic
that neither the fixture evaluator (sigma_eval.py) nor the CI Sigma->Lucene
conversion target can express — see tests/detections/sigma_eval.py's docstring and
.github/workflows/detections.yml. Those Sigma files stay `status: experimental`
(the documented single-event logic-of-record, deliberately excluded from
deploy_detections.sh's query-rule import) and are paired with hand-authored Elastic
SIEM `type: threshold` rule exports in rules/elastic/threshold/*.ndjson, which
deploy_detections.sh imports separately (WS1.2 extension, issue #192).

This validates the Kibana detection_engine import-schema shape of those ndjson
files AND the pairing back to their Sigma logic-of-record: the referenced Sigma
file must exist, carry a matching `id`, and be `status: experimental` (the whole
reason the threshold companion exists instead of a deployed query rule).

Run:  python tests/detections/test_threshold_rules.py   (or: pytest tests/detections)
"""

import json
import re
import unittest
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
THRESHOLD_DIR = ROOT / "rules" / "elastic" / "threshold"
SIGMA_DIR = ROOT / "rules" / "sigma"

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_LANGUAGES = {"lucene", "kuery"}
ATTACK_TAG_RE = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$")
_DURATION_RE = re.compile(r"^(?:now-)?(\d+)m$")


def _minutes(value: str) -> int:
    m = _DURATION_RE.match(value)
    assert m, f"unexpected duration format: {value!r}"
    return int(m.group(1))


# #393: the documented campaign duration each threshold rule's own Sigma
# logic/description names as what it must fully contain within one
# evaluation - the "detection_window" term in the corrected `lookback >=
# interval + detection_window` formula. Hardcoded here (not derivable from
# the ndjson itself - it's a design decision, not a stored field) so a
# future edit that silently narrows `from` back toward the old flawed
# `interval + 1m` convention fails this test immediately, without needing
# a live Elasticsearch (security-auditor finding on this fix's own
# review: the live-fire suite alone could not catch that regression -
# none of its tests vary event age relative to the window boundary).
DETECTION_WINDOW_MINUTES = {
    "auth-win-bruteforce-failed-logons.ndjson": 5,
    "auth-win-bruteforce-source-spray.ndjson": 5,
    "auth-win-explicit-cred-account-sweep.ndjson": 5,
    "disc-win-domain-group-discovery-repeat.ndjson": 10,
    "disc-win-nltest-discovery-repeat.ndjson": 10,
    "disc-win-user-discovery-repeat.ndjson": 10,
    "net-zeek-ssh-session-cadence.ndjson": 5,
    "net-zeek-ssh-session-cadence-sustained.ndjson": 30,
    "net-zeek-dns-doh-non-standard-cardinality.ndjson": 10,
    "net-zeek-dns-crypto-mining-pool-cardinality.ndjson": 10,
}


def load_ndjson(path: Path):
    """Each line of a Kibana-import ndjson file is one standalone JSON rule object."""
    rules = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            rules.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise AssertionError(f"{path.name} line {i + 1} is not valid single-line JSON: {e}")
    return rules


def load_sigma_ids_and_status():
    ids, statuses = {}, {}
    for path in SIGMA_DIR.glob("*.yml"):
        rule = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        ids[path.name] = rule.get("id")
        statuses[path.name] = str(rule.get("status", "experimental")).lower()
    return ids, statuses


class ThresholdRuleTests(unittest.TestCase):
    def setUp(self):
        self.files = sorted(THRESHOLD_DIR.glob("*.ndjson"))
        self.assertGreaterEqual(
            len(self.files), 2,
            "expected at least the 1a/1b threshold companions in rules/elastic/threshold/")
        self.sigma_ids, self.sigma_statuses = load_sigma_ids_and_status()

    def test_files_are_single_line_ndjson(self):
        for path in self.files:
            lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            self.assertEqual(
                len(lines), 1,
                f"{path.name}: expected exactly one rule per file, one JSON object per "
                f"line (true NDJSON) — deploy_detections.sh's --form file=@... import "
                f"requires this, not pretty-printed multi-line JSON")

    def test_required_kibana_import_fields(self):
        for path in self.files:
            for rule in load_ndjson(path):
                for field in ("rule_id", "name", "type", "language", "query", "index",
                               "threshold", "risk_score", "severity", "tags", "threat",
                               "references"):
                    self.assertIn(field, rule, f"{path.name}: missing required field '{field}'")
                self.assertEqual(rule["type"], "threshold", f"{path.name}: type must be 'threshold'")
                self.assertIn(rule["language"], VALID_LANGUAGES, f"{path.name}: bad language")
                self.assertTrue(rule["query"].strip(), f"{path.name}: empty query")
                self.assertIsInstance(rule["index"], list)
                self.assertTrue(rule["index"], f"{path.name}: empty index list")
                self.assertIn(rule["severity"], VALID_SEVERITIES, f"{path.name}: bad severity")
                self.assertIsInstance(rule["risk_score"], int)
                self.assertTrue(0 <= rule["risk_score"] <= 100, f"{path.name}: risk_score out of range")
                self.assertTrue(rule["rule_id"].endswith("-threshold"),
                                 f"{path.name}: rule_id should end with '-threshold'")

    def test_threshold_block_is_well_formed(self):
        for path in self.files:
            for rule in load_ndjson(path):
                th = rule["threshold"]
                self.assertIsInstance(th.get("field"), list)
                self.assertTrue(th["field"], f"{path.name}: threshold.field must be non-empty")
                self.assertIsInstance(th.get("value"), int)
                self.assertGreaterEqual(th["value"], 1, f"{path.name}: threshold.value must be >=1")
                for card in th.get("cardinality", []):
                    self.assertIn("field", card)
                    self.assertIsInstance(card.get("value"), int)
                    self.assertGreaterEqual(card["value"], 1,
                                             f"{path.name}: cardinality.value must be >=1")

    def test_tags_and_threat_are_consistent(self):
        for path in self.files:
            for rule in load_ndjson(path):
                attack_tags = [t for t in rule["tags"] if ATTACK_TAG_RE.match(t)]
                self.assertTrue(attack_tags, f"{path.name}: no attack.tXXXX tag in 'tags'")
                # Every attack.tXXXX(.YYY) tag must be represented in the `threat` MITRE block.
                threat_ids = set()
                for entry in rule["threat"]:
                    for tech in entry.get("technique", []):
                        threat_ids.add(tech["id"].lower())
                        for sub in tech.get("subtechnique", []):
                            threat_ids.add(sub["id"].lower())
                for tag in attack_tags:
                    m = ATTACK_TAG_RE.match(tag)
                    tid = f"t{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
                    self.assertIn(tid, threat_ids,
                                   f"{path.name}: tag {tag} not represented in 'threat'")

    def test_pairs_with_an_experimental_sigma_logic_of_record(self):
        for path in self.files:
            for rule in load_ndjson(path):
                sigma_refs = [r for r in rule["references"] if r.startswith("rules/sigma/")]
                self.assertEqual(
                    len(sigma_refs), 1,
                    f"{path.name}: expected exactly one rules/sigma/ reference")
                sigma_name = Path(sigma_refs[0]).name
                self.assertIn(sigma_name, self.sigma_ids,
                               f"{path.name}: references missing Sigma file {sigma_name}")
                expected_sigma_id = rule["rule_id"][: -len("-threshold")]
                self.assertEqual(
                    self.sigma_ids[sigma_name], expected_sigma_id,
                    f"{path.name}: rule_id does not match {sigma_name}'s Sigma id "
                    f"(pairing broken — rule_id must be '<sigma-id>-threshold')")
                self.assertEqual(
                    self.sigma_statuses[sigma_name], "experimental",
                    f"{path.name}: paired Sigma rule {sigma_name} must stay "
                    f"status: experimental (the threshold rule is the deployed "
                    f"enforcement; a stable/test Sigma rule would ALSO deploy as a "
                    f"noisy per-event query rule)")

    def test_bruteforce_source_spray_excludes_all_four_ip_sentinels(self):
        # #370: without this exclusion, every local/console/service-account 4625
        # (no real network source - Winlogbeat emits one of these 4 placeholder
        # values) collapses into one shared bucket, so 6 distinct accounts
        # failing a local logon within the window fires a false severity:high
        # "password spray" alert. Regression guard for the exact gap #370's own
        # live-verification found in the issue's OWN suggested fix: a 3-value
        # exclusion (omitting "") still let the empty-string sentinel through.
        # Must match configs/logstash.conf's source.ip copy guard (#342)
        # exactly - see the cross-reference comment there.
        path = THRESHOLD_DIR / "auth-win-bruteforce-source-spray.ndjson"
        rule = load_ndjson(path)[0]
        # #393: query is now the exact `sigma convert` output (regenerated
        # from rules/sigma/auth_win_bruteforce_source_spray.yml, not
        # hand-typed) so Lucene special characters are backslash-escaped
        # (\- , \:\:) rather than quoted ("-" , "::") the way the original
        # hand-authored query represented them. Strip escaping backslashes
        # before checking for the raw sentinel value so this test doesn't
        # re-pin one particular escaping convention (that byte-for-byte
        # check already lives in test_live_fire.py's
        # ThresholdQueryMatchesCompiledSigmaTests, against the real
        # compiler output).
        unescaped_query = rule["query"].replace("\\", "")
        for sentinel in ("-", "0.0.0.0", "::", '""'):
            self.assertIn(sentinel, unescaped_query,
                           f"{path.name}: query must exclude IpAddress sentinel {sentinel!r}")

    def test_lookback_guarantees_full_containment_of_the_documented_detection_window(self):
        # #393 (security-auditor finding on the fix's own review): nothing
        # in this suite or test_live_fire.py's live-fire tests actually
        # proved the CORRECTED window is what's deployed, as opposed to
        # merely proving some window filtering exists -
        # test_threshold_events_outside_lookback_window_do_not_count
        # indexes events an hour old, outside both the old flawed window
        # and the new corrected one, so it can't distinguish them. A
        # silent revert to the old interval+1m convention (or a new 9th
        # file shipped with it) would pass every other test in both
        # files. This is the compile-time regression guard that closes
        # that gap: lookback >= interval + detection_window is asserted
        # as an exact equality, since every file in this corpus is tuned
        # to the mathematical minimum (zero slack) rather than shipped
        # with extra margin.
        for path in self.files:
            self.assertIn(
                path.name, DETECTION_WINDOW_MINUTES,
                f"{path.name}: no DETECTION_WINDOW_MINUTES entry — a new threshold "
                f"rule was added without teaching this test its documented "
                f"detection window, silently exempting it from the containment-"
                f"math regression guard")
            rule = load_ndjson(path)[0]
            lookback = _minutes(rule["from"])
            interval = _minutes(rule["interval"])
            meta_from = _minutes(rule["meta"]["from"])
            self.assertEqual(
                meta_from + interval, lookback,
                f"{path.name}: meta.from ({meta_from}m) + interval ({interval}m) != "
                f"from ({lookback}m) — meta.from (the Kibana UI's own display of the "
                f"rule's overlap) has drifted from the deployed from/interval pair")
            detection_window = DETECTION_WINDOW_MINUTES[path.name]
            self.assertEqual(
                interval + detection_window, lookback,
                f"{path.name}: from (now-{lookback}m) != interval ({interval}m) + "
                f"this rule's documented detection window ({detection_window}m) — "
                f"a real sliding window of that width is no longer GUARANTEED full "
                f"containment in one evaluation (#393's own fix), only partially "
                f"contained depending on campaign phase, silently reintroducing the "
                f"gap this issue closed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
