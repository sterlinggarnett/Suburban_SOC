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

_TECH_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_ID_ASSIGN_RE = re.compile(r"\[threat\]\[technique\]\[id\]\"\s*=>\s*\"([^\"]+)\"")
_TACTIC_ASSIGN_RE = re.compile(r"\[threat\]\[tactic\]\[name\]\"\s*=>")
_NIST_ASSIGN_RE = re.compile(r"\[nist\]\[function\]\"\s*=>")


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
