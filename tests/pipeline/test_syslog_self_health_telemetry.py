#!/usr/bin/env python3
"""
#556: the capture host's own syslog was never shipped to Elasticsearch — a
30-day event.dataset aggregation over the live indices returned 100%
zeek.*, so no unit-level failure (a `failed` systemd unit, a CA-fingerprint
mismatch — configs/systemd/*.service each carry a `[FATAL]` line for this)
was ever observable in the SIEM. Of the 145 rules in rules/ at the time,
none covered SOC self-integrity — the 6 existing T1562.001 rules are all
`product: windows`.

Static structure tests for the three pieces this fix touches, no live
Logstash/Filebeat needed — matching this directory's existing convention
(see test_auditd_execve_telemetry.py, test_mac_correlation.py):

  1. configs/network/filebeat.yml — a new filestream input for
     /var/log/syslog (the file this repo's capture host actually runs,
     distinct from configs/endpoint/filebeat_endpoint.yml's own pre-
     existing syslog input, which ships to a different pipeline instance).
  2. configs/logstash.conf — event.module:"system" + event.dataset:"syslog"
     stamping for that input's path, distinct from the existing auth.log/
     secure branch (same event.module, no event.dataset there) so the two
     new Sigma rules below can't also match ordinary SSH auth traffic.
  3. rules/sigma/system_lnx_self_health_unit_failed.yml and
     rules/sigma/system_lnx_ca_fingerprint_mismatch.yml — logic coverage
     lives in tests/detections/test_sigma_detections.py via
     tests/detections/fixtures.json; this file only asserts the two rules
     exist, target the new dataset, and stay off the internal-only allow-
     list (a rule matching every failing unit on the host would be a worse
     signal-to-noise ratio than no rule at all).

Run:  python tests/pipeline/test_syslog_self_health_telemetry.py
      (or: pytest tests/pipeline)
"""

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
FILEBEAT_NETWORK = (ROOT / "configs" / "network" / "filebeat.yml").read_text(encoding="utf-8")
LOGSTASH_CONF = (ROOT / "configs" / "logstash.conf").read_text(encoding="utf-8")
SIGMA_DIR = ROOT / "rules" / "sigma"
UNIT_FAILED_RULE = SIGMA_DIR / "system_lnx_self_health_unit_failed.yml"
CA_MISMATCH_RULE = SIGMA_DIR / "system_lnx_ca_fingerprint_mismatch.yml"
VERIFY_CA_SCRIPT = (ROOT / "scripts" / "setup" / "verify_ca_fingerprint.sh").read_text(encoding="utf-8")


class FilebeatSyslogInputTests(unittest.TestCase):
    def test_capture_host_syslog_input_exists(self):
        docs = list(yaml.safe_load_all(FILEBEAT_NETWORK))
        self.assertEqual(1, len(docs), "expected a single YAML document")
        inputs = docs[0]["filebeat.inputs"]
        syslog_inputs = [i for i in inputs if i.get("id") == "capture-host-syslog"]
        self.assertEqual(1, len(syslog_inputs), "expected exactly one capture-host-syslog input")
        self.assertIn("/var/log/syslog", syslog_inputs[0]["paths"])
        self.assertTrue(syslog_inputs[0].get("enabled"))

    def test_syslog_input_uses_fingerprint_identity(self):
        """Same reasoning as the Zeek/Suricata inputs in this file: a
        content-blind native (inode/offset) identity risks missing a
        same-size rewrite (e.g. logrotate's copytruncate mode)."""
        docs = list(yaml.safe_load_all(FILEBEAT_NETWORK))
        syslog_input = next(i for i in docs[0]["filebeat.inputs"] if i.get("id") == "capture-host-syslog")
        self.assertTrue(syslog_input.get("prospector.scanner.fingerprint.enabled"))
        self.assertIn("file_identity.fingerprint", syslog_input)


class LogstashSyslogBranchTests(unittest.TestCase):
    def test_syslog_path_is_stamped_system_module_syslog_dataset(self):
        self.assertRegex(
            LOGSTASH_CONF,
            r'\[log\]\[file\]\[path\]\s*=~\s*/\\/syslog\$/\s*\{\s*'
            r'(?:#[^\n]*\n\s*)*'
            r'mutate\s*\{\s*add_field\s*=>\s*\{\s*"\[event\]\[module\]"\s*=>\s*"system"\s*'
            r'"\[event\]\[dataset\]"\s*=>\s*"syslog"',
            "expected an else-if branch stamping event.module=system + "
            "event.dataset=syslog for a /var/log/syslog-sourced path")

    def test_syslog_branch_lives_in_the_endpoint_logs_category(self):
        """Must be inside the same `if "endpoint_logs" in [tags]` block as
        the auth.log/secure and audit.log branches — Filebeat's own :5044
        beats output is what tags endpoint_logs, and network/filebeat.yml's
        new input ships over that same port."""
        idx_category = LOGSTASH_CONF.index('if "endpoint_logs" in [tags]')
        idx_syslog_branch = LOGSTASH_CONF.index('=~ /\\/syslog$/')
        # The next top-level Category comment after Category 2 bounds the block.
        idx_next_category = LOGSTASH_CONF.index("Category 2.5", idx_category)
        self.assertLess(idx_category, idx_syslog_branch)
        self.assertLess(idx_syslog_branch, idx_next_category)

    def test_syslog_branch_does_not_collide_with_auth_log_branch(self):
        """auth.log/secure's own branch never sets event.dataset — asserting
        that stays true is what keeps the two Sigma rules below from also
        matching ordinary SSH auth traffic."""
        auth_branch = LOGSTASH_CONF[
            LOGSTASH_CONF.index(r"/(auth\.log|secure)$/"):
            LOGSTASH_CONF.index(r"/audit\/audit\.log$/")
        ]
        self.assertNotIn("[event][dataset]", auth_branch)


class SelfHealthRuleExistenceTests(unittest.TestCase):
    def test_both_rules_exist(self):
        self.assertTrue(UNIT_FAILED_RULE.is_file())
        self.assertTrue(CA_MISMATCH_RULE.is_file())

    def test_both_rules_target_the_new_syslog_dataset(self):
        for path in (UNIT_FAILED_RULE, CA_MISMATCH_RULE):
            with self.subTest(rule=path.name):
                rule = yaml.safe_load(path.read_text(encoding="utf-8"))
                selections = [v for k, v in rule["detection"].items() if k != "condition"]
                self.assertTrue(
                    any(sel.get("event.dataset") == "syslog" for sel in selections),
                    f"{path.name} does not select on event.dataset:syslog")

    def test_both_rules_carry_the_t1562_001_tag(self):
        """The issue's own framing: the 6 pre-existing T1562.001 rules are
        all product:windows — these are meant to be the Linux counterpart."""
        for path in (UNIT_FAILED_RULE, CA_MISMATCH_RULE):
            with self.subTest(rule=path.name):
                rule = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertIn("attack.t1562.001", rule.get("tags", []))

    def test_unit_failed_rule_scopes_to_a_named_allowlist(self):
        """A rule matching every failing unit on the host, not just this
        SOC's own units, would be a worse signal-to-noise ratio than no
        rule at all — see the rule's own description for the maintenance
        trade-off this makes."""
        rule = yaml.safe_load(UNIT_FAILED_RULE.read_text(encoding="utf-8"))
        unit_selection = rule["detection"]["selection_unit"]
        targets = unit_selection.get("message|contains")
        self.assertIsInstance(targets, list)
        self.assertIn("slo-metrics.service", targets)
        self.assertGreaterEqual(len(targets), 5)

    def test_ca_mismatch_rule_matches_the_real_script_output(self):
        """The rule's true_positive fixture is only as good as the string
        it's built from actually shipping — pin against the live script."""
        rule = yaml.safe_load(CA_MISMATCH_RULE.read_text(encoding="utf-8"))
        target = rule["detection"]["selection_fatal"]["message|contains"]
        self.assertIn(target, VERIFY_CA_SCRIPT,
                      "rule's matched string no longer appears verbatim in "
                      "verify_ca_fingerprint.sh — the two have drifted")


if __name__ == "__main__":
    unittest.main(verbosity=2)
