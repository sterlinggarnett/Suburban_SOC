#!/usr/bin/env python3
"""
#444: Suricata eve.json -> ECS ingest — the second step of M23, landing
alongside #443's sensor deployment. Before this fix, configs/network/
filebeat.yml shipped nothing from Suricata, and configs/logstash.conf had
no branch mapping alert.signature/alert.signature_id/alert.category to ECS
rule.*/threat.technique.*, nor any tenant-stamping/event.module dimension
for the source.

Static structure tests for the three pieces this fix touches:

  1. configs/network/filebeat.yml — a new filestream input for
     /storage/PCAP/suricata/eve.json (+ its rotated siblings).
  2. configs/logstash.conf — a new top-level "Category 0b" branch (gated
     purely on [log][file][path], same pattern as Category 0's Zeek
     branch — NOT nested inside "endpoint_logs" in [tags], since that tag
     is stamped generically by the shared Beats :5044 input for every
     source): event.module:"suricata" unconditionally, event.dataset per
     eve.json record type, and alert.* -> rule.*/threat.technique.* only
     for event_type:"alert" records, gated on alert.signature actually
     being present (the #217-shape discipline #442's auditd branch
     established) via bracket notation throughout (#328's dotted-string
     footgun, named explicitly in #444's own issue text).
  3. configs/elasticsearch/logstash-security-template.json — explicit
     rule.name/rule.id/rule.category (keyword, ignore_above:1024)
     mappings, so these don't fall to Elasticsearch's own default dynamic
     type inference (the #288/#337-class risk).

Pure stdlib, static text/regex assertions against the real config files —
no live Logstash/Suricata, matching this directory's existing convention
(see test_auditd_execve_telemetry.py, test_mac_correlation.py). NOT
exercised against a real eve.json document in the environment this was
authored in — no live capture host to produce one (#443's own disclosed
gap) — structural/static tests only against Suricata's documented eve.json
schema shape.

Run:  python tests/pipeline/test_suricata_eve_telemetry.py
      (or: pytest tests/pipeline)
"""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOGSTASH_CONF = (ROOT / "configs" / "logstash.conf").read_text(encoding="utf-8")
FILEBEAT_NETWORK = (ROOT / "configs" / "network" / "filebeat.yml").read_text(encoding="utf-8")
TEMPLATE_PATH = ROOT / "configs" / "elasticsearch" / "logstash-security-template.json"


def _suricata_block(text: str) -> str:
    """Isolate Category 0b's body (between its own header and Category 1's),
    so a match can't be accidentally satisfied by the Zeek/auditd blocks
    elsewhere in this file — the same #217-class mistake
    test_auditd_execve_telemetry.py's own _auditd_block guards against."""
    start = text.index("Category 0b: Suricata eve.json")
    end = text.index("Category 1: Network & Application Telemetry", start)
    return text[start:end]


class FilebeatInputTests(unittest.TestCase):
    def test_suricata_eve_filestream_input_exists(self):
        self.assertIn("id: suricata-eve", FILEBEAT_NETWORK)
        self.assertIn("/storage/PCAP/suricata/eve.json", FILEBEAT_NETWORK)

    def test_suricata_eve_input_is_a_filestream_type(self):
        idx = FILEBEAT_NETWORK.index("id: suricata-eve")
        preceding = FILEBEAT_NETWORK[:idx]
        last_type_pos = preceding.rfind("- type:")
        self.assertGreater(last_type_pos, -1)
        self.assertIn("- type: filestream", preceding[last_type_pos:last_type_pos + 30])

    def test_covers_rotated_eve_json_files_too(self):
        idx = FILEBEAT_NETWORK.index("id: suricata-eve")
        block = FILEBEAT_NETWORK[idx:idx + 600]
        self.assertIn("eve.json.*", block)


class Category0bGatingTests(unittest.TestCase):
    def test_block_is_gated_purely_on_log_file_path_not_endpoint_logs_tag(self):
        block = _suricata_block(LOGSTASH_CONF)
        gate_line = 'if [log][file][path] =~ /eve\\.json/ {'
        self.assertIn(gate_line, block)
        # Must not be nested inside the "endpoint_logs" in [tags] Category 2
        # branch — that tag is stamped generically for every Beats-shipped
        # source, so gating there is unnecessary and would make this block
        # order-dependent on Category 2's own position in the file. Checked
        # only in the code from the gate line onward, since this block's
        # own header comment legitimately mentions the tag in prose (why
        # it's NOT used) without that being a real condition.
        code_from_gate = block[block.index(gate_line):]
        self.assertNotIn('"endpoint_logs" in [tags]', code_from_gate)


class EventModuleAndDatasetStampingTests(unittest.TestCase):
    def test_event_module_stamped_unconditionally(self):
        block = _suricata_block(LOGSTASH_CONF)
        self.assertIn('"[event][module]" => "suricata"', block)

    def test_event_dataset_derived_from_event_type_field(self):
        block = _suricata_block(LOGSTASH_CONF)
        self.assertIn('"[event][dataset]" => "suricata.%{[event_type]}"', block)

    def test_missing_event_type_is_tagged_not_silently_dropped(self):
        block = _suricata_block(LOGSTASH_CONF)
        self.assertIn("_suricata_event_type_missing", block)


class AlertMappingTests(unittest.TestCase):
    def _alert_block(self) -> str:
        block = _suricata_block(LOGSTASH_CONF)
        start = block.index('[event_type] == "alert"')
        return block[start:]

    def test_alert_fields_mapped_via_bracket_notation(self):
        # #328's dotted-string footgun, named explicitly in #444's own
        # issue text — a dotted "alert.signature" target would create a
        # FLAT field, not descend into [alert][signature].
        block = self._alert_block()
        self.assertIn('"[alert][signature]"    => "[rule][name]"', block)
        self.assertIn('"[alert][signature_id]" => "[rule][id]"', block)
        self.assertIn('"[alert][category]"     => "[rule][category]"', block)
        # No dotted-string form anywhere in this block.
        self.assertNotIn('"alert.signature"', block)
        self.assertNotIn('"rule.name"', block)

    def test_attack_technique_metadata_mapped_to_threat_technique_id(self):
        block = self._alert_block()
        self.assertIn(
            '"[alert][metadata][attack_technique]" => "[threat][technique][id]"', block
        )

    def test_rule_mapping_gated_on_alert_signature_presence(self):
        # #217-shape guard, same discipline as #442's auditd
        # event.dataset gate: never claim rule.* content that isn't
        # actually there.
        block = self._alert_block()
        guard_pos = block.find("if [alert][signature] {")
        rename_pos = block.find('"[alert][signature]"    => "[rule][name]"')
        incomplete_tag_pos = block.find("_suricata_alert_incomplete")
        self.assertGreater(guard_pos, -1)
        self.assertGreater(rename_pos, -1)
        self.assertGreater(incomplete_tag_pos, -1)
        self.assertLess(guard_pos, rename_pos,
                         "rule.* rename must be inside the alert.signature presence guard")

    def test_non_alert_event_types_are_not_run_through_alert_mapping(self):
        # The alert.* -> rule.* rename must be nested under the
        # event_type=="alert" condition, not applied unconditionally to
        # every eve.json record (flow/http/dns/tls records have no
        # alert.* fields to rename in the first place).
        block = _suricata_block(LOGSTASH_CONF)
        alert_cond_pos = block.index('[event_type] == "alert"')
        rename_pos = block.index('"[alert][signature]"    => "[rule][name]"')
        self.assertLess(alert_cond_pos, rename_pos)


class NoSoarWiringYetTests(unittest.TestCase):
    def test_suricata_alerts_not_added_to_soar_trigger_condition(self):
        # #444's own explicit either-is-defensible policy choice, decided
        # for this stage as dashboard-only (see Category 0b's own trailing
        # comment) — Category 6's SOAR trigger condition must not
        # reference rule.name/suricata in this same change.
        # Anchored to the real section header text, not a bare "Category 6"
        # substring — Category 0b's own comment above mentions "Category 6"
        # in prose (pointing at this same trigger, to explain it's NOT
        # wired in), and that mention sits much earlier in the file than
        # the real header.
        idx = LOGSTASH_CONF.index("Category 6: SOAR webhook signing")
        # Generous window after the real header for its own trigger
        # condition rather than the whole file.
        soar_window = LOGSTASH_CONF[idx:idx + 4000]
        trigger_start = soar_window.index('if ([event][dataset] == "zeek.intel"')
        trigger_line_end = soar_window.index("\n", trigger_start)
        trigger_condition = soar_window[trigger_start:trigger_line_end]
        self.assertNotIn("suricata", trigger_condition)
        self.assertNotIn("[rule][name]", trigger_condition)


class TemplateMappingTests(unittest.TestCase):
    def setUp(self):
        self.template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        self.properties = self.template["template"]["mappings"]["properties"]

    def test_rule_object_exists(self):
        self.assertIn("rule", self.properties)

    def test_rule_fields_are_explicit_keyword_with_ignore_above(self):
        # Same #337 discipline as user.id: an explicit keyword property
        # with no ignore_above gets Elasticsearch's unbounded default, not
        # strings_as_keyword's 1024 — must be set explicitly.
        rule_props = self.properties["rule"]["properties"]
        for field in ("name", "id", "category"):
            self.assertEqual(rule_props[field]["type"], "keyword")
            self.assertEqual(rule_props[field]["ignore_above"], 1024)

    def test_rule_id_is_keyword_not_numeric(self):
        # Matches ECS's own rule.id convention (some sources use
        # non-numeric identifiers) even though Suricata's signature_id is
        # itself always numeric.
        self.assertEqual(self.properties["rule"]["properties"]["id"]["type"], "keyword")


class NoByteClampNeededTests(unittest.TestCase):
    def test_rule_fields_not_in_long_fields_byte_clamp_hash(self):
        # None of the 3 new fields were raised to ignore_above:32766, so
        # none needs a configs/logstash.conf long_fields clamp entry —
        # locks in that this fix didn't need one (rule content is
        # maintainer-authored, not attacker-controlled traffic content).
        long_fields_idx = LOGSTASH_CONF.index("long_fields")
        long_fields_block = LOGSTASH_CONF[long_fields_idx:long_fields_idx + 2000]
        self.assertNotIn('"[rule][name]"', long_fields_block)
        self.assertNotIn('"[rule][id]"', long_fields_block)
        self.assertNotIn('"[rule][category]"', long_fields_block)


if __name__ == "__main__":
    unittest.main()
