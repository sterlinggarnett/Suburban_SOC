#!/usr/bin/env python3
"""
#442: Linux process-execution (execve) telemetry — the prerequisite for
#441 Part A's 5 proc_creation_lnx_* Sigma rules. Before this fix,
configs/endpoint/filebeat_endpoint.yml collected only /var/log/auth.log and
/var/log/secure, and configs/logstash.conf's endpoint_logs branch stamped
event.module only for [winlog] or a path matching auth.log|secure — a Linux
exec event would arrive completely unstamped and match no logsource at all.
linux/process_creation was an empty logsource against 51
windows/process_creation rules.

Static structure tests for the four pieces this fix touches:

  1. configs/endpoint/filebeat_endpoint.yml — a new filestream input for
     /var/log/audit/audit.log.
  2. configs/logstash.conf — event.module:"auditd" stamping, and a new
     Component 4 branch that correlates auditd's SYSCALL+EXECVE record pair
     (via Logstash's `aggregate` filter, keyed on the shared audit id) into
     process.executable/process.args/process.pid/process.parent.pid/
     user.id/user.name, deliberately WITHOUT process.parent.name (auditd's
     SYSCALL record only gives a PID number for the parent, not a name, and
     this pipeline has no PID->exe-name process-tree cache — mapping a
     field nothing produces is this repo's own #217 anti-pattern).
  3. configs/detections/suburban-soc-ecs.yml — a field-mapping-auditd-
     process-creation pySigma transformation scoped to
     logsource:{product:linux, category:process_creation}, mapping
     Image/CommandLine/User only (not ParentImage/ParentCommandLine, for
     the same reason as #2).
  4. configs/elasticsearch/logstash-security-template.json — explicit
     process.pid/process.parent.pid (long) and user.id (keyword) mappings,
     so these don't fall to Elasticsearch's own default dynamic type
     inference (the #288-class "decided by whichever document creates the
     field first" risk).

Pure stdlib, static text/regex assertions against the real config files —
no live Logstash/auditd, matching this directory's existing convention (see
test_mac_correlation.py, test_framework_enrichment.py). None of this is
exercised against a live auditd stream in this environment (no reachable
Docker daemon / Linux audit host) — confirm the real field order/shape
auditd emits on a target kernel before relying on the grok patterns this
locks in, in production.

Run:  python tests/pipeline/test_auditd_execve_telemetry.py
      (or: pytest tests/pipeline)
"""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOGSTASH_CONF = (ROOT / "configs" / "logstash.conf").read_text(encoding="utf-8")
FILEBEAT_ENDPOINT = (ROOT / "configs" / "endpoint" / "filebeat_endpoint.yml").read_text(encoding="utf-8")
ECS_PIPELINE = (ROOT / "configs" / "detections" / "suburban-soc-ecs.yml").read_text(encoding="utf-8")
TEMPLATE_PATH = ROOT / "configs" / "elasticsearch" / "logstash-security-template.json"
AUDIT_RULES_PATH = ROOT / "configs" / "endpoint" / "audit.rules"


def _auditd_block(text: str) -> str:
    """Isolate Component 4's body (between its own header and Category
    2.5's), so a match can't be accidentally satisfied by the Sysmon/sshd
    blocks earlier in the same endpoint_logs scope — the exact #217-class
    mistake this test suite exists to catch, so the test itself must not
    repeat it."""
    start = text.index("Component 4: Linux process-execution")
    end = text.index("Category 2.5", start)
    return text[start:end]


class FilebeatInputTests(unittest.TestCase):
    def test_audit_log_filestream_input_exists(self):
        self.assertIn("id: audit-logs", FILEBEAT_ENDPOINT)
        self.assertIn("/var/log/audit/audit.log", FILEBEAT_ENDPOINT)

    def test_audit_log_input_is_a_filestream_type(self):
        idx = FILEBEAT_ENDPOINT.index("id: audit-logs")
        preceding = FILEBEAT_ENDPOINT[:idx]
        # The nearest "- type: <x>" line above "id: audit-logs" must be
        # filestream, same as every other input in this file.
        last_type_pos = preceding.rfind("- type:")
        self.assertGreater(last_type_pos, -1)
        self.assertIn("- type: filestream", preceding[last_type_pos:last_type_pos + 30])


class EventModuleStampingTests(unittest.TestCase):
    def test_auditd_path_stamps_event_module_auditd(self):
        self.assertIn(r'audit\/audit\.log$/ {', LOGSTASH_CONF)
        # Anchored + escaped, same #230/#243 lesson this file's own
        # auth.log/secure condition already applies (a bare "audit.log"
        # would wildcard-match e.g. "myauditXlog").
        idx = LOGSTASH_CONF.index(r'audit\/audit\.log$/ {')
        nearby = LOGSTASH_CONF[idx:idx + 200]
        self.assertIn('"[event][module]" => "auditd"', nearby)


class AuditdCorrelationBlockTests(unittest.TestCase):
    def test_block_is_gated_on_the_audit_log_path(self):
        block = _auditd_block(LOGSTASH_CONF)
        self.assertIn(r'if [log][file][path] =~ /audit\/audit\.log$/ {', block)

    def test_header_grok_extracts_record_type_and_audit_id(self):
        block = _auditd_block(LOGSTASH_CONF)
        self.assertIn("[audit][record_type]", block)
        self.assertIn("[audit][id]", block)

    def test_syscall_branch_is_correlation_only_and_drops(self):
        block = _auditd_block(LOGSTASH_CONF)
        syscall_start = block.index('[audit][record_type] == "SYSCALL"')
        execve_start = block.index('[audit][record_type] == "EXECVE"')
        syscall_block = block[syscall_start:execve_start]
        self.assertIn("aggregate {", syscall_block)
        self.assertIn('task_id => "%{[audit][id]}"', syscall_block)
        self.assertIn("drop {}", syscall_block)

    def test_execve_branch_extracts_args_via_quote_aware_regex_not_kv(self):
        # a plain `kv` filter's default whitespace-token splitting would
        # break an argv element containing embedded spaces (e.g.
        # `bash -c "<full pasted command>"`) apart mid-value.
        block = _auditd_block(LOGSTASH_CONF)
        execve_start = block.index('[audit][record_type] == "EXECVE"')
        else_start = block.index("# PROCTITLE/CWD/PATH/other records", execve_start)
        execve_block = block[execve_start:else_start]
        self.assertNotIn("kv {", execve_block)
        self.assertIn("ruby {", execve_block)
        self.assertIn('a\\d+="', execve_block)
        self.assertIn('[process][args]', execve_block)

    def test_execve_branch_correlates_via_aggregate_keyed_on_audit_id(self):
        block = _auditd_block(LOGSTASH_CONF)
        execve_start = block.index('[audit][record_type] == "EXECVE"')
        else_start = block.index("# PROCTITLE/CWD/PATH/other records", execve_start)
        execve_block = block[execve_start:else_start]
        self.assertIn("aggregate {", execve_block)
        self.assertIn('task_id => "%{[audit][id]}"', execve_block)
        self.assertIn("end_of_task => true", execve_block)

    def test_execve_branch_populates_process_and_user_fields(self):
        block = _auditd_block(LOGSTASH_CONF)
        execve_start = block.index('[audit][record_type] == "EXECVE"')
        else_start = block.index("# PROCTITLE/CWD/PATH/other records", execve_start)
        execve_block = block[execve_start:else_start]
        for field in (
            "[process][executable]",
            "[process][pid]",
            "[process][parent][pid]",
            "[user][id]",
            "[user][name]",
        ):
            self.assertIn(field, execve_block)

    def test_does_not_populate_process_parent_name(self):
        # #217-shape guard: auditd's SYSCALL record only gives ppid (a PID
        # NUMBER), and this pipeline has no PID->exe-name process-tree
        # cache — the whole Component 4 block must never claim a
        # process.parent.name mapping nothing actually produces.
        block = _auditd_block(LOGSTASH_CONF)
        self.assertNotIn("[process][parent][name]", block)

    def test_discloses_the_pipeline_workers_correlation_caveat(self):
        # `aggregate` only correlates correctly when every event sharing a
        # task_id lands on the same pipeline worker — unsafe under
        # Logstash's default multi-worker config, which
        # configs/logstash.yml does not override. Must be disclosed, not
        # silently assumed safe, matching this repo's convention for every
        # other environment-unverifiable claim.
        block = _auditd_block(LOGSTASH_CONF)
        self.assertIn("OPERATIONAL CAVEAT", block)
        self.assertIn("pipeline.workers", block)

    def test_event_dataset_is_only_stamped_when_correlation_succeeded(self):
        # A guard against the #217 shape from the OTHER direction: an
        # EXECVE record whose SYSCALL sibling never arrived/matched/timed
        # out of the aggregate map must not still look like a real,
        # matchable process-execution record downstream.
        block = _auditd_block(LOGSTASH_CONF)
        execve_start = block.index('[audit][record_type] == "EXECVE"')
        else_start = block.index("# PROCTITLE/CWD/PATH/other records", execve_start)
        execve_block = block[execve_start:else_start]
        guard_pos = execve_block.find("if [process][executable] {")
        dataset_pos = execve_block.find('"[event][dataset]" => "auditd.execve"')
        incomplete_tag_pos = execve_block.find("_audit_correlation_incomplete")
        self.assertGreater(guard_pos, -1)
        self.assertGreater(dataset_pos, -1)
        self.assertGreater(incomplete_tag_pos, -1)
        self.assertLess(guard_pos, dataset_pos, "event.dataset stamp must be inside the process.executable guard")

    def test_other_record_types_are_dropped(self):
        block = _auditd_block(LOGSTASH_CONF)
        # The trailing catch-all else branch (PROCTITLE/CWD/PATH/etc.)
        self.assertIn("} else {", block)
        self.assertEqual(block.count("drop {}"), 2, "expected exactly 2 drop {} — the SYSCALL branch and the catch-all else")


class EcsPipelineMappingTests(unittest.TestCase):
    def test_auditd_process_creation_transformation_exists(self):
        self.assertIn("field-mapping-auditd-process-creation", ECS_PIPELINE)

    def _transformation_block(self) -> str:
        start = ECS_PIPELINE.index("id: field-mapping-auditd-process-creation")
        end = ECS_PIPELINE.index("\n\n", start)
        return ECS_PIPELINE[start:end]

    def test_scoped_to_linux_process_creation_logsource(self):
        block = self._transformation_block()
        self.assertIn("product: linux", block)
        self.assertIn("category: process_creation", block)

    def test_maps_image_commandline_user(self):
        block = self._transformation_block()
        self.assertIn("Image: process.executable", block)
        self.assertIn("CommandLine: process.args", block)
        self.assertIn("User: user.name", block)

    def test_does_not_map_parent_fields(self):
        # Same #217-shape reasoning as the logstash.conf test above — the
        # pipeline never populates process.parent.name/args for this
        # logsource, so the pySigma mapping must not claim it does.
        block = self._transformation_block()
        self.assertNotIn("ParentImage", block)
        self.assertNotIn("ParentCommandLine", block)


class TemplateMappingTests(unittest.TestCase):
    def setUp(self):
        self.template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        self.properties = self.template["template"]["mappings"]["properties"]

    def test_process_pid_is_explicit_long(self):
        self.assertEqual(self.properties["process"]["properties"]["pid"], {"type": "long"})

    def test_process_parent_pid_is_explicit_long(self):
        parent = self.properties["process"]["properties"]["parent"]["properties"]
        self.assertEqual(parent["pid"], {"type": "long"})

    def test_user_id_is_explicit_keyword_with_ignore_above(self):
        # #337's own finding (this template's _meta.description): an
        # explicit keyword property with NO ignore_above gets
        # Elasticsearch's unbounded default (2147483647), not
        # strings_as_keyword's 1024 — must be set explicitly, not omitted.
        user_id = self.properties["user"]["properties"]["id"]
        self.assertEqual(user_id["type"], "keyword")
        self.assertIn("ignore_above", user_id)

    def test_process_args_and_user_name_already_covered_no_new_ceiling_needed(self):
        # process.executable/process.args/user.name are produced by this
        # new source too, but were already explicitly mapped (Sysmon) —
        # confirms this fix didn't need to touch them.
        self.assertEqual(self.properties["process"]["properties"]["args"]["ignore_above"], 32766)
        self.assertEqual(self.properties["user"]["properties"]["name"]["ignore_above"], 32766)


class ByteClampCoverageTests(unittest.TestCase):
    def test_process_args_and_user_name_already_in_the_byte_clamp_hash(self):
        # The two 32766-ceiling fields this new source produces
        # (process.args, user.name) must already have a long_fields entry
        # in configs/logstash.conf from #263/#337 — this locks in that
        # #442 didn't need to (and didn't) add a new one, since neither
        # field's ceiling changed.
        long_fields_start = LOGSTASH_CONF.index("long_fields = {")
        long_fields_end = LOGSTASH_CONF.index("\n      }", long_fields_start)
        block = LOGSTASH_CONF[long_fields_start:long_fields_end]
        self.assertIn('"[process][args]" => ["process.args", ceiling]', block)
        self.assertIn('"[user][name]" => ["user.name", ceiling]', block)


class AuditRulesFileTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(AUDIT_RULES_PATH.exists(), f"missing {AUDIT_RULES_PATH}")
        self.rules = AUDIT_RULES_PATH.read_text(encoding="utf-8")

    def test_watches_execve_for_real_users(self):
        self.assertIn("-S execve -F auid>=1000", self.rules)
        # Excludes the "auid unset" sentinel (4294967295), not just >=1000.
        self.assertIn("auid!=4294967295", self.rules)

    def test_watches_execve_for_root_privileged_regardless_of_auid(self):
        self.assertIn("-S execve -F euid=0", self.rules)

    def test_covers_both_64_and_32_bit_syscall_tables(self):
        self.assertIn("arch=b64", self.rules)
        self.assertIn("arch=b32", self.rules)

    def test_documents_the_enriched_log_format_dependency(self):
        # user.name resolution (auid -> name) depends on auditd.conf's
        # log_format=ENRICHED — must be documented, not left implicit.
        self.assertIn("log_format = ENRICHED", self.rules)


if __name__ == "__main__":
    unittest.main()
