#!/usr/bin/env python3
"""
#286: MAC-based device quarantine — static structure tests for the two
stacked breaks the issue diagnosed:

  1. configs/logstash.conf's Category 0 branch (the one real Filebeat-
     shipped Zeek data reaches) never renamed orig_l2_addr/resp_l2_addr to
     source.mac/destination.mac — only the dead network_logs branch did.
  2. Even with that rename, the SOAR containment webhook body is built from
     a zeek.intel event, not conn.log — and mac-logging only ever writes
     L2 addresses to conn.log. Nothing joined the two by `uid`.

Plus the two prerequisites the issue's "done" criteria list: mac-logging
actually loaded on the real capture path (configs/intel/config.zeek, not
the dead configs/zeek/local.zeek), and SOP-012's data inventory updated to
list MAC addresses as personal data this pipeline now collects.

Pure stdlib, static text/regex assertions against the real config files —
no live Logstash/Zeek/Elasticsearch, matching this directory's existing
convention (see test_framework_enrichment.py, test_grok_parse_failures.py).
A syntax-level Logstash config validation (`logstash --config.test_and_exit`)
was not available in the environment this was written in and should be run
before deploying this change (noted in the PR).

Run:  python tests/pipeline/test_mac_correlation.py  (or: pytest tests/pipeline)
"""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOGSTASH_CONF = (ROOT / "configs" / "logstash.conf").read_text(encoding="utf-8")
CONFIG_ZEEK = (ROOT / "configs" / "intel" / "config.zeek").read_text(encoding="utf-8")
LOCAL_ZEEK = (ROOT / "configs" / "zeek" / "local.zeek").read_text(encoding="utf-8")
SOP_012 = (ROOT / "docs" / "SOP-012-privacy-data-handling.md").read_text(encoding="utf-8")
DOCKER_COMPOSE = (ROOT / "scripts" / "setup" / "docker-compose.yml").read_text(encoding="utf-8")
ENRICH_ROLE_PATH = ROOT / "configs" / "elasticsearch" / "roles" / "logstash_enrich_reader.json"


def _category_0_block(text: str) -> str:
    """Isolate Category 0's body (between its own header and Category 1's),
    so a match against the LIVE branch can't be satisfied by the dead
    network_logs branch further down the same file — the exact bug #286
    is about, so the test itself must not repeat it."""
    start = text.index("Category 0")
    end = text.index("Category 1")
    return text[start:end]


def _zeek_intel_block(text: str) -> str:
    """Isolate the `if [event][dataset] == "zeek.intel" {` filter branch.

    code-reviewer round 2 Should-Fix: this used to slice through to
    "Category 1", ~30 lines past the branch's own closing brace — silently
    absorbing the unrelated #177 ntfy-masking and user_agent-stripping
    blocks that follow it in the same Category 0 scope. No assertion
    happened to collide with that extra text, but a future one could and
    would then be testing the wrong branch without any indication. Ends at
    the #177 comment instead — the very next thing after this branch's own
    closing brace — a tight, real boundary rather than a coincidentally-
    safe distant one."""
    marker = 'if [event][dataset] == "zeek.intel" {'
    start = text.index(marker)
    end = text.index("# #177:", start)
    return text[start:end]


class MacRenameTests(unittest.TestCase):
    def test_category_0_renames_orig_l2_addr_to_source_mac(self):
        block = _category_0_block(LOGSTASH_CONF)
        self.assertIn('"[orig_l2_addr]" => "[source][mac]"', block)

    def test_category_0_renames_resp_l2_addr_to_destination_mac(self):
        block = _category_0_block(LOGSTASH_CONF)
        self.assertIn('"[resp_l2_addr]" => "[destination][mac]"', block)


class UidCorrelationTests(unittest.TestCase):
    def test_zeek_intel_branch_queries_by_uid(self):
        block = _zeek_intel_block(LOGSTASH_CONF)
        self.assertIn("elasticsearch {", block)
        self.assertIn("uid:%{[uid]}", block)

    def test_correlation_query_is_scoped_to_conn_log_events(self):
        # Must not match against arbitrary event.dataset values sharing a
        # uid coincidentally (Zeek uids are effectively unique, but the
        # query should still be explicit about what it's joining against).
        block = _zeek_intel_block(LOGSTASH_CONF)
        self.assertIn("event.dataset:zeek.conn", block)

    def test_correlation_pulls_only_source_mac_not_destination(self):
        # security-auditor round 1 HIGH: destination.mac has zero consumers
        # (over-collection) and, more importantly, populating it would be a
        # step toward acting on the wrong device — containment always
        # targets source.ip (the external attacker), never the internal
        # victim. Only source.mac may be pulled.
        block = _zeek_intel_block(LOGSTASH_CONF)
        self.assertIn('"[source][mac]" => "[source][mac]"', block)
        self.assertNotIn('"[destination][mac]" => "[destination][mac]"', block)

    def test_correlation_is_scoped_to_the_events_own_tenant_index(self):
        # WS0.3/WS0.5 tenant isolation — must not query across tenants.
        block = _zeek_intel_block(LOGSTASH_CONF)
        self.assertIn('index   => "logstash-security-%{[tenant][id]}"', block)

    def test_correlation_is_gated_on_indicator_direction(self):
        # security-auditor round 1 HIGH: for a Conn::IN_ORIG match (a known-
        # bad IP connecting IN to an internal host), orig_l2_addr is the
        # GATEWAY's MAC as observed on the monitored link, not the external
        # attacker's — populating source.mac in that direction would make
        # is_excluded(ip=.., mac=..) match a protected router MAC and
        # silently suppress containment of a genuine attacker. Only
        # Conn::IN_RESP (an internal device connecting OUT to a bad IP) is
        # the direction where source.mac correctly identifies the device
        # source.ip already refers to.
        # Search for the actual `if` CONDITION usage, not just the string —
        # the explanatory comment above the block also mentions
        # "Conn::IN_RESP" in prose, which would make a bare assertIn pass
        # vacuously even if the real gate were removed (caught by mutation
        # testing this exact way while writing this fix).
        block = _zeek_intel_block(LOGSTASH_CONF)
        self.assertIn('and [threat][indicator][sighting] == "Conn::IN_RESP"', block)

    def test_correlation_also_requires_source_ip_to_be_internal(self):
        # security-auditor round 2 MEDIUM: Conn::IN_RESP alone doesn't
        # guarantee source.ip is genuinely an internal device — if an
        # internal IP is ever itself an intel indicator, an INBOUND
        # connection to it also produces Conn::IN_RESP with source.ip as
        # the external attacker and orig_l2_addr as the gateway again.
        # Requiring source.ip to actually match the RFC1918/ULA predicate
        # (same one already used for the geoip guards in this file) closes
        # that residual path.
        block = _zeek_intel_block(LOGSTASH_CONF)
        self.assertIn(
            r'[source][ip] =~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|fc|fd)/',
            block)

    def test_correlation_guards_uid_before_interpolating_into_the_query(self):
        # The query string is Lucene query_string syntax built via sprintf
        # interpolation — an unguarded [uid] would let a malformed/hostile
        # value reach it. Confirms a character-class guard precedes the
        # elasticsearch filter, not just that one exists somewhere in the file.
        block = _zeek_intel_block(LOGSTASH_CONF)
        guard_pos = block.find("=~")
        es_pos = block.find("elasticsearch {")
        self.assertGreater(guard_pos, -1, "no regex guard found before the elasticsearch filter")
        self.assertLess(guard_pos, es_pos, "uid guard must precede the elasticsearch filter")

    def test_correlation_uid_guard_uses_true_string_anchors_not_line_anchors(self):
        # security-auditor round 1 HIGH: Logstash conditionals compile to
        # Ruby/Joni regex, where ^/$ match LINE boundaries, not string
        # boundaries — a uid value with an embedded newline could pass a
        # ^...$ check on its first line while smuggling Lucene query_string
        # syntax on a later line into the interpolated query. \A/\z are true
        # string anchors and must be used instead.
        block = _zeek_intel_block(LOGSTASH_CONF)
        self.assertIn(r"[uid] =~ /\A[A-Za-z0-9]{1,64}\z/", block)
        self.assertNotIn(r"[uid] =~ /^[A-Za-z0-9]", block,
                         "uid guard must not use line-anchored ^/$ regex")

    def test_correlation_tags_a_definite_query_failure_separately_from_a_miss(self):
        # security-auditor round 1 MEDIUM: without tag_on_failure, a genuine
        # query failure (bad credential, ES down) is indistinguishable from
        # "conn.log not indexed yet" — both just leave source.mac unset.
        block = _zeek_intel_block(LOGSTASH_CONF)
        self.assertIn('tag_on_failure => ["_mac_enrich_failed"]', block)

    def test_correlation_tags_a_definite_miss_for_observability(self):
        # code-reviewer round 1: a zero-hit lookup and a never-attempted one
        # were indistinguishable from the outside (source.mac just stays
        # unset either way) — no way to measure in production whether this
        # correlation is actually finding matches on the traffic it exists
        # for (see the KNOWN LIMITATION comment above this block).
        block = _zeek_intel_block(LOGSTASH_CONF)
        self.assertIn('add_tag => ["soar_mac_correlation_miss"]', block)
        # The tag name also appears in the explanatory comment above the
        # elasticsearch block — search for the actual add_tag USAGE, not
        # just the string, to correctly assert it comes after the lookup.
        miss_pos = block.find('add_tag => ["soar_mac_correlation_miss"]')
        es_pos = block.find("elasticsearch {")
        self.assertLess(es_pos, miss_pos, "the miss check must come AFTER the lookup attempt")

    def test_correlation_has_no_unverified_plugin_options(self):
        # security-auditor round 2 HIGH: a `timeout` option was here in
        # round 1 to bound worst-case pipeline stall, but could not be
        # verified against a live Logstash instance whether
        # logstash-filter-elasticsearch actually declares that option (vs.
        # only the OUTPUT plugin) — an unrecognized option is a FATAL
        # ConfigurationError at pipeline startup (blinds the whole stack),
        # a strictly worse outcome than the stall it was meant to bound.
        # Removed until verified live. This test locks in the removal so
        # it isn't silently reintroduced.
        block = _zeek_intel_block(LOGSTASH_CONF)
        self.assertNotIn("timeout =>", block)

    def test_correlation_uses_authenticated_tls_elasticsearch_connection(self):
        # Must not silently downgrade to an unauthenticated/plaintext
        # connection — matches this file's own output{} block conventions.
        block = _zeek_intel_block(LOGSTASH_CONF)
        self.assertIn("ssl_enabled => true", block)

    def test_correlation_uses_the_dedicated_read_only_credential_not_logstash_internal(self):
        # security-auditor round 1 CRITICAL: logstash_internal (LOGSTASH_ES_USER,
        # used everywhere else in this pipeline) holds only logstash_writer —
        # write/manage, no read privilege at all — so a query using it 403s
        # on every event, making the whole fix silently inert. Must use the
        # dedicated logstash_enrich_reader credential instead.
        block = _zeek_intel_block(LOGSTASH_CONF)
        self.assertIn('user     => "${LOGSTASH_ENRICH_USER:logstash_enrich}"', block)
        self.assertIn('password => "${LOGSTASH_ENRICH_PASS:}"', block)
        self.assertNotIn('user     => "${LOGSTASH_ES_USER}"', block)


class TenantValidationTests(unittest.TestCase):
    def test_tenant_id_is_validated_before_any_index_selector_use(self):
        # security-auditor round 1 HIGH: [tenant][id] was validated nowhere
        # — safe as long as it only ever fed a WRITE index name (ES rejects
        # a malformed one outright). #286 adds the first READ use (the
        # correlation query's index selector below), which is fail-OPEN for
        # an unvalidated wildcard/comma-separated value, not fail-safe like
        # a write. Same slug grammar erase_tenant.sh already enforces.
        filter_start = LOGSTASH_CONF.index("filter {")
        correlation_start = LOGSTASH_CONF.index('if [event][dataset] == "zeek.intel" {')
        preamble = LOGSTASH_CONF[filter_start:correlation_start]
        self.assertIn(r"[tenant][id] !~ /\A[a-z0-9][a-z0-9-]{1,38}\z/", preamble)
        self.assertIn('"[tenant][id]" => "unassigned"', preamble)


class EnrichCredentialProvisioningTests(unittest.TestCase):
    """security-auditor round 1 CRITICAL: the correlation query needs its
    own read-only ES credential — these lock in that it's actually
    provisioned least-privilege, not just referenced by name in
    logstash.conf (which would silently 403 forever without this)."""

    def test_role_file_exists_and_is_read_only_on_logstash_security(self):
        self.assertTrue(ENRICH_ROLE_PATH.exists(), f"missing {ENRICH_ROLE_PATH}")
        role = json.loads(ENRICH_ROLE_PATH.read_text(encoding="utf-8"))
        indices = role["indices"]
        self.assertEqual(len(indices), 1)
        self.assertEqual(indices[0]["names"], ["logstash-security-*"])
        self.assertEqual(indices[0]["privileges"], ["read"])

    def test_docker_compose_provisions_the_role_and_user(self):
        self.assertIn("logstash_enrich_reader", DOCKER_COMPOSE)
        self.assertIn("/_security/user/logstash_enrich", DOCKER_COMPOSE)
        self.assertIn(r'\"roles\":[\"logstash_enrich_reader\"]', DOCKER_COMPOSE)

    def test_docker_compose_password_is_never_spliced_into_container_argv(self):
        # Same reasoning as AGENT_CHECKPOINTS_PASSWORD/INTEL_WRITER_PASSWORD
        # in the same file: $$ (not $) so the literal password only ever
        # comes from this container's own environment block, not argv
        # (readable via `docker inspect`/`ps --no-trunc` for as long as the
        # exited one-shot provision container exists).
        self.assertIn("$${LOGSTASH_ENRICH_PASSWORD}", DOCKER_COMPOSE)

    def test_logstash_service_receives_the_enrich_credential(self):
        self.assertIn("LOGSTASH_ENRICH_USER=logstash_enrich", DOCKER_COMPOSE)
        self.assertIn("LOGSTASH_ENRICH_PASS=${LOGSTASH_ENRICH_PASSWORD:-}", DOCKER_COMPOSE)


class ZeekLoadOrderTests(unittest.TestCase):
    def test_config_zeek_loads_mac_logging(self):
        # The real capture path (every script under scripts/setup/ and
        # zeek-host-capture.service passes config.zeek, never local.zeek).
        self.assertIn("@load policy/protocols/conn/mac-logging", CONFIG_ZEEK)

    def test_local_zeek_no_longer_claims_to_provide_mac_logging(self):
        # local.zeek is dead (unreferenced by any real capture invocation) —
        # its mac-logging @load was cosmetic. Must not remain, so a future
        # reader doesn't mistake it for the real fix.
        self.assertNotIn("@load policy/protocols/conn/mac-logging", LOCAL_ZEEK)


class PrivacyDocTests(unittest.TestCase):
    def test_sop_012_lists_mac_addresses_as_personal_data(self):
        self.assertIn("MAC address", SOP_012)

    def test_sop_012_references_the_286_fix(self):
        self.assertIn("#286", SOP_012)

    def test_sop_012_no_longer_directs_operators_to_the_dead_local_zeek_file(self):
        # security-auditor round 1 MEDIUM: an operator following the
        # Containment playbook to stop a PII leak must not be pointed at a
        # file that has zero effect on the real capture path. local.zeek is
        # still MENTIONED (to explain it's dead), so check the original
        # bare, unqualified instruction is gone, not that the string never
        # appears anywhere.
        self.assertNotIn("Update `local.zeek` or `logstash.conf`", SOP_012)
        self.assertIn("configs/intel/config.zeek", SOP_012)

    def test_erase_tenant_covers_the_quarantine_stream(self):
        # security-auditor round 1 MEDIUM: logstash-security-quarantine-*
        # is a separate data stream (same index_patterns template) that
        # erase_tenant.sh's STREAMS array omitted — quarantined events
        # (grok/json parse failures) carry the full ECS payload, including
        # MAC fields since #286, and survived a completed erasure receipt.
        erase_tenant = (ROOT / "scripts" / "setup" / "erase_tenant.sh").read_text(encoding="utf-8")
        self.assertIn("logstash-security-quarantine-${TENANT}", erase_tenant)


if __name__ == "__main__":
    unittest.main()
