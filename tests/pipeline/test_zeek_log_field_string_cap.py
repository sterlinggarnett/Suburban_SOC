#!/usr/bin/env python3
"""
#389: Zeek's logging framework — not its DNS analyzer — silently truncates
every logged string field at ``Log::default_max_field_string_bytes`` (4096
bytes upstream, introduced in Zeek 8.1.0; the pinned zeek/zeek:8.2.1 image
has it, the native 8.0.5 on the capture host does not). That cap sits BELOW
this pipeline's own designed visibility ceiling for dns.answers
(ignore_above:8191 + the #352/#390 ``pipeline.oversized`` tag), so a TXT
answer between 4096 and 8191 chars was cut by Zeek before Logstash or
Elasticsearch could ever see or flag it.

configs/intel/config.zeek now raises the cap (version-guarded, since a
pre-8.1 Zeek rejects the identifier outright — live-confirmed on 8.0.5:
`"redef" used but not previously defined (Log::default_max_field_string_bytes)`),
and
configs/logstash.conf's exact-length ``pipeline.dns_answer_truncated_by_zeek``
signal keys on that SAME number. Three things must stay in lockstep, and
each is a static text assertion against the real files (no live Zeek —
tests/detections/test_zeek_log_field_string_cap_live.py is the live half,
against the pinned image):

  1. config.zeek's redef value is the one this module expects and is
     guarded for pre-8.1 Zeek.
  2. logstash.conf's exact-length literal equals config.zeek's redef value
     (a Zeek-truncated answer lands at exactly the cap; the tag must look
     for exactly the cap, or it goes silently blind on a value change).
  3. Every real capture invocation's post-copy staleness guard (#288)
     also checks the redef landed — a stale pre-#389 config.zeek would
     otherwise run Zeek at 4096 while Logstash looks for the raised cap.

Run:  pytest tests/pipeline/test_zeek_log_field_string_cap.py
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG_ZEEK = (ROOT / "configs" / "intel" / "config.zeek").read_text(encoding="utf-8")
LOGSTASH_CONF = (ROOT / "configs" / "logstash.conf").read_text(encoding="utf-8")
TEMPLATE = json.loads(
    (ROOT / "configs" / "elasticsearch" / "logstash-security-template.json").read_text(encoding="utf-8"))
REAL_CAPTURE_SOURCES = [
    (name, (ROOT / rel).read_text(encoding="utf-8")) for name, rel in (
        ("zeek_run_pcap.sh", "scripts/setup/zeek_run_pcap.sh"),
        ("stream_capture.sh", "scripts/setup/stream_capture.sh"),
        ("zeek_connect_host.sh", "scripts/setup/zeek_connect_host.sh"),
        ("zeek-host-capture.service", "configs/systemd/zeek-host-capture.service"),
    )
]

# The value this pipeline runs Zeek at: EQUAL to dns.answers' ignore_above
# (8191). Security-auditor review of the first draft (16384) found that any
# cap ABOVE the indexing ceiling opens a detection blind window: a Zeek-
# logged answer longer than ignore_above is stored but never indexed, so
# net_zeek_dns_txt_answer_abuse.yml's answers|re can no longer match it -
# whereas Zeek's old 4096 cut, for all its silence, kept every answer
# indexable. Pinning the cap to the ceiling doubles the retained content
# (4096 -> 8191 bytes) while keeping every Zeek-logged answer rule-
# matchable; a Zeek-truncated answer lands at exactly 8191 and is still
# indexed. Raising BOTH together past 8191 needs the array-aware byte clamp
# the template's own _meta WARNING names (Lucene's 32766-byte term limit
# for a forged multi-byte value) - tracked as #545, not done here. The
# lockstep tests below force config.zeek, logstash.conf, the mirror
# constant and the template ceiling to move together.
EXPECTED_CAP = 8191
REDEF_RE = re.compile(r"^redef Log::default_max_field_string_bytes = (\d+);\s*$", re.M)
VERSION_GUARD_OPEN = "@if ( Version::number >= 80100 )"
LOGSTASH_LITERAL_RE = re.compile(r"a\.bytesize == (\d+)")
# Anchored AND value-inclusive (security-auditor: the identifier alone also
# appears in config.zeek's comments, so a copy with the comment but no
# active redef - or a different value - would pass an identifier-only grep).
GUARD_GREP_RE = re.compile(
    r'grep -q "\^redef Log::default_max_field_string_bytes = %d;" /storage/PCAP/intel/config\.zeek'
    % EXPECTED_CAP)


def _dns_answers_ignore_above() -> int:
    props = TEMPLATE["template"]["mappings"]["properties"]
    return int(props["dns"]["properties"]["answers"]["ignore_above"])


class ConfigZeekCapTests(unittest.TestCase):
    def test_config_zeek_redefs_the_log_field_string_cap_to_the_expected_value(self):
        matches = REDEF_RE.findall(CONFIG_ZEEK)
        self.assertEqual(len(matches), 1,
                         "expected exactly one Log::default_max_field_string_bytes redef in "
                         "configs/intel/config.zeek")
        self.assertEqual(int(matches[0]), EXPECTED_CAP)

    def test_redef_is_inside_a_pre_8_1_version_guard(self):
        # Zeek < 8.1 has no such identifier and fails to parse the whole
        # config (live-confirmed on the capture host's native 8.0.5), which
        # would take every @load in config.zeek down with it. The pinned
        # image is 8.2.1, but the guard is what keeps config.zeek loadable
        # on both the image and a host-native zeek.
        open_pos = CONFIG_ZEEK.find(VERSION_GUARD_OPEN)
        self.assertGreater(open_pos, -1, f"missing {VERSION_GUARD_OPEN!r} in config.zeek")
        close_pos = CONFIG_ZEEK.find("@endif", open_pos)
        self.assertGreater(close_pos, -1, "version guard has no @endif")
        redef = REDEF_RE.search(CONFIG_ZEEK)
        self.assertIsNotNone(redef)
        self.assertTrue(open_pos < redef.start() < close_pos,
                        "the redef must sit inside the Version::number >= 80100 guard")

    def test_cap_equals_the_pipelines_dns_answers_indexing_ceiling(self):
        # Zeek's cap must EQUAL ignore_above: below it wastes indexable
        # range (the old 4096 cut), above it makes every Zeek-logged answer
        # in (ceiling, cap] unindexed and invisible to the TXT-abuse rule
        # (security-auditor, first draft). Move both or neither - #545.
        self.assertEqual(EXPECTED_CAP, _dns_answers_ignore_above())


class LogstashLockstepTests(unittest.TestCase):
    def _logstash_block(self) -> str:
        marker = "array_fields = {"
        pos = LOGSTASH_CONF.find(marker)
        self.assertGreater(pos, -1, "configs/logstash.conf's #390 array_fields block is missing")
        return LOGSTASH_CONF[pos:]

    def test_logstash_exact_length_literal_equals_config_zeeks_redef(self):
        literals = LOGSTASH_LITERAL_RE.findall(self._logstash_block())
        self.assertEqual(len(literals), 1,
                         "expected exactly one `a.bytesize == <cap>` comparison in the #389 block")
        self.assertEqual(int(literals[0]), int(REDEF_RE.search(CONFIG_ZEEK).group(1)))

    def test_field_truncation_mirror_constant_equals_config_zeeks_redef(self):
        # code-reviewer follow-up: tests/pipeline/test_field_truncation.py's
        # Python mirror pins ITSELF to logstash.conf's literal, and this
        # module pins that literal to config.zeek — closed transitively, but
        # tie the mirror constant to the redef directly too, so a reader of
        # either module sees one assertion naming all three.
        mirror_src = (ROOT / "tests" / "pipeline" / "test_field_truncation.py").read_text(encoding="utf-8")
        m = re.search(r"^ZEEK_MAX_FIELD_STRING_BYTES = (\d+)\s*$", mirror_src, re.M)
        self.assertIsNotNone(m, "test_field_truncation.py no longer defines ZEEK_MAX_FIELD_STRING_BYTES")
        self.assertEqual(int(m.group(1)), int(REDEF_RE.search(CONFIG_ZEEK).group(1)))

    def test_logstash_no_longer_keys_on_the_old_upstream_4096_default(self):
        # The old literal was a black-box observation of the upstream
        # default; with the cap raised it would be a permanently-dark signal.
        self.assertNotIn('== 4096', self._logstash_block())


class DeployedCopyGuardTests(unittest.TestCase):
    def test_every_real_capture_invocation_guard_checks_the_redef_landed(self):
        # Extends #288's post-copy staleness canary: a silently-failed cp
        # leaving a pre-#389 config.zeek on disk would run Zeek at 4096
        # while Logstash's exact-length tag looks for the raised cap —
        # degraded (weird.log still fires) but the per-record pointer is
        # blind. Fail loudly instead, same as the capture-loss canary. The
        # grep is anchored on the active redef line WITH its value, so a
        # comment-only copy or a copy carrying a different value fails too.
        for label, text in REAL_CAPTURE_SOURCES:
            with self.subTest(source=label):
                self.assertRegex(text, GUARD_GREP_RE)


if __name__ == "__main__":
    unittest.main()
