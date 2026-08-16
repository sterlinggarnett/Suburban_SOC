#!/usr/bin/env python3
"""
Field-truncation tagging fixture tests (#252, extended #263, #290, #344).

SCOPE (same documented scope as tests/pipeline/test_grok_parse_failures.py):
a Python re-implementation of configs/logstash.conf's field-truncation ruby
filter's LOGIC, for fast fixture tests without a live Logstash. It does NOT
exercise the actual compiled ruby filter that runs in the container — see
the tester-debugger live-verification notes for that. Keep this in sync by
hand with the ruby block at configs/logstash.conf (Component 4 area, "#252"
comment).

process.args/process.parent.args/winlog.event_data.ScriptBlockText/
winlog.event_data.ImagePath/url.path/winlog.event_data.CommandLine/
network_parsed.uri are mapped ignore_above:32766 (#249/#250 raised it to
8191; #263 raised it again to 32766 and added ImagePath, after 8191
turned out to still be below real PowerShell 4104 chunk sizes; #290 added
url.path; #344 added the 2 fields only reachable via the template's
long_command_fields dynamic_template rather than an explicit property —
see CeilingConsistencyTests for why the template-derived tests above
can't discover those on their own). A value longer than CEILING (32766
chars) is silently dropped from the ES index
while remaining in _source — ignore_above's own char-based check handles
this server-side, safely, before Lucene ever sees the term. This filter
tags pipeline.truncated="true" + pipeline.truncated_fields instead of
letting that drop stay invisible.

#263 review found a SEPARATE, more dangerous failure mode: ignore_above is a
character count, but Lucene's own per-term hard limit is a UTF-8 BYTE count
(32766) — a value under CEILING in characters but byte-heavy (multi-byte
UTF-8 content, only possible via non-ASCII text) can still exceed Lucene's
byte limit, which — confirmed live — makes Elasticsearch reject the WHOLE
DOCUMENT (HTTP 400 "immense term"), not just drop the field. The filter
guards this with BYTE_CEILING, clamping the value before it reaches
Elasticsearch. The two checks are deliberately mutually exclusive (char
check first): since UTF-8 byte length is never less than character length,
checking bytesize unconditionally before the char check would make every
char-ceiling hit ALSO trip the byte clamp, since BYTE_CEILING < CEILING —
silently making pipeline.truncated unreachable. Confirmed the fixed logic
still discriminates via test_ascii_value_over_ceiling_char_tagged_not_byte_
clamped below, not just by eyeballing the ruby diff.

#263 also found the Sysmon `mutate.rename` block (configs/logstash.conf,
~line 523) targeted bare dotted strings ("process.args"), which Logstash
creates as a FLAT field literally named "process.args" — not the nested
[process][args] structure this filter's long_fields keys expect. Confirmed
live: the nested lookup returned nil for real Sysmon-sourced process.args/
process.parent.args, so those two fields were never actually tagged. Worked
around at the time with a flat-key fallback (#263); #328 fixed the rename
block itself (bracket notation), so the fallback is no longer needed —
nothing in this pipeline produces the flat dotted-key shape anymore.

Run:  python tests/pipeline/test_field_truncation.py  (or: pytest tests/pipeline)
"""

import json
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TEMPLATE_PATH = ROOT / "configs" / "elasticsearch" / "logstash-security-template.json"
LOGSTASH_CONF_PATH = ROOT / "configs" / "logstash.conf"

CEILING = 32766
BYTE_CEILING = 32000
LONG_FIELDS = {
    "process.args": ["process", "args"],
    "process.parent.args": ["process", "parent", "args"],
    "winlog.event_data.ScriptBlockText": ["winlog", "event_data", "ScriptBlockText"],
    "winlog.event_data.ImagePath": ["winlog", "event_data", "ImagePath"],
    "url.path": ["url", "path"],
    "winlog.event_data.CommandLine": ["winlog", "event_data", "CommandLine"],
    "network_parsed.uri": ["network_parsed", "uri"],
}


def _nested_get(event: dict, path_parts):
    cur: object = event
    for part in path_parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _clamp_bytes(val: str, byte_ceiling: int) -> str:
    """Mirrors ruby's val.byteslice(0, byte_ceiling).scrub: cut at a byte
    boundary (which may split a multi-byte character), then repair any
    resulting invalid byte sequence — Python's errors="replace" matches
    scrub's default replacement-character behavior."""
    return val.encode("utf-8")[:byte_ceiling].decode("utf-8", errors="replace")


def tag_truncation(event: dict):
    """Mirrors configs/logstash.conf's #252/#263 ruby filter. Returns
    (char_hit, byte_hit): field labels dropped by ignore_above (char count)
    and field labels defensively byte-clamped to avoid a Lucene immense-term
    document rejection, respectively. Mutually exclusive per field — see
    module docstring for why checking both unconditionally would be wrong."""
    char_hit = []
    byte_hit = []
    for label, path_parts in LONG_FIELDS.items():
        val = _nested_get(event, path_parts)
        if not isinstance(val, str):
            continue
        if len(val) > CEILING:
            char_hit.append(label)
        elif len(val.encode("utf-8")) > BYTE_CEILING:
            byte_hit.append(label)
    return char_hit, byte_hit


class FieldTruncationTaggingTests(unittest.TestCase):
    def test_short_scriptblocktext_not_tagged(self):
        event = {"winlog": {"event_data": {"ScriptBlockText": "Invoke-Something -Arg 1"}}}
        self.assertEqual(tag_truncation(event), ([], []))

    def test_long_scriptblocktext_tagged(self):
        # #263: 32766 covers real PowerShell 4104 chunk sizes (~20000 chars)
        # and Windows' own ~32767-char CreateProcess command-line limit, so a
        # value that still trips CEILING is synthetic/adversarial, not a
        # realistic organic one — well past the ignore_above ceiling. Pure
        # ASCII, so char length == byte length: the char check fires first
        # (mutually exclusive branches), landing in char_hit not byte_hit.
        event = {"winlog": {"event_data": {"ScriptBlockText": "A" * 40000}}}
        self.assertEqual(tag_truncation(event), (["winlog.event_data.ScriptBlockText"], []))

    def test_exactly_at_byte_ceiling_not_tagged(self):
        # For pure ASCII, bytes==chars, so BYTE_CEILING (32000) — not
        # CEILING (32766) — is the binding constraint near the boundary.
        # Only strictly-over either ceiling should tag, or every field at
        # the exact boundary would falsely alarm.
        event = {"process": {"args": "A" * BYTE_CEILING}}
        self.assertEqual(tag_truncation(event), ([], []))

    def test_ascii_value_between_byte_and_char_ceiling_byte_clamped(self):
        # Deliberate, documented interaction: an ASCII value exactly at
        # CEILING (32766 chars = 32766 bytes, since bytes==chars for ASCII)
        # is still over BYTE_CEILING (32000) — the mutually-exclusive
        # char-check-first branching means values in the narrow
        # BYTE_CEILING+1..CEILING band land in byte_hit, not char_hit, even
        # for pure ASCII. Zero practical impact on #263's real target
        # (realistic payloads are ~3000-20000 chars, far under BYTE_CEILING)
        # — this is the cost of the safety margin BYTE_CEILING intentionally
        # keeps below CEILING (see CeilingConsistencyTests).
        event = {"process": {"args": "A" * CEILING}}
        self.assertEqual(tag_truncation(event), ([], ["process.args"]))

    def test_one_over_ceiling_tagged(self):
        event = {"process": {"args": "A" * 32767}}
        self.assertEqual(tag_truncation(event), (["process.args"], []))

    def test_multiple_long_fields_all_listed(self):
        event = {
            "process": {"args": "A" * 33000, "parent": {"args": "B" * 33000}},
            "winlog": {"event_data": {"ScriptBlockText": "C" * 33000}},
        }
        self.assertEqual(
            tag_truncation(event),
            (["process.args", "process.parent.args", "winlog.event_data.ScriptBlockText"], []),
        )

    def test_missing_fields_no_crash_no_tag(self):
        self.assertEqual(tag_truncation({}), ([], []))

    def test_non_string_field_ignored(self):
        # Malformed/mistyped upstream data must not crash the filter.
        event = {"process": {"args": 12345}}
        self.assertEqual(tag_truncation(event), ([], []))

    def test_other_long_fields_under_ceiling_not_tagged(self):
        # A field this filter doesn't check (e.g. url.original, an EXPLICIT
        # property at ignore_above:8191 — explicit properties always take
        # precedence over the long_command_fields dynamic_template, and
        # url.original's path doesn't match that template's path_match
        # patterns anyway) is deliberately out of scope for #252 —
        # ScriptBlockText/process.args/ImagePath are the attacker-controlled
        # fields the issue is about. Fixture must stay above whatever
        # CEILING currently is, or this assertion holds trivially regardless
        # of correctness.
        event = {"url": {"original": "A" * (CEILING + 1000)}}
        self.assertEqual(tag_truncation(event), ([], []))

    def test_imagepath_over_ceiling_tagged(self):
        # #263 security-auditor HIGH: system_win_suspicious_service_binpath_
        # lolbin.yml selects on ImagePath|contains — an encoded PowerShell
        # binPath (the same long-payload shape #263 is about) silently
        # bypassed that rule while ImagePath stayed at the old 8191 ceiling,
        # untracked by this filter. Now in scope with the other 3 fields.
        event = {"winlog": {"event_data": {"ImagePath": "A" * 40000}}}
        self.assertEqual(tag_truncation(event), (["winlog.event_data.ImagePath"], []))

    def test_security_channel_commandline_over_ceiling_tagged(self):
        # #344: winlog.event_data.CommandLine (Windows Security-channel
        # EventID 4688, Winlogbeat's raw un-renamed shape - unlike the
        # Sysmon channel, which renames its CommandLine to process.args,
        # already covered above) matches the long_command_fields dynamic_
        # template's *CommandLine glob at ignore_above:32766 in the real ES
        # template, but was missing from configs/logstash.conf's long_fields
        # clamp hash - same whole-document Lucene immense-term rejection
        # risk #263/#290 fixed for their own fields, just undiscovered
        # because CeilingConsistencyTests' template walk only sees explicit
        # properties, not dynamic_template matches.
        event = {"winlog": {"event_data": {"CommandLine": "A" * 40000}}}
        self.assertEqual(tag_truncation(event), (["winlog.event_data.CommandLine"], []))

    def test_network_parsed_uri_over_ceiling_tagged(self):
        # #344 security-auditor follow-up: the one OTHER concrete instance
        # of this bug class found in the repo. network_parsed.uri (Zeek
        # http.log's uri field, deliberately left unrenamed per Category
        # 1's own rename-block comment - net_zeek_http_cobalt_strike_
        # beacon.yml selects on it directly) matches the long_command_
        # fields dynamic_template's *uri glob at ignore_above:32766, same
        # as CommandLine above - but unlike CommandLine, this one is
        # live-reachable today via the unauthenticated :5514 HTTP input,
        # same fully attacker-controlled shape as #290's url.path (an HTTP
        # request URI).
        event = {"network_parsed": {"uri": "A" * 40000}}
        self.assertEqual(tag_truncation(event), (["network_parsed.uri"], []))

    def test_flat_dotted_key_no_longer_matched(self):
        # #328 fixed the Sysmon rename block to bracket notation, so nothing
        # in the pipeline produces a flat "process.args"-shaped key anymore
        # — the #263-era fallback that used to catch it was removed as dead
        # code in the same fix. A stray flat key (should never occur from
        # any real source post-#328) must NOT be picked up as a substitute
        # for the real nested field, or a future regression of the rename
        # block back to dotted-string form would silently start passing
        # this suite again via the wrong mechanism.
        event = {"process.args": "A" * 40000}
        self.assertEqual(tag_truncation(event), ([], []))


class ByteClampTaggingTests(unittest.TestCase):
    """#263 HIGH (both security-auditor and code-reviewer, confirmed live):
    ignore_above is a character ceiling; Lucene's own per-term hard limit is
    a UTF-8 BYTE ceiling. A value under CEILING chars but byte-heavy
    (multi-byte UTF-8 — impossible for pure ASCII, where bytes==chars
    exactly) can still exceed Lucene's byte limit. Live-confirmed
    consequence if unguarded: Elasticsearch rejects the WHOLE DOCUMENT
    (HTTP 400 document_parsing_exception -> illegal_argument_exception
    "immense term"), not just drops the field — worse than the bug #263 set
    out to fix. These tests exercise the byte_hit side of tag_truncation and
    the clamp helper independently."""

    def test_ascii_value_over_ceiling_char_tagged_not_byte_clamped(self):
        # The critical regression case: without the mutually-exclusive
        # branch ordering, this ASCII value (bytes==chars, both over
        # BYTE_CEILING since BYTE_CEILING < CEILING) would land in byte_hit
        # instead of char_hit, making pipeline.truncated permanently dead
        # for realistic long ASCII payloads — exactly the original #252/#263
        # signal this filter exists to produce.
        event = {"winlog": {"event_data": {"ScriptBlockText": "A" * 33000}}}
        self.assertEqual(tag_truncation(event), (["winlog.event_data.ScriptBlockText"], []))

    def test_multibyte_value_under_char_ceiling_over_byte_ceiling_clamped(self):
        # 9000 chars (well under CEILING=32766) of a 4-byte-UTF-8 character
        # (emoji) = 36000 UTF-8 bytes (over BYTE_CEILING=32000, over
        # Lucene's real 32766 hard limit too) — the exact shape confirmed
        # live to trigger the HTTP 400 immense-term document rejection when
        # unclamped.
        event = {"winlog": {"event_data": {"ScriptBlockText": "\U0001F600" * 9000}}}
        self.assertEqual(tag_truncation(event), ([], ["winlog.event_data.ScriptBlockText"]))

    def test_multibyte_value_under_both_ceilings_not_tagged(self):
        # 5000 emoji chars = 20000 bytes — under both CEILING and
        # BYTE_CEILING, matching a realistic ~20000-char 4104 chunk that
        # happens to contain multi-byte content.
        event = {"winlog": {"event_data": {"ScriptBlockText": "\U0001F600" * 5000}}}
        self.assertEqual(tag_truncation(event), ([], []))

    def test_security_channel_commandline_multibyte_byte_clamped(self):
        # #344 security-auditor follow-up: the new CommandLine test in
        # FieldTruncationTaggingTests only exercises the char_hit branch
        # (pure ASCII, safe - ES's own ignore_above drops it server-side,
        # document survives). The actually dangerous branch #344 is about
        # is byte_hit: an unclamped multi-byte value here is exactly what
        # crashes the WHOLE document (HTTP 400 immense term), not just
        # this field.
        event = {"winlog": {"event_data": {"CommandLine": "\U0001F600" * 9000}}}
        self.assertEqual(tag_truncation(event), ([], ["winlog.event_data.CommandLine"]))

    def test_clamp_helper_produces_valid_utf8_under_byte_ceiling(self):
        val = "\U0001F600" * 9000
        clamped = _clamp_bytes(val, BYTE_CEILING)
        self.assertLessEqual(len(clamped.encode("utf-8")), BYTE_CEILING)
        # Round-trips clean (scrub's replacement-character repair leaves
        # valid UTF-8, not raw truncated bytes that would themselves fail to
        # parse).
        clamped.encode("utf-8").decode("utf-8")


class CeilingConsistencyTests(unittest.TestCase):
    """#263 security-auditor MEDIUM: the "keep `ceiling` in lockstep with the
    template's ignore_above" invariant stated in configs/logstash.conf's
    comment was previously enforced by nothing but that comment — a future
    edit to either side could silently drift and either false-alarm
    (Logstash tags truncated for values ES actually indexes fine) or, worse,
    go blind (ES silently drops values Logstash never flags). Parse both
    real files and assert they agree with each other and with this test
    module's own CEILING, converting the stated invariant into a CI gate."""

    def _logstash_ceiling(self):
        text = LOGSTASH_CONF_PATH.read_text(encoding="utf-8")
        match = re.search(r"^\s*ceiling\s*=\s*(\d+)\s*$", text, re.MULTILINE)
        self.assertIsNotNone(match, "could not find 'ceiling = <N>' in configs/logstash.conf")
        return int(match.group(1))

    def _logstash_byte_ceiling(self):
        text = LOGSTASH_CONF_PATH.read_text(encoding="utf-8")
        match = re.search(r"^\s*byte_ceiling\s*=\s*(\d+)\s*$", text, re.MULTILINE)
        self.assertIsNotNone(match, "could not find 'byte_ceiling = <N>' in configs/logstash.conf")
        return int(match.group(1))

    def _template_ignore_above(self):
        template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        mappings = template["template"]["mappings"]
        props = mappings["properties"]
        dynamic = mappings["dynamic_templates"][0]["long_command_fields"]["mapping"]["ignore_above"]
        return {
            "process.args": props["process"]["properties"]["args"]["ignore_above"],
            "process.parent.args": props["process"]["properties"]["parent"]["properties"]["args"]["ignore_above"],
            "winlog.event_data.ScriptBlockText":
                props["winlog"]["properties"]["event_data"]["properties"]["ScriptBlockText"]["ignore_above"],
            "winlog.event_data.ImagePath":
                props["winlog"]["properties"]["event_data"]["properties"]["ImagePath"]["ignore_above"],
            "url.path": props["url"]["properties"]["path"]["ignore_above"],
            "long_command_fields (dynamic_template)": dynamic,
        }

    def _walk_ceiling_paths(self, properties, prefix=()):
        """Yield the dotted path of every explicit property mapped at exactly
        CEILING (32766) — walks the REAL template rather than trusting a
        hand-maintained list, so this discovers a field even if nobody
        remembered to add it anywhere else."""
        for key, val in properties.items():
            if not isinstance(val, dict):
                continue
            if "properties" in val:
                yield from self._walk_ceiling_paths(val["properties"], prefix + (key,))
            elif val.get("ignore_above") == CEILING:
                yield ".".join(prefix + (key,))

    def _template_ceiling_paths(self):
        template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        props = template["template"]["mappings"]["properties"]
        return set(self._walk_ceiling_paths(props))

    def test_logstash_ceiling_matches_this_modules_ceiling(self):
        self.assertEqual(self._logstash_ceiling(), CEILING)

    def test_logstash_byte_ceiling_matches_this_modules_byte_ceiling(self):
        self.assertEqual(self._logstash_byte_ceiling(), BYTE_CEILING)

    def test_byte_ceiling_stays_below_lucene_hard_limit_with_margin(self):
        # Must stay under Lucene's real 32766-byte hard limit, with margin
        # for lowercase_normalizer's case-folding growth (applied by ES
        # after this filter runs — a small number of Unicode code points,
        # e.g. U+0130, grow in UTF-8 byte length when case-folded).
        self.assertLess(self._logstash_byte_ceiling(), 32766)

    def test_byte_ceiling_stays_below_char_ceiling(self):
        # Load-bearing for the mutually-exclusive branch ordering in
        # tag_truncation/the ruby filter — see module docstring.
        self.assertLess(self._logstash_byte_ceiling(), self._logstash_ceiling())

    def test_template_ignore_above_fields_match_ceiling(self):
        ignore_above = self._template_ignore_above()
        for label, value in ignore_above.items():
            self.assertEqual(value, CEILING, f"{label}: ignore_above={value}, expected {CEILING}")

    def test_every_ceiling_field_has_a_byte_clamp_entry(self):
        # #290 security-auditor HIGH: url.path was raised to ignore_above:
        # 32766 without being added to logstash.conf's long_fields clamp
        # hash or this module's LONG_FIELDS mirror — silently reintroducing
        # #263's Lucene immense-term whole-document-rejection bug on a new
        # attacker-controlled field (live-confirmed: a 20000-char/40000-byte
        # url.path crashed the whole document via HTTP 400), with CI staying
        # green because nothing walked the template to notice a 5th field
        # had appeared. Derives "which fields need clamping" FROM the
        # template itself (every EXPLICIT property at exactly CEILING)
        # rather than trusting a hand-maintained list to stay in sync with
        # it, so a 6th explicit-property field raised to 32766 later can't
        # skip this check the same way. Narrower than it may sound
        # (security-auditor follow-up review): does NOT see fields created
        # through the long_command_fields dynamic_template (also at
        # ignore_above:32766) — those never appear as named properties, so
        # they're invisible to this walk no matter how many are added to
        # long_fields/LONG_FIELDS by hand. #344 fixed the 2 concretely-
        # identified instances this way (winlog.event_data.CommandLine and
        # network_parsed.uri — see test_security_channel_commandline_over_
        # ceiling_tagged / test_network_parsed_uri_over_ceiling_tagged
        # above), rather than rewriting the ruby filter to walk the
        # dynamic_template's glob patterns generically. A pure glob-only
        # sweep (matching ONLY the 6 path_match patterns) would regress
        # ImagePath/url.path, neither of which matches any of them despite
        # needing the same clamp — so a correct structural fix would need
        # to UNION the glob sweep with the existing explicit list, not
        # replace it. That union is the real deferred work, and the real
        # cost security-auditor review identified is NOT correctness but
        # performance: it requires a recursive walk of every event's full
        # field tree on every single event, on a pipeline with its own
        # ingest-lag SLO (scripts/setup/ai_agent/slo_metrics.py) — a cost
        # this fix deliberately did not take on for 2 concretely-verified
        # fields when a 1-line hash entry does the same job. Tracked as
        # #367 (close the class permanently rather than field-by-field).
        template_paths = self._template_ceiling_paths()

        logstash_text = LOGSTASH_CONF_PATH.read_text(encoding="utf-8")
        long_fields_block = re.search(r"long_fields\s*=\s*\{(.*?)\n\s*\}", logstash_text, re.DOTALL)
        self.assertIsNotNone(long_fields_block,
                             "could not find 'long_fields = {...}' in configs/logstash.conf")
        logstash_labels = set(re.findall(r'=>\s*"([^"]+)"', long_fields_block.group(1)))

        missing_from_logstash = template_paths - logstash_labels
        self.assertEqual(set(), missing_from_logstash,
                         f"template field(s) mapped ignore_above:{CEILING} with no matching entry "
                         f"in configs/logstash.conf's long_fields clamp hash — the byte-clamp never "
                         f"runs for them, risking a Lucene immense-term whole-document rejection on "
                         f"an unclamped field: {missing_from_logstash}")

        missing_from_python_mirror = template_paths - set(LONG_FIELDS.keys())
        self.assertEqual(set(), missing_from_python_mirror,
                         f"template field(s) mapped ignore_above:{CEILING} missing from this "
                         f"module's own LONG_FIELDS mirror — tag_truncation() won't tag them even "
                         f"though the real ruby filter clamps them, giving this test suite false "
                         f"confidence: {missing_from_python_mirror}")

        # #344 security-auditor MEDIUM: everything above derives expectations
        # FROM the template, so a hand-added entry that exists ONLY in one of
        # the two hand-maintained lists (e.g. a dynamic-template-only field
        # like CommandLine/network_parsed.uri, invisible to template_paths by
        # construction) was never checked against the other at all — deleting
        # the new logstash.conf entry left every other assertion in this test
        # green. This closes that gap directly: the two hand-maintained lists
        # must agree with EACH OTHER, independent of what the template walk
        # can see, covering every current and future dynamic-template-only
        # entry the walk-based checks above structurally cannot.
        self.assertEqual(set(LONG_FIELDS.keys()), logstash_labels,
                         "configs/logstash.conf's long_fields hash and this module's LONG_FIELDS "
                         "mirror have drifted apart — every clamped field must be listed in both, "
                         "or either the ruby filter or the Python test mirror silently stops "
                         f"matching reality. logstash-only: {logstash_labels - set(LONG_FIELDS.keys())}, "
                         f"python-only: {set(LONG_FIELDS.keys()) - logstash_labels}")


if __name__ == "__main__":
    unittest.main()
