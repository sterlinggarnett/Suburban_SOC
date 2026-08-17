#!/usr/bin/env python3
"""
Field-truncation tagging fixture tests (#252, extended #263, #290, #344, #337).

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

import fnmatch
import inspect
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
# #352: dns.answers's own ignore_above (matches the template's dns.answers
# property, #292) — deliberately NOT one of the LONG_FIELDS entries below,
# since dns.answers is an ARRAY and that hash's byte-clamp mechanism only
# ever operates on String values (see the module docstring's #337 note on
# why an array field there would silently no-op).
DNS_ANSWERS_CEILING = 8191
# #337: values are (bracket_path_parts, field_ceiling) — byte-clamp only
# ever applies when field_ceiling * 4 exceeds CEILING (32766, Lucene's
# byte hard limit); 8191/1024 are structurally safe from the Lucene
# immense-term crash by design (8191*4=32764, 1024*4=4096 — both stay
# under Lucene's 32766-byte hard limit even for all-multi-byte content),
# so those only need the char_hit truncation-visibility tag.
LONG_FIELDS = {
    "process.args": (["process", "args"], CEILING),
    "process.parent.args": (["process", "parent", "args"], CEILING),
    "winlog.event_data.ScriptBlockText": (["winlog", "event_data", "ScriptBlockText"], CEILING),
    "winlog.event_data.ImagePath": (["winlog", "event_data", "ImagePath"], CEILING),
    "url.path": (["url", "path"], CEILING),
    "winlog.event_data.CommandLine": (["winlog", "event_data", "CommandLine"], CEILING),
    "network_parsed.uri": (["network_parsed", "uri"], CEILING),
    "user.name": (["user", "name"], CEILING),
    "related.user": (["related", "user"], 8191),
    "process.executable": (["process", "executable"], 8191),
    "process.parent.name": (["process", "parent", "name"], 8191),
    "file.path": (["file", "path"], 1024),
    "user.target.name": (["user", "target", "name"], 1024),
    "process.pe.original_file_name": (["process", "pe", "original_file_name"], 1024),
    "file.hash.sha256": (["file", "hash", "sha256"], 1024),
}


def _nested_get(event: dict, path_parts):
    cur: object = event
    for part in path_parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _flatten(value: list) -> list:
    """Mirrors Ruby's Array#flatten (all levels, not just one) - used by
    tag_oversized_dns_answer for the #352 nested-array fix."""
    out = []
    for item in value:
        if isinstance(item, list):
            out.extend(_flatten(item))
        else:
            out.append(item)
    return out


def _clamp_bytes(val: str, byte_ceiling: int) -> str:
    """Mirrors ruby's val.byteslice(0, byte_ceiling).scrub: cut at a byte
    boundary (which may split a multi-byte character), then repair any
    resulting invalid byte sequence — Python's errors="replace" matches
    scrub's default replacement-character behavior."""
    return val.encode("utf-8")[:byte_ceiling].decode("utf-8", errors="replace")


def _utf16_length(val: str) -> int:
    """Elasticsearch's ignore_above compares against Java's String#length —
    UTF-16 CODE UNITS — not Python's len() (Unicode CODE POINTS). The two
    only diverge for astral-plane characters (code point > U+FFFF, most
    emoji among them): Python's len() counts one as 1, Java/ES counts it
    as 2 (a surrogate pair). Encoding to UTF-16-LE and halving the byte
    count gives the identical count Java/ES uses — mirrors
    configs/logstash.conf's val.encode("UTF-16LE").bytesize / 2."""
    return len(val.encode("utf-16-le")) // 2


def tag_truncation(event: dict):
    """Mirrors configs/logstash.conf's #252/#263/#337 ruby filter. Returns
    (char_hit, byte_hit): field labels dropped by ignore_above (UTF-16
    code-unit count) and field labels defensively byte-clamped to avoid a
    Lucene immense-term document rejection, respectively. Mutually
    exclusive per field — see module docstring for why checking both
    unconditionally would be wrong. #337: byte-clamp is only ever
    attempted when field_ceiling*4 exceeds Lucene's real 32766-byte
    hard limit — a field at a low enough per-field ceiling can't
    structurally reach it even at its own worst-case (all-multi-byte)
    length, so the check is skipped rather than merely always-false."""
    char_hit = []
    byte_hit = []
    for label, (path_parts, field_ceiling) in LONG_FIELDS.items():
        val = _nested_get(event, path_parts)
        if not isinstance(val, str):
            continue
        if _utf16_length(val) > field_ceiling:
            char_hit.append(label)
        elif field_ceiling * 4 > CEILING and len(val.encode("utf-8")) > BYTE_CEILING:
            byte_hit.append(label)
    return char_hit, byte_hit


def tag_oversized_dns_answer(event: dict) -> bool:
    """Mirrors configs/logstash.conf's #352 ruby filter block. dns.answers
    is a flat ARRAY in production (unlike every LONG_FIELDS entry above,
    which are all scalar strings), so this is deliberately a separate
    mechanism, not a LONG_FIELDS entry — same UTF-16 code-unit counting as
    tag_truncation (see _utf16_length), same DNS_ANSWERS_CEILING as the
    real template's dns.answers ignore_above (CeilingConsistencyTests pins
    both). Pure visibility, no clamping: unlike tag_truncation/
    ByteClampTaggingTests, this never mutates the value — #352's own issue
    text is explicit that raising ignore_above or clamping dns.answers
    isn't safe without first making the byte-clamp mechanism array-aware,
    which is out of scope here.
    security-auditor round 2 MEDIUM: a SCALAR dns.answers (this corpus's
    own established fixture convention — #292's fixtures.json/test_live_
    fire.py both model `answers` as scalar, and Elasticsearch indexes a
    1-element array and a bare scalar IDENTICALLY) is checked the same as
    an array element, not skipped — the first draft's `isinstance(answers,
    list)` guard silently skipped exactly the shape #352's own
    attacker-controllable ingest path (an unauthenticated :5514 POST)
    actually produces."""
    # code-reviewer follow-up: reuse the file's existing nested-traversal
    # primitive instead of re-implementing it here — _nested_get already
    # handles a "dns" key that exists but isn't a dict (returns None,
    # confirmed live against the real pinned Logstash image to match
    # Ruby's own event.get("[dns][answers]") behavior for the same
    # malformed shape).
    # security-auditor round 3: _flatten (not a bare isinstance ternary) -
    # a NESTED array (e.g. [["<9000 chars>"]]) is silently unindexed past
    # ignore_above:8191 exactly like a flat array element (live-confirmed
    # against the real running Elasticsearch: it flattens arrays-of-arrays
    # for a keyword-mapped field), but would otherwise never satisfy
    # isinstance(a, str) below and skip the check entirely - same
    # unauthenticated :5514 ingest path as the scalar case above, one
    # extra bracket away from the flat shape that IS checked. Mirrors
    # configs/logstash.conf's ruby elements = answers.is_a?(Array) ?
    # answers.flatten : [answers].
    answers = _nested_get(event, ["dns", "answers"])
    if answers is None:
        return False
    elements = _flatten(answers) if isinstance(answers, list) else [answers]
    return any(isinstance(a, str) and _utf16_length(a) > DNS_ANSWERS_CEILING for a in elements)


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

    def test_user_name_over_ceiling_tagged(self):
        # #337: user.name was mapped keyword with NO ignore_above at all —
        # unlike every field above, which was ALREADY at ignore_above:
        # 32766 and just missing a clamp entry, user.name previously had
        # NO char-ceiling backstop whatsoever (Elasticsearch's own
        # unbounded default), so a long value reached Lucene directly
        # instead of being safely ignore_above-dropped first. Now in scope
        # with the same ceiling as its siblings above.
        event = {"user": {"name": "A" * 40000}}
        self.assertEqual(tag_truncation(event), (["user.name"], []))

    def test_related_user_over_8191_ceiling_truncated(self):
        # #337 security-auditor follow-up: related.user is at 8191, NOT
        # ceiling (32766) like user.name above — ECS defines related.* as
        # an array field, and this filter only clamps String values, so a
        # 32766-tier entry would satisfy CeilingConsistencyTests while
        # silently no-oping the byte-clamp the moment a real producer
        # populates it (the same dns.answers trap the template's own
        # _meta documents). Mapped at 8191 instead, matching its
        # related.hosts sibling — no producer anywhere in configs/
        # logstash.conf today (grep-confirmed), pre-emptive hardening
        # matching #344's IpAddress precedent either way.
        event = {"related": {"user": "A" * 9000}}
        self.assertEqual(tag_truncation(event), (["related.user"], []))

    def test_process_executable_over_8191_ceiling_truncated(self):
        # #337: process.executable is an EXPLICIT property at
        # ignore_above:8191 (not 32766) — the first of the lower-ceiling
        # fields the truncation filter previously had zero visibility
        # into, closing #252's own stated purpose (make silent
        # ignore_above drops MEASURABLE) for it.
        event = {"process": {"executable": "A" * 9000}}
        self.assertEqual(tag_truncation(event), (["process.executable"], []))

    def test_process_executable_under_8191_ceiling_not_tagged(self):
        event = {"process": {"executable": "A" * 100}}
        self.assertEqual(tag_truncation(event), ([], []))

    def test_process_parent_name_over_8191_ceiling_truncated(self):
        event = {"process": {"parent": {"name": "A" * 9000}}}
        self.assertEqual(tag_truncation(event), (["process.parent.name"], []))

    def test_file_path_over_1024_ceiling_truncated(self):
        # #337: file.path has no explicit property — falls to
        # strings_as_keyword's default ignore_above:1024, the lowest tier
        # this filter now tracks.
        event = {"file": {"path": "A" * 2000}}
        self.assertEqual(tag_truncation(event), (["file.path"], []))

    def test_user_target_name_over_1024_ceiling_truncated(self):
        event = {"user": {"target": {"name": "A" * 2000}}}
        self.assertEqual(tag_truncation(event), (["user.target.name"], []))

    def test_process_pe_original_file_name_over_1024_ceiling_truncated(self):
        event = {"process": {"pe": {"original_file_name": "A" * 2000}}}
        self.assertEqual(tag_truncation(event), (["process.pe.original_file_name"], []))

    def test_file_hash_sha256_over_1024_ceiling_truncated(self):
        event = {"file": {"hash": {"sha256": "A" * 2000}}}
        self.assertEqual(tag_truncation(event), (["file.hash.sha256"], []))

    def test_multiple_ceiling_tiers_tagged_together(self):
        # One event tripping all 3 tiers at once (32766/8191/1024) — each
        # gets its OWN correct ceiling applied, not one global value.
        event = {
            "user": {"name": "A" * 33000, "target": {"name": "B" * 2000}},
            "process": {"parent": {"name": "C" * 9000}},
        }
        got, byte_got = tag_truncation(event)
        self.assertEqual(set(got), {"user.name", "user.target.name", "process.parent.name"})
        self.assertEqual(byte_got, [])

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

    def test_user_name_multibyte_byte_clamped(self):
        # #337: the actually-dangerous branch for the acute part of this
        # fix — user.name previously had NO ignore_above at all, so a
        # byte-heavy value reached Lucene directly with nothing to catch
        # it, unlike the other fields above which were already at
        # ignore_above:32766 and only missing a clamp entry.
        event = {"user": {"name": "\U0001F600" * 9000}}
        self.assertEqual(tag_truncation(event), ([], ["user.name"]))

    def test_lower_ceiling_field_never_byte_clamped_even_with_heavy_multibyte(self):
        # #337: the load-bearing regression case for the whole per-field-
        # ceiling design. process.executable's real ceiling is 8191
        # UTF-16 code units, and 8191*4=32764 bytes is the worst-case byte
        # count even for all-multi-byte content — structurally incapable
        # of reaching Lucene's 32766-byte hard limit, so this field must
        # NEVER reach the byte-clamp branch (field_ceiling*4 > 32766 is
        # false for 8191). 4095 emoji = 8190 UTF-16 units, legitimately
        # UNDER the 8191 ceiling — proves the field is correctly left
        # completely untagged, not just "byte-clamp skipped." Live-
        # verified against the real ruby filter in a throwaway
        # logstash:9.3.2 container, not just this Python mirror.
        event = {"process": {"executable": "\U0001F600" * 4095}}
        self.assertEqual(tag_truncation(event), ([], []))

    def test_lower_ceiling_field_astral_over_ceiling_truncated_not_byte_clamped(self):
        # #337 security-auditor follow-up: the actual UTF-16-vs-code-point
        # divergence this fix closes. 8000 emoji = 8000 Python len()
        # (code points, UNDER 8191 — this is what the filter's PREVIOUS
        # code-point-based check would have seen, silently missing the
        # drop) but 16000 UTF-16 code units (Elasticsearch's own count,
        # OVER 8191) — ES genuinely ignore_above-drops this value, so the
        # filter must tag it truncated. Confirms the fix's whole point:
        # char_hit fires based on UTF-16 length, not len(). NOT byte-
        # clamped either (wrong tier — 16000*2=32000 bytes stays under
        # Lucene's real limit anyway, and this tier never reaches that
        # branch regardless — see field_ceiling*4 > 32766 above). The
        # field's own value is untouched by a truncation tag (unlike a
        # byte-clamp, tagging doesn't rewrite _source).
        event = {"process": {"executable": "\U0001F600" * 8000}}
        got = tag_truncation(event)
        self.assertEqual(got, (["process.executable"], []))

    def test_astral_char_ceiling_boundary_utf16_units_not_code_points(self):
        # #337: pins the EXACT boundary in UTF-16 units (8191), not code
        # points — 4095 emoji = 8190 units (under, not tagged), 4096
        # emoji = 8192 units (over, tagged). A code-point-based check
        # would see 4095/4096 code points, both comfortably under 8191,
        # and never tag either — this is the precise fixture that
        # distinguishes correct (UTF-16-aware) from buggy (code-point)
        # counting, live-verified against the real ruby filter.
        under = {"process": {"executable": "\U0001F600" * 4095}}
        over = {"process": {"executable": "\U0001F600" * 4096}}
        self.assertEqual(tag_truncation(under), ([], []))
        self.assertEqual(tag_truncation(over), (["process.executable"], []))

    def test_process_executable_exactly_at_8191_ceiling_not_tagged(self):
        # code-reviewer follow-up: the 32766 tier already pins its exact
        # boundary (test_exactly_at_byte_ceiling_not_tagged /
        # test_one_over_ceiling_tagged) — the two new lower tiers didn't
        # have the same precision, so an off-by-one (e.g. accidental >=)
        # in the field_ceiling comparison wouldn't have been caught.
        event = {"process": {"executable": "A" * 8191}}
        self.assertEqual(tag_truncation(event), ([], []))

    def test_process_executable_one_over_8191_ceiling_tagged(self):
        event = {"process": {"executable": "A" * 8192}}
        self.assertEqual(tag_truncation(event), (["process.executable"], []))

    def test_file_path_exactly_at_1024_ceiling_not_tagged(self):
        event = {"file": {"path": "A" * 1024}}
        self.assertEqual(tag_truncation(event), ([], []))

    def test_file_path_one_over_1024_ceiling_tagged(self):
        event = {"file": {"path": "A" * 1025}}
        self.assertEqual(tag_truncation(event), (["file.path"], []))

    def test_clamp_helper_produces_valid_utf8_under_byte_ceiling(self):
        val = "\U0001F600" * 9000
        clamped = _clamp_bytes(val, BYTE_CEILING)
        self.assertLessEqual(len(clamped.encode("utf-8")), BYTE_CEILING)
        # Round-trips clean (scrub's replacement-character repair leaves
        # valid UTF-8, not raw truncated bytes that would themselves fail to
        # parse).
        clamped.encode("utf-8").decode("utf-8")


class OversizedDnsAnswerTaggingTests(unittest.TestCase):
    """#352 (security-auditor follow-up to #292/#351): dns.answers is a
    flat ARRAY, structurally excluded from LONG_FIELDS' string-only
    byte-clamp mechanism (see that dict's own #337 comment on the
    identical related.user trap). An individual answer over
    DNS_ANSWERS_CEILING is silently unindexed by ES's ignore_above with no
    error and no pipeline.truncated tag either way — this filter adds
    visibility only (a boolean tag), deliberately no clamp/raise. Live-
    verified (not just unit-tested) against the real pinned
    docker.elastic.co/logstash/logstash:9.3.2 image: the exact ruby block
    below, extracted verbatim from configs/logstash.conf and run through a
    throwaway stdin/stdout pipeline, produced the identical
    tag/no-tag result for every case in this class, including the 8191
    vs. 8192 boundary and the second-element-only case.
    HONEST DISCLOSURE (tester-debugger, #352 review): the >8191 threshold
    these tests pin is live-verified as structurally unreachable for real
    TXT-record traffic today — Zeek's own DNS analyzer independently
    truncates a TXT record's joined answers[] string at ~4096 chars, with
    no marker, before Elasticsearch's ignore_above ever gets a chance to
    matter (filed as #389, needs a Zeek-side fix). These tests still
    prove the FILTER LOGIC is correct for any value that does reach
    8191+ chars (defense-in-depth against a future non-Zeek producer, a
    future Zeek version without this cap, or #389 being fixed) - they do
    not claim TXT records reach this ceiling in production right now."""

    def test_short_array_not_tagged(self):
        event = {"dns": {"answers": ["v=spf1 include:_spf.example.com ~all", "short"]}}
        self.assertFalse(tag_oversized_dns_answer(event))

    def test_exactly_at_ceiling_not_tagged(self):
        event = {"dns": {"answers": ["A" * DNS_ANSWERS_CEILING]}}
        self.assertFalse(tag_oversized_dns_answer(event))

    def test_one_over_ceiling_tagged(self):
        event = {"dns": {"answers": ["A" * (DNS_ANSWERS_CEILING + 1)]}}
        self.assertTrue(tag_oversized_dns_answer(event))

    def test_second_element_over_ceiling_still_tagged(self):
        # Per-element check, not just the first array entry.
        event = {"dns": {"answers": ["short-one", "B" * (DNS_ANSWERS_CEILING + 500)]}}
        self.assertTrue(tag_oversized_dns_answer(event))

    def test_nested_array_oversized_element_tagged(self):
        # security-auditor round 3 MEDIUM: a NESTED array (one extra
        # bracket beyond the flat shape) is silently unindexed by ES's
        # ignore_above exactly like a flat array element - live-confirmed
        # against a real running Elasticsearch (indexed [["<9000 chars>"]]
        # into a real keyword-mapped dns.answers field: 0 hits on an exact
        # term query for the value; a short nested value DID match,
        # proving ES flattens arrays-of-arrays rather than rejecting or
        # ignoring them outright). Reachable via the same unauthenticated
        # :5514 POST already documented for the scalar case.
        event = {"dns": {"answers": [["A" * (DNS_ANSWERS_CEILING + 1)]]}}
        self.assertTrue(tag_oversized_dns_answer(event))

    def test_nested_array_short_element_not_tagged(self):
        event = {"dns": {"answers": [["short-nested-value"]]}}
        self.assertFalse(tag_oversized_dns_answer(event))

    def test_no_dns_field_no_crash_no_tag(self):
        self.assertFalse(tag_oversized_dns_answer({"query": "example.com"}))

    def test_no_answers_field_no_crash_no_tag(self):
        self.assertFalse(tag_oversized_dns_answer({"dns": {}}))

    def test_dns_field_not_a_dict_no_crash_no_tag(self):
        # code-reviewer follow-up: malformed upstream data where "dns"
        # itself isn't an object (a scalar or an array, not the expected
        # {"answers": [...]} shape) - live-verified against the real
        # pinned Logstash image that Ruby's event.get("[dns][answers]")
        # returns nil for all of these shapes, matching this mirror's
        # guarded None/False return on both sides, no crash either way.
        for malformed_dns in ("not-a-dict", 12345, ["a", "b"]):
            with self.subTest(dns=malformed_dns):
                self.assertFalse(tag_oversized_dns_answer({"dns": malformed_dns}))

    def test_oversized_scalar_answers_tagged(self):
        # security-auditor round 2 MEDIUM: an earlier draft of this test
        # asserted the OPPOSITE of what's correct here, with reasoning
        # that doesn't hold up - "a lone scalar has always been correctly
        # handled by ES's own ignore_above check" describes exactly the
        # SILENT, UNTAGGED drop this whole filter exists to surface, not
        # a reason to skip it. #292's own established fixture convention
        # models `answers` as a scalar (fixtures.json, test_live_fire.py),
        # and Elasticsearch indexes a 1-element array and a bare scalar
        # IDENTICALLY (test_live_fire.py's own note) - so an oversized
        # scalar is silently unindexed exactly the same way an oversized
        # array element is, and must get the same tag.
        event = {"dns": {"answers": "C" * (DNS_ANSWERS_CEILING + 500)}}
        self.assertTrue(tag_oversized_dns_answer(event))

    def test_short_scalar_answers_not_tagged(self):
        event = {"dns": {"answers": "v=spf1 include:_spf.example.com ~all"}}
        self.assertFalse(tag_oversized_dns_answer(event))

    def test_non_string_scalar_answers_no_crash_no_tag(self):
        # Malformed/mistyped upstream data (e.g. a numeric dns.answers)
        # must not crash the filter - matches FieldTruncationTaggingTests.
        # test_non_string_field_ignored's established convention.
        event = {"dns": {"answers": 12345}}
        self.assertFalse(tag_oversized_dns_answer(event))

    def test_non_string_element_ignored_not_crash(self):
        event = {"dns": {"answers": [12345, "A" * (DNS_ANSWERS_CEILING + 1)]}}
        self.assertTrue(tag_oversized_dns_answer(event))

    def test_astral_char_ceiling_boundary_utf16_units_not_code_points(self):
        # Same astral-plane UTF-16-vs-code-point divergence as
        # ByteClampTaggingTests.test_astral_char_ceiling_boundary_utf16_
        # units_not_code_points, at the identical 8191 ceiling: 4095 emoji
        # = 8190 UTF-16 units (under, not tagged), 4096 emoji = 8192 units
        # (over, tagged). A code-point-based check would see 4095/4096
        # code points, both comfortably under 8191, and never tag either.
        under = {"dns": {"answers": ["\U0001F600" * 4095]}}
        over = {"dns": {"answers": ["\U0001F600" * 4096]}}
        self.assertFalse(tag_oversized_dns_answer(under))
        self.assertTrue(tag_oversized_dns_answer(over))


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

    def _logstash_dns_answers_block_text(self):
        # #352: anchor every check below to text AFTER this marker, not
        # the whole file - the original long_fields block above also
        # contains a UTF-16LE...bytesize / 2 expression (on its own line,
        # feeding a separate `if utf16_length > field_ceiling` check), and
        # this file is explicitly one of the places that comparison could
        # plausibly be reshaped in a future edit. Scoping prevents these
        # tests from ever validating/finding the WRONG block instead of
        # failing loudly if the #352 block's shape changes.
        # security-auditor round 3 MEDIUM: the marker previously started at
        # `answers = event.get(...)`, INSIDE the ruby block - the `if
        # [dns][answers] {` Logstash-level guard and the `elements = ...`
        # scalar/array/nested-array normalization line both sit ABOVE that
        # point, so neither was ever in scope for any assertion below (a
        # typo'd or deleted guard, or a reverted .flatten, would have
        # stayed CI-green). Starting at the guard line covers both.
        text = LOGSTASH_CONF_PATH.read_text(encoding="utf-8")
        marker = "if [dns][answers] {"
        marker_pos = text.find(marker)
        self.assertGreater(
            marker_pos, -1,
            f"could not find {marker!r} in configs/logstash.conf - has the "
            f"#352 oversized-dns-answer block been renamed or removed?")
        return text[marker_pos:]

    def _logstash_dns_answers_ceiling(self):
        # #352: the oversized-dns-answer ruby block has no named variable
        # (unlike ceiling/byte_ceiling above) - the literal is inline,
        # TWICE: a.bytesize > N (the cheap short-circuit, security-auditor
        # round 2) and (a.encode("UTF-16LE").bytesize / 2) > N (the real,
        # semantically authoritative check). Both must agree with each
        # other AND with DNS_ANSWERS_CEILING - a drift between the two
        # inline literals (e.g. someone "optimizing" the short-circuit
        # threshold without updating the real check, or vice versa) would
        # silently break the short-circuit's own correctness proof (see
        # that comment in configs/logstash.conf), not just this test's
        # accuracy.
        block = self._logstash_dns_answers_block_text()
        match = re.search(
            r"a\.bytesize\s*>\s*(\d+)\s*&&\s*\(a\.encode\(\"UTF-16LE\"\)\.bytesize\s*/\s*2\)\s*>\s*(\d+)",
            block)
        self.assertIsNotNone(
            match, "could not find the #352 oversized-dns-answer ceiling "
            "literals (bytesize short-circuit + UTF-16LE check) in "
            "configs/logstash.conf")
        byte_ceiling, utf16_ceiling = int(match.group(1)), int(match.group(2))
        self.assertEqual(
            byte_ceiling, utf16_ceiling,
            "the #352 bytesize short-circuit ceiling and the real UTF-16LE "
            "ceiling have drifted apart in configs/logstash.conf - the "
            "short-circuit's own correctness proof requires them to match")
        return utf16_ceiling

    def test_logstash_dns_answers_ceiling_matches_this_modules_constant(self):
        # #352: keeps the hardcoded ceiling in the ruby block's inline
        # comparison in lockstep with DNS_ANSWERS_CEILING here - same
        # drift risk the ceiling/byte_ceiling checks above already guard
        # against for the other two constants.
        self.assertEqual(self._logstash_dns_answers_ceiling(), DNS_ANSWERS_CEILING)

    def test_logstash_dns_answers_block_field_and_tag_names_not_typoed(self):
        # security-auditor round 2 MEDIUM: this repo has hit the "a nested-
        # field-path or output-name typo ships CI-green and silently dead"
        # failure class three times before (#263's flat "process.args" vs
        # nested [process][args], #228's dead qtype_name/rcode_name
        # renames, #217's ImagePath) - nothing previously asserted the
        # #352 block's actual source field path, output field name, or tag
        # name, so a one-character typo in any of the three would pass
        # every OversizedDnsAnswerTaggingTests test (which only exercises
        # the Python mirror) and the ceiling tests above (which only pin
        # the numeric literal) while the real filter silently never fires
        # or writes the wrong field.
        # security-auditor round 3: also pins the Logstash-level guard and
        # the .flatten normalization (the nested-array fix) - both sat
        # outside this test's scope before the marker was corrected above.
        block = self._logstash_dns_answers_block_text()
        for literal in (
                "if [dns][answers] {",
                'event.get("[dns][answers]")',
                "answers.is_a?(Array) ? answers.flatten : [answers]",
                'event.set("[pipeline][oversized_dns_answer]", "true")',
                'event.tag("pipeline_oversized_dns_answer")'):
            with self.subTest(literal=literal):
                self.assertIn(
                    literal, block,
                    f"configs/logstash.conf's #352 block no longer contains "
                    f"{literal!r} - renamed, typoed, or removed?")

    def test_dns_answers_ceiling_matches_real_template(self):
        # #352: DNS_ANSWERS_CEILING must track the real template's
        # dns.answers ignore_above (#292), not a value chosen independently
        # - a future template change that raises/lowers it (e.g. once the
        # byte-clamp is made array-aware, per this issue's own proposed
        # fix note) must fail this test loudly rather than leave the
        # visibility tag silently checking the wrong boundary.
        template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        props = template["template"]["mappings"]["properties"]
        self.assertEqual(props["dns"]["properties"]["answers"]["ignore_above"], DNS_ANSWERS_CEILING)

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
            "user.name": props["user"]["properties"]["name"]["ignore_above"],
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

    _NO_SUCH_PROPERTY = object()

    def _explicit_ignore_above(self, dotted_path):
        """The real template's ignore_above for an EXPLICIT property.
        Returns _NO_SUCH_PROPERTY if the path isn't an explicit property at
        all (falls to a dynamic_template instead), or None if the property
        EXISTS but has no ignore_above set (Elasticsearch's own unbounded
        default — exactly user.name's pre-#337 state). security-auditor
        follow-up: these two cases must not collapse to the same return
        value — a caller treating them as equivalent could pass on a field
        that's actually unbounded, believing it correctly falls to a lower
        dynamic-template default."""
        template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        cur = template["template"]["mappings"]["properties"]
        parts = dotted_path.split(".")
        for i, part in enumerate(parts):
            if part not in cur:
                return self._NO_SUCH_PROPERTY
            node = cur[part]
            if i == len(parts) - 1:
                return node.get("ignore_above")
            cur = node.get("properties", {})
        return self._NO_SUCH_PROPERTY

    def test_337_lower_ceiling_fields_match_reality(self):
        # #337: LONG_FIELDS/long_fields now track fields at ceilings LOWER
        # than 32766 — this test derives each one's EXPECTED ceiling from
        # the real template rather than trusting the hand-maintained
        # 8191/1024 literals to stay accurate, same "don't trust a comment,
        # verify against the file" discipline as every other check in this
        # class.
        #
        # process.executable/process.parent.name/related.user are EXPLICIT
        # properties at ignore_above:8191 — direct lookup. Asserts an
        # actual int, not just equality with expected_ceiling, so a
        # property that regressed to "exists but no ignore_above"
        # (_explicit_ignore_above returning None, not _NO_SUCH_PROPERTY)
        # fails loudly here instead of comparing None == 8191 in a way
        # that could theoretically coincide.
        for label in ("process.executable", "process.parent.name", "related.user"):
            _parts, expected_ceiling = LONG_FIELDS[label]
            actual = self._explicit_ignore_above(label)
            self.assertIsInstance(actual, int,
                                  f"{label}: template ignore_above is {actual!r}, not a real ceiling")
            self.assertEqual(actual, expected_ceiling,
                             f"{label}: template ignore_above={actual}, LONG_FIELDS expects {expected_ceiling}")

        # related.hosts isn't tracked in LONG_FIELDS (no attacker-
        # controlled-content concern the way user.name/related.user are),
        # but it's the sibling ignore_above:8191 was explicitly chosen to
        # match — verify that precedent still holds.
        self.assertEqual(self._explicit_ignore_above("related.hosts"), 8191,
                         "related.hosts drifted from ignore_above:8191 — related.user was "
                         "deliberately mapped to match it (#337 security-auditor review), "
                         "re-verify that reasoning still applies")

        # file.path/user.target.name/process.pe.original_file_name/
        # file.hash.sha256 have NO explicit property — they fall to
        # strings_as_keyword's default ignore_above:1024. Verify BOTH
        # halves of that claim, not just the number: no explicit property
        # exists (or this reasoning no longer applies and the test would
        # be validating the wrong thing), and none of them accidentally
        # matches long_command_fields' glob (which would instead raise
        # them to ceiling — the exact #290 case-normalization-adjacent
        # drift this repo has already hit once).
        template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        dynamic_templates = template["template"]["mappings"]["dynamic_templates"]
        strings_as_keyword_default = next(
            dt["strings_as_keyword"]["mapping"]["ignore_above"]
            for dt in dynamic_templates if "strings_as_keyword" in dt
        )
        long_command_fields_globs = next(
            dt["long_command_fields"]["path_match"]
            for dt in dynamic_templates if "long_command_fields" in dt
        )
        for label in ("file.path", "user.target.name", "process.pe.original_file_name", "file.hash.sha256"):
            _parts, expected_ceiling = LONG_FIELDS[label]
            self.assertIs(
                self._explicit_ignore_above(label), self._NO_SUCH_PROPERTY,
                f"{label} is now an EXPLICIT template property — this test's strings_as_keyword-"
                f"default assumption no longer applies, update LONG_FIELDS to the real ignore_above"
            )
            # fnmatchcase, not fnmatch: Elasticsearch's path_match is
            # case-sensitive; plain fnmatch applies the HOST OS's
            # normcase, which on a non-POSIX CI runner would silently
            # case-fold this comparison and diverge from real ES behavior.
            matches_command_glob = any(fnmatch.fnmatchcase(label, glob) for glob in long_command_fields_globs)
            self.assertFalse(
                matches_command_glob,
                f"{label} now matches a long_command_fields glob ({long_command_fields_globs}) — it "
                f"would get ignore_above:{CEILING}, not strings_as_keyword's default, AND would need "
                f"a byte-clamp entry (see test_every_ceiling_field_has_a_byte_clamp_entry)"
            )
            self.assertEqual(
                strings_as_keyword_default, expected_ceiling,
                f"strings_as_keyword's default ignore_above changed to {strings_as_keyword_default}, "
                f"but LONG_FIELDS still expects {expected_ceiling} for {label}"
            )

    def test_dynamic_template_only_fields_use_the_dynamic_templates_own_ceiling(self):
        # #337 security-auditor follow-up: winlog.event_data.CommandLine
        # and network_parsed.uri are invisible to _template_ceiling_paths()
        # (dynamic_template matches, not explicit properties — see
        # test_every_ceiling_field_has_a_byte_clamp_entry's own docstring
        # for why), so the field-LIST bidirectional check there proves
        # logstash.conf and LONG_FIELDS agree on including them, but
        # neither that check nor the walk-based ones anchor WHICH ceiling
        # they're at to the template's actual dynamic_template value — two
        # hand-maintained lists could drift to the SAME wrong tier
        # together and every existing assertion would still pass.
        template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        dynamic_ceiling = template["template"]["mappings"]["dynamic_templates"][0][
            "long_command_fields"]["mapping"]["ignore_above"]
        for label in ("winlog.event_data.CommandLine", "network_parsed.uri"):
            _parts, expected_ceiling = LONG_FIELDS[label]
            self.assertEqual(
                dynamic_ceiling, expected_ceiling,
                f"{label} is tracked at LONG_FIELDS ceiling {expected_ceiling}, but the real "
                f"long_command_fields dynamic_template it actually matches is at ignore_above:"
                f"{dynamic_ceiling} — these must agree or the byte-clamp guard "
                f"(field_ceiling*4 > 32766) could silently stop firing for this field"
            )

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
        long_fields_block = re.search(r"long_fields\s*=\s*\{(.*?)\n      \}", logstash_text, re.DOTALL)
        self.assertIsNotNone(long_fields_block,
                             "could not find 'long_fields = {...}' in configs/logstash.conf")
        block_text = long_fields_block.group(1)
        # #337: entries are now ["label", field_ceiling] pairs, not bare
        # "label" strings — field_ceiling is either the `ceiling` variable
        # (32766, the only tier needing byte-clamp) or a lower numeric
        # literal (8191/1024, truncation-visibility only). Two separate
        # extractions: only-at-ceiling labels for the byte-clamp-specific
        # checks below (must match template_paths, which by construction
        # only ever contains 32766-ceiling fields), and every label
        # regardless of tier for the full bidirectional sync check.
        logstash_labels_at_ceiling = set(re.findall(r'=>\s*\[\s*"([^"]+)"\s*,\s*ceiling\s*\]', block_text))
        logstash_labels_all = set(re.findall(r'=>\s*\[\s*"([^"]+)"', block_text))

        missing_from_logstash = template_paths - logstash_labels_at_ceiling
        self.assertEqual(set(), missing_from_logstash,
                         f"template field(s) mapped ignore_above:{CEILING} with no matching entry "
                         f"in configs/logstash.conf's long_fields clamp hash — the byte-clamp never "
                         f"runs for them, risking a Lucene immense-term whole-document rejection on "
                         f"an unclamped field: {missing_from_logstash}")

        python_labels_at_ceiling = {label for label, (_parts, c) in LONG_FIELDS.items() if c == CEILING}
        missing_from_python_mirror = template_paths - python_labels_at_ceiling
        self.assertEqual(set(), missing_from_python_mirror,
                         f"template field(s) mapped ignore_above:{CEILING} missing (or mapped at the "
                         f"wrong ceiling) in this module's own LONG_FIELDS mirror — tag_truncation() "
                         f"won't byte-clamp them even though the real ruby filter does, giving this "
                         f"test suite false confidence: {missing_from_python_mirror}")

        # #344 security-auditor MEDIUM: everything above derives expectations
        # FROM the template, so a hand-added entry that exists ONLY in one of
        # the two hand-maintained lists (e.g. a dynamic-template-only field
        # like CommandLine/network_parsed.uri, invisible to template_paths by
        # construction) was never checked against the other at all — deleting
        # the new logstash.conf entry left every other assertion in this test
        # green. This closes that gap directly: the two hand-maintained lists
        # must agree with EACH OTHER, independent of what the template walk
        # can see, covering every current and future dynamic-template-only
        # entry the walk-based checks above structurally cannot. #337:
        # extended to also cross-check that both sides agree on WHICH
        # ceiling each field uses, not just that the label exists on both
        # sides — a field silently drifting between ceiling tiers on one
        # side only is the same "test suite gives false confidence" shape.
        self.assertEqual(set(LONG_FIELDS.keys()), logstash_labels_all,
                         "configs/logstash.conf's long_fields hash and this module's LONG_FIELDS "
                         "mirror have drifted apart — every clamped field must be listed in both, "
                         "or either the ruby filter or the Python test mirror silently stops "
                         f"matching reality. logstash-only: {logstash_labels_all - set(LONG_FIELDS.keys())}, "
                         f"python-only: {set(LONG_FIELDS.keys()) - logstash_labels_all}")

        # #337 security-auditor follow-up: (8191|1024) was a hardcoded
        # alternation — silently blind to a future THIRD lower tier (e.g.
        # a field added at 16384), the exact "nobody remembered to update
        # every place" class this whole extension exists to close. (\d+)
        # matches any numeric ceiling; it can never accidentally capture
        # the `ceiling` IDENTIFIER used by the 32766-tier entries above,
        # so the two extractions stay non-overlapping.
        logstash_lower_tier_pairs = set(re.findall(r'=>\s*\[\s*"([^"]+)"\s*,\s*(\d+)\s*\]', block_text))
        python_lower_tier_pairs = {
            (label, str(c)) for label, (_parts, c) in LONG_FIELDS.items() if c != CEILING
        }
        self.assertEqual(
            python_lower_tier_pairs, logstash_lower_tier_pairs,
            "configs/logstash.conf's long_fields hash and this module's LONG_FIELDS mirror "
            "disagree on a field's specific lower-tier ceiling — tag_truncation() would "
            f"tag at the wrong threshold. logstash: {logstash_lower_tier_pairs}, "
            f"python: {python_lower_tier_pairs}"
        )

    def test_lower_tier_byte_clamp_guard_formula_matches_python_mirror(self):
        # #337 security-auditor follow-up: the byte-clamp gate
        # (field_ceiling * 4 > ceiling) is IDENTICAL logic in
        # configs/logstash.conf and this module's tag_truncation(), but
        # nothing previously checked that — the bidirectional checks above
        # compare LONG_FIELDS *data* (which fields, which tier), not the
        # *formula* applied to that data, so the two files' guard
        # expressions could silently diverge (e.g. one using `* 4`, the
        # other `* 3`) with every other assertion in this class still
        # green. A logstash.conf comment already promised this test exists
        # by name — it did not, until now (caught by the same follow-up
        # review that found the gap itself).
        logstash_text = LOGSTASH_CONF_PATH.read_text(encoding="utf-8")
        match = re.search(r"elsif field_ceiling \* (\d+) > ceiling", logstash_text)
        self.assertIsNotNone(match,
                             "could not find the 'elsif field_ceiling * N > ceiling' byte-clamp "
                             "guard in configs/logstash.conf — has it been reworded?")
        logstash_multiplier = int(match.group(1))

        python_source = inspect.getsource(tag_truncation)
        python_match = re.search(r"field_ceiling \* (\d+) > CEILING", python_source)
        self.assertIsNotNone(python_match,
                             "could not find the 'field_ceiling * N > CEILING' byte-clamp guard "
                             "in this module's tag_truncation() — has it been reworded?")
        python_multiplier = int(python_match.group(1))

        self.assertEqual(
            logstash_multiplier, python_multiplier,
            f"configs/logstash.conf's byte-clamp guard uses field_ceiling * {logstash_multiplier}, "
            f"but this module's tag_truncation() uses field_ceiling * {python_multiplier} — the two "
            f"filters would disagree on which lower-tier fields ever need byte-clamping"
        )
        # Pin the multiplier itself, not just cross-file agreement — the
        # true worst-case ratio (UTF-16-aware) is 3 bytes per code unit
        # (BMP 3-byte characters); *4 (the original code-point-era
        # estimate) is deliberately more conservative, not tighter, so
        # anchor to *4 explicitly rather than let both sides drift to some
        # other still-mutually-consistent value.
        self.assertEqual(logstash_multiplier, 4)


if __name__ == "__main__":
    unittest.main()
