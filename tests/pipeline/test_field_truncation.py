#!/usr/bin/env python3
"""
Field-truncation tagging fixture tests (#252).

SCOPE (same documented scope as tests/pipeline/test_grok_parse_failures.py):
a Python re-implementation of configs/logstash.conf's field-truncation ruby
filter's LOGIC, for fast fixture tests without a live Logstash. It does NOT
exercise the actual compiled ruby filter that runs in the container — see
tests/pipeline's live-verification notes / the manual live check run against
the real stack for that. Keep this in sync by hand with the ruby block at
configs/logstash.conf (Component 4 area, "#252" comment).

process.args/process.parent.args/winlog.event_data.ScriptBlockText are
mapped ignore_above:8191 (#249/#250) — a value longer than that ceiling is
silently dropped from the index while remaining in _source. This filter
tags pipeline.truncated="true" + pipeline.truncated_fields instead of
letting that drop stay invisible.

Run:  python tests/pipeline/test_field_truncation.py  (or: pytest tests/pipeline)
"""

import unittest

CEILING = 8191
LONG_FIELDS = {
    "process.args": lambda e: e.get("process", {}).get("args"),
    "process.parent.args": lambda e: e.get("process", {}).get("parent", {}).get("args"),
    "winlog.event_data.ScriptBlockText": lambda e: e.get("winlog", {}).get("event_data", {}).get("ScriptBlockText"),
}


def tag_truncation(event: dict):
    """Mirrors configs/logstash.conf's #252 ruby filter. Returns the list of
    field labels that exceeded CEILING (empty if none did)."""
    hit = []
    for label, getter in LONG_FIELDS.items():
        val = getter(event)
        if isinstance(val, str) and len(val) > CEILING:
            hit.append(label)
    return hit


class FieldTruncationTaggingTests(unittest.TestCase):
    def test_short_scriptblocktext_not_tagged(self):
        event = {"winlog": {"event_data": {"ScriptBlockText": "Invoke-Something -Arg 1"}}}
        self.assertEqual(tag_truncation(event), [])

    def test_long_scriptblocktext_tagged(self):
        # ~20000 chars, the commonly-cited real PowerShell 4104 chunk size
        # this issue is about — well past the 8191 ignore_above ceiling.
        event = {"winlog": {"event_data": {"ScriptBlockText": "A" * 20000}}}
        self.assertEqual(tag_truncation(event), ["winlog.event_data.ScriptBlockText"])

    def test_exactly_at_ceiling_not_tagged(self):
        # ignore_above:8191 keeps values UP TO 8191 chars indexed — only
        # strictly-over should tag, or every field at the exact boundary
        # would falsely alarm.
        event = {"process": {"args": "A" * 8191}}
        self.assertEqual(tag_truncation(event), [])

    def test_one_over_ceiling_tagged(self):
        event = {"process": {"args": "A" * 8192}}
        self.assertEqual(tag_truncation(event), ["process.args"])

    def test_multiple_long_fields_all_listed(self):
        event = {
            "process": {"args": "A" * 9000, "parent": {"args": "B" * 9000}},
            "winlog": {"event_data": {"ScriptBlockText": "C" * 9000}},
        }
        self.assertEqual(
            tag_truncation(event),
            ["process.args", "process.parent.args", "winlog.event_data.ScriptBlockText"],
        )

    def test_missing_fields_no_crash_no_tag(self):
        self.assertEqual(tag_truncation({}), [])

    def test_non_string_field_ignored(self):
        # Malformed/mistyped upstream data must not crash the filter.
        event = {"process": {"args": 12345}}
        self.assertEqual(tag_truncation(event), [])

    def test_other_long_fields_under_ceiling_not_tagged(self):
        # A field this filter doesn't check (e.g. url.original, also mapped
        # ignore_above:8191 via the long_command_fields dynamic_template) is
        # deliberately out of scope for #252 — ScriptBlockText/process.args
        # are the attacker-controlled fields the issue is about.
        event = {"url": {"original": "A" * 20000}}
        self.assertEqual(tag_truncation(event), [])


if __name__ == "__main__":
    unittest.main()
