#!/usr/bin/env python3
"""
Dashboard .keyword field-mapping fixture tests (#341).

SCOPE: static analysis of configs/server/*.ndjson (deployed Kibana saved
objects) against the two ES index templates this repo checks in
(logstash-security-template.json, soar-actions-template.json). No live
Kibana/Elasticsearch needed.

Every string field EXPLICITLY mapped in either template is a bare
`keyword` (or, for a few fields, `ip`) — never `text` with a `keyword`
multi-field, so `.keyword` never resolves to a real sub-field. A Kibana
panel's terms-agg bucket field referencing "<field>.keyword" against
either template therefore matches nothing and the panel silently renders
empty on real telemetry — same symptom as if no data existed at all,
confirmed 5 times by hand before this test existed: findings/
20260629-dashboard-panel-audit.md's Network dashboard fix (commit
be95698); #341's Endpoint dashboard fix, which itself found 3 MORE
instances beyond the 4 the issue described, in the same file; this test's
first draft finding 15 further instances across 7 more dashboard files;
and security-auditor follow-up review of that draft finding 6 MORE
(3 on logstash-security's executive dashboard, 1 on soar-actions', and 2
in a fieldFormatMap the draft didn't scan at all) that the draft's
conservative "unmapped field -> skip" rule was wrongly letting through.

Two GOVERNED_INDEX_PATTERNS, not one, each with its own exhaustiveness
rule for what "unmapped" means:

- logstash-* (logstash-security-template.json): has TWO dynamic_templates,
  long_command_fields (narrow glob) and strings_as_keyword (catches EVERY
  remaining string field with no glob restriction at all). Neither has a
  keyword multi-field. That makes this template's bare-keyword coverage
  EXHAUSTIVE: a string field referenced here that isn't an explicit
  property still can't have a real .keyword sub-field, because
  strings_as_keyword is guaranteed to have mapped it as bare keyword too.
  This is exactly the gap security-auditor review of the first draft
  found: nist.function/threat.technique.id/threat.technique.name are
  real, populated (configs/logstash.conf's Category-0-Zeek-classification
  block) logstash-* fields, invisible to the old explicit-properties-only
  walk, but still provably broken.
- soar-actions-* (soar-actions-template.json): has NO dynamic_templates
  section at all, so a field that ISN'T one of its explicit properties
  falls to Elasticsearch's own DEFAULT dynamic mapping, which DOES
  produce a real text+keyword multi-field. Only this template's explicit
  properties (e.g. action.type, confirmed broken by the same auditor
  review) are provably bare-keyword; everything else is a genuine
  "don't know," not a violation.

A third case — an index pattern with NO checked-in template at all, e.g.
control_status_dashboard.ndjson's "soc-controls" — gets ES's default
dynamic mapping across the board, so its .keyword references may be (and,
confirmed by hand, currently are) entirely legitimate. Not in
GOVERNED_INDEX_PATTERNS, so never flagged: this is the mock-vs-real split
docs/AI_conversation_transcript.md describes, and flagging it would be a
guess, not a finding.

Two more narrowings, both deliberate: only checks aggregation
`params.field` values inside `attributes.visState` PLUS index-pattern
`fieldFormatMap` (the 2 fieldFormatMap-only instances the first draft
missed) — a `.keyword` reference embedded in a raw KQL/Lucene query
string, a `lens` saved object's `datasourceStates`, or a `map` layer would
fail differently and isn't covered (swept by hand during the
security-auditor review that found the fieldFormatMap gap; none exist
today).

Run:  python -m pytest tests/dashboards -q
"""

import json
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SERVER_DIR = ROOT / "configs" / "server"
LOGSTASH_TEMPLATE_PATH = ROOT / "configs" / "elasticsearch" / "logstash-security-template.json"
SOAR_TEMPLATE_PATH = ROOT / "configs" / "elasticsearch" / "soar-actions-template.json"

# title -> (template path, is_exhaustive). is_exhaustive=True means this
# template's dynamic_templates guarantee EVERY string field — explicit
# property or not — is bare keyword, so an unmapped field is still a
# confident violation, not a guess. See module docstring for why the two
# patterns differ on this. NOTE: the "logstash-*" Kibana data view is
# broader than logstash-security-template.json's own index_patterns
# ("logstash-security-*") — the exhaustiveness claim assumes every
# logstash-* index in this deployment is actually logstash-security-*
# (true today: configs/logstash.conf's only 2 ES outputs both write
# logstash-security[-quarantine]-%{[tenant][id]}). A future logstash-<
# other>-* index NOT governed by this template would make is_exhaustive
# wrongly claim coverage it doesn't have.
GOVERNED_INDEX_PATTERNS = {
    "logstash-*": (LOGSTASH_TEMPLATE_PATH, True),
    "soar-actions-*": (SOAR_TEMPLATE_PATH, False),
}

FIELD_RE = re.compile(r'"field"\s*:\s*"([^"]+)\.keyword"')
INDEX_REF_NAME = "kibanaSavedObjectMeta.searchSourceJSON.index"


def _format_map_keyword_fields(format_map_json):
    """fieldFormatMap's keys are field names, not schema — must be parsed
    as JSON, not pattern-matched. security-auditor follow-up: a prior
    regex-based version (FORMAT_MAP_RE, matching literal `"id":` right
    after the field key) depended on "id" being serialized as the FIRST
    key inside each format entry, which Kibana does not guarantee on
    re-export — a re-exported dashboard could reintroduce the exact bug
    this checks for with CI silently still green."""
    try:
        format_map = json.loads(format_map_json) if format_map_json else {}
    except json.JSONDecodeError:
        return []
    return [key[: -len(".keyword")] for key in format_map if key.endswith(".keyword")]


def find_violations(saved_objects, index_titles, field_types_by_pattern):
    """Pure matching logic, unit-testable against synthetic fixtures
    independent of the real files on disk — mirrors tag_truncation()'s
    role in test_field_truncation.py. saved_objects: iterable of
    (location_label, obj_dict). index_titles: {index-pattern id: title}.
    field_types_by_pattern: {title: (field_types_dict, is_exhaustive)}.
    Returns a list of human-readable violation strings."""
    violations = []

    def check(location, obj_id, title, field):
        governed = field_types_by_pattern.get(title)
        if governed is None:
            return  # not a governed pattern: don't guess
        field_types, is_exhaustive = governed
        mapping = field_types.get(field)
        if mapping is not None:
            if "keyword" in mapping.get("fields", {}):
                return  # genuinely has a multi-field: not a violation
            reason = f"is mapped {mapping.get('type')!r} with no keyword multi-field"
        elif is_exhaustive:
            reason = "is not an explicit property, but this index's dynamic_templates make every string field bare keyword"
        else:
            return  # not explicit, and this template isn't exhaustive: don't guess
        violations.append(f"{location} ({obj_id}) — \"{field}.keyword\" but {field} {reason}")

    for location, obj in saved_objects:
        index_id = None
        for ref in obj.get("references", []):
            if ref.get("name") == INDEX_REF_NAME:
                index_id = ref.get("id")
                break
        title = index_titles.get(index_id)

        if obj.get("type") == "visualization":
            vis_state = obj.get("attributes", {}).get("visState", "")
            for field in FIELD_RE.findall(vis_state):
                check(location, obj.get("id"), title, field)
        elif obj.get("type") == "index-pattern":
            # fieldFormatMap keys a field pivot/link config by field name
            # directly on the index-pattern object itself, not via a
            # references indirection — the object IS the index pattern.
            own_title = obj.get("attributes", {}).get("title")
            format_map = obj.get("attributes", {}).get("fieldFormatMap", "")
            for field in _format_map_keyword_fields(format_map):
                check(location, obj.get("id"), own_title, field)

    return violations


def _iter_saved_objects():
    for path in sorted(SERVER_DIR.glob("*.ndjson")):
        with path.open(encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                yield f"{path.relative_to(ROOT)}:{lineno}", json.loads(line)


def _build_index_pattern_titles(saved_objects):
    """id -> title. Dashboard files routinely reference an index-pattern
    object deployed from a DIFFERENT file (endpoint_dashboard.ndjson has
    none of its own; it relies on kibana_data_views_final.ndjson), so this
    has to be built from every file, not looked up per-file."""
    titles = {}
    for _location, obj in saved_objects:
        if obj.get("type") == "index-pattern":
            titles[obj["id"]] = obj.get("attributes", {}).get("title")
    return titles


def _template_field_types(template_path):
    """dotted-path -> mapping dict, for every EXPLICIT property in the
    given template."""
    template = json.loads(template_path.read_text(encoding="utf-8"))
    props = template["template"]["mappings"]["properties"]

    def walk(properties, prefix=()):
        for key, val in properties.items():
            if not isinstance(val, dict):
                continue
            path = prefix + (key,)
            if "properties" in val:
                yield from walk(val["properties"], path)
            elif "type" in val:
                yield ".".join(path), val

    return dict(walk(props))


def _real_field_types_by_pattern():
    return {
        title: (_template_field_types(path), is_exhaustive)
        for title, (path, is_exhaustive) in GOVERNED_INDEX_PATTERNS.items()
    }


class FindViolationsLogicTests(unittest.TestCase):
    """Synthetic-fixture unit tests for find_violations() itself — proves
    the matching/skip logic is correct independent of what the real files
    currently contain, same reasoning as test_field_truncation.py's
    tag_truncation() tests."""

    LOGSTASH_FIELDS = {"source.ip": {"type": "ip"}, "user.name": {"type": "keyword"}}
    SOAR_FIELDS = {"action.type": {"type": "keyword"}}
    PATTERNS = {
        "logstash-*": (LOGSTASH_FIELDS, True),
        "soar-actions-*": (SOAR_FIELDS, False),
    }
    TITLES = {"logstash-idx": "logstash-*", "soar-idx": "soar-actions-*"}

    def _panel(self, field, index_id="logstash-idx"):
        return ("t", {
            "type": "visualization",
            "id": "test-panel",
            "attributes": {"visState": json.dumps({"aggs": [{"params": {"field": field}}]})},
            "references": [{"name": INDEX_REF_NAME, "id": index_id}],
        })

    def test_bare_keyword_field_with_dot_keyword_flagged(self):
        violations = find_violations([self._panel("user.name.keyword")], self.TITLES, self.PATTERNS)
        self.assertEqual(len(violations), 1)
        self.assertIn("user.name.keyword", violations[0])

    def test_ip_type_field_with_dot_keyword_flagged(self):
        violations = find_violations([self._panel("source.ip.keyword")], self.TITLES, self.PATTERNS)
        self.assertEqual(len(violations), 1)

    def test_field_without_dot_keyword_not_flagged(self):
        violations = find_violations([self._panel("user.name")], self.TITLES, self.PATTERNS)
        self.assertEqual(violations, [])

    def test_genuine_keyword_multifield_not_flagged(self):
        # If a field genuinely HAD a keyword multi-field, .keyword would be
        # correct, not a bug — the checker must not flag it.
        patterns = {"logstash-*": ({"user.name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}}, True)}
        violations = find_violations([self._panel("user.name.keyword")], self.TITLES, patterns)
        self.assertEqual(violations, [])

    def test_unmapped_field_on_exhaustive_pattern_IS_flagged(self):
        # security-auditor follow-up: this is the exact gap that let
        # nist.function/threat.technique.id/threat.technique.name through
        # in the first draft. logstash-*'s strings_as_keyword dynamic
        # template has no path_match restriction, so ANY string field not
        # already an explicit property is still guaranteed bare keyword —
        # "not explicit" must NOT mean "skip" for this pattern.
        violations = find_violations(
            [self._panel("some.dynamic.field.keyword")], self.TITLES, self.PATTERNS)
        self.assertEqual(len(violations), 1)
        self.assertIn("dynamic_templates make every string field bare keyword", violations[0])

    def test_unmapped_field_on_non_exhaustive_pattern_not_flagged(self):
        # soar-actions-* has NO dynamic_templates section, so an unmapped
        # field there falls to Elasticsearch's own default dynamic mapping
        # (real text+keyword) — skip, don't guess, unlike the logstash-*
        # case above. This is the asymmetry the whole test hinges on.
        violations = find_violations(
            [self._panel("some.other.field.keyword", index_id="soar-idx")], self.TITLES, self.PATTERNS)
        self.assertEqual(violations, [])

    def test_soar_explicit_property_flagged(self):
        violations = find_violations(
            [self._panel("action.type.keyword", index_id="soar-idx")], self.TITLES, self.PATTERNS)
        self.assertEqual(len(violations), 1)

    def test_ungoverned_index_pattern_not_flagged(self):
        # The mock-vs-real split this repo has hit before (see module
        # docstring / docs/AI_conversation_transcript.md): a panel backed
        # by an index with NO checked-in template (e.g. "soc-controls",
        # which gets Elasticsearch's default dynamic text+keyword mapping)
        # must not be flagged just because the field name happens to
        # collide with one that's broken on a governed pattern.
        titles = {"logstash-idx": "logstash-*", "other-idx": "soc-controls"}
        violations = find_violations(
            [self._panel("user.name.keyword", index_id="other-idx")], titles, self.PATTERNS)
        self.assertEqual(violations, [])

    def test_unresolvable_index_reference_not_flagged(self):
        # No references array at all, or the ref name doesn't match — the
        # index pattern can't be determined, so don't guess.
        obj = ("t", {
            "type": "visualization", "id": "no-ref-panel",
            "attributes": {"visState": json.dumps({"aggs": [{"params": {"field": "user.name.keyword"}}]})},
            "references": [],
        })
        violations = find_violations([obj], self.TITLES, self.PATTERNS)
        self.assertEqual(violations, [])

    def test_non_visualization_non_index_pattern_saved_objects_ignored(self):
        obj = ("t", {"type": "dashboard", "id": "d1", "attributes": {}})
        violations = find_violations([obj], self.TITLES, self.PATTERNS)
        self.assertEqual(violations, [])

    def test_field_format_map_on_governed_pattern_flagged(self):
        # security-auditor follow-up: fieldFormatMap lives on the
        # index-pattern object itself (own title, no references
        # indirection needed), not on a visualization — the first draft's
        # `type != "visualization"` guard skipped it entirely.
        obj = ("t", {
            "type": "index-pattern", "id": "logstash-idx",
            "attributes": {
                "title": "logstash-*",
                "fieldFormatMap": json.dumps({"source.ip.keyword": {"id": "url"}}),
            },
        })
        violations = find_violations([obj], self.TITLES, self.PATTERNS)
        self.assertEqual(len(violations), 1)

    def test_field_format_map_key_order_does_not_matter(self):
        # A prior regex-based version of this check matched only when "id"
        # happened to be serialized as the FIRST key inside the format
        # entry — real, since Kibana doesn't guarantee key order on
        # re-export. Parsing as JSON (not pattern-matching) must catch
        # this regardless of key order.
        obj = ("t", {
            "type": "index-pattern", "id": "logstash-idx",
            "attributes": {
                "title": "logstash-*",
                "fieldFormatMap": '{"source.ip.keyword": {"params": {"x": 1}, "id": "url"}}',
            },
        })
        violations = find_violations([obj], self.TITLES, self.PATTERNS)
        self.assertEqual(len(violations), 1)

    def test_field_format_map_malformed_json_does_not_crash(self):
        obj = ("t", {
            "type": "index-pattern", "id": "logstash-idx",
            "attributes": {"title": "logstash-*", "fieldFormatMap": "{not valid json"},
        })
        violations = find_violations([obj], self.TITLES, self.PATTERNS)
        self.assertEqual(violations, [])


class RealDashboardFilesTests(unittest.TestCase):
    """Integration test against the actual deployed dashboard files."""

    def test_no_dot_keyword_field_against_a_bare_keyword_template_field(self):
        saved_objects = list(_iter_saved_objects())
        index_titles = _build_index_pattern_titles(saved_objects)
        field_types_by_pattern = _real_field_types_by_pattern()
        violations = find_violations(saved_objects, index_titles, field_types_by_pattern)

        self.assertEqual(
            [], violations,
            "dashboard panel(s)/index-pattern(s) reference a .keyword sub-field that "
            "does not exist on the real mapping — the panel (or field-format pivot) "
            "silently fails against real telemetry (#341):\n" + "\n".join(violations)
        )


if __name__ == "__main__":
    unittest.main()
