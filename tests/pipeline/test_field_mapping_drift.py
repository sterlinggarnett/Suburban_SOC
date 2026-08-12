#!/usr/bin/env python3
"""
Static field-mapping drift check between configs/logstash.conf's Zeek
ingest-time renames and configs/detections/suburban-soc-ecs.yml's pySigma
field_name_mapping transformations (#287).

THE BUG CLASS: a Sigma rule selects a raw Zeek field name that
suburban-soc-ecs.yml's field_name_mapping claims maps to some ECS target —
but configs/logstash.conf either never actually renames that raw field at
all, or renames it to a DIFFERENT target. The rule compiles fine, its
sigma_eval.py fixture test passes (that module evaluates raw Sigma field
names directly, never through this pipeline mapping — see its own module
docstring), and the compiled query is a permanent silent no-op against real
telemetry. tests/detections/test_live_fire.py (#221) does not catch this
structurally either: it reads suburban-soc-ecs.yml's OWN mapping table and
applies it to fixture data, then queries with a rule compiled through that
SAME table — it proves the rule and the pipeline mapping agree with EACH
OTHER, never that the pipeline mapping agrees with what configs/logstash.conf
(the file that actually produces the real field names) does.

This recurred 4 times across independent detection-expansion batches before
being tracked here:
  - #217: ImagePath case-sensitivity/mapping gap
  - #232 (M13 US2): Security-channel ECS mapping missing fields
    Kerberoasting/DCSync/etc. select on
  - #233/#234 (M13 US3): suburban-soc-ecs.yml CLAIMED an OriginalFileName
    rename logstash.conf never performed
  - #228 (M13 US5): zero pipeline transformations existed for
    zeek/dns/ssl/conn/http; even after adding them, review found the
    connection 4-tuple was mapped for conn but missing from dns/ssl/http,
    and field-mapping-zeek-http initially omitted `host` entirely

SCOPE: Zeek only (product: zeek field_name_mapping transformations cross-
referenced against configs/logstash.conf's Category 0 Zeek block, PLUS
configs/network/filebeat.yml's own input-processor rename — http.log's
`host` -> zeek.http.host happens there, before Logstash ever sees the
event, per that file's own comment on why it can't be done in
logstash.conf). The issue's own acceptance criterion: "even a check limited
to the Category 0 Zeek block... would have caught 3 of the 4 real bugs
found during #228's review round" — Winlogbeat channels (Sysmon, Security,
System, etc.) are a real gap of the same shape but are NOT covered here;
see #287 for that follow-on scope if this proves its value.

ALGORITHM: for every field_name_mapping transformation in
suburban-soc-ecs.yml scoped to `product: zeek, service: X`, and for every
raw_field -> target pair it declares, assert configs/logstash.conf (merged
with filebeat.yml) actually renames raw_field to that EXACT target for
dataset "zeek.X" — checking both the dataset-scoped conditional rename
block (`if [event][dataset] == "zeek.X" { ... rename => {...} ... }`) and
the unconditional block that applies to every zeek_logs event regardless of
dataset. A field_name_mapping entry existing at all is itself evidence a
real rename is expected (pySigma's default is to leave an unmapped field
name as-is, so nobody would list an identity mapping here on purpose) — so
"logstash.conf never renames this field for this dataset at all" is just as
much a drift bug as "renames it to something else".

Run:  python tests/pipeline/test_field_mapping_drift.py  (or: pytest tests/pipeline)
"""

import re
import unittest
from pathlib import Path
from typing import Optional

import yaml

ROOT = Path(__file__).resolve().parents[2]
LOGSTASH_CONF_PATH = ROOT / "configs" / "logstash.conf"
FILEBEAT_YML_PATH = ROOT / "configs" / "network" / "filebeat.yml"
PIPELINE_PATH = ROOT / "configs" / "detections" / "suburban-soc-ecs.yml"

CONF = LOGSTASH_CONF_PATH.read_text(encoding="utf-8")

# suburban-soc-ecs.yml's own documented INVARIANT (its field-mapping-zeek-dns
# comment): Category 0's connection 4-tuple + proto/service is renamed
# UNCONDITIONALLY for every zeek_logs event, so "any field renamed
# unconditionally there must appear in every zeek/* transformation that
# exists below, ... or a rule that scopes a dns/ssl/http detection to a
# source/destination... is a silent no-op." Encoded here as data so it can
# be enforced as a CI gate (test_every_zeek_transformation_maps_the_core_
# connection_fields) instead of staying a comment nobody re-checks by hand.
CORE_ZEEK_FIELDS = {
    "id.orig_h": "source.ip",
    "id.resp_h": "destination.ip",
    "id.orig_p": "source.port",
    "id.resp_p": "destination.port",
    "proto": "network.transport",
    "service": "network.protocol",
}


def _matching_brace(text: str, open_pos: int) -> int:
    """Index of the "}" matching the "{" at open_pos, via depth counting —
    robust against the fixed-width slicing a naive non-greedy regex would
    need, since Category 0 nests several levels of if/mutate blocks."""
    assert text[open_pos] == "{", f"expected '{{' at offset {open_pos}, found {text[open_pos]!r}"
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError(f"no matching '}}' found for '{{' at offset {open_pos}")


def _normalize_target(bracket_path: str) -> str:
    """Logstash bracket notation to dotted ECS path: "[source][ip]" -> "source.ip"."""
    return ".".join(re.findall(r"\[([^\]]+)\]", bracket_path))


def _normalize_raw(bracket_key: str) -> str:
    """A rename SOURCE is always a single bracket pair, whether it wraps a
    simple word ("[query]" -> "query") or a Zeek flat dotted-literal key
    ("[id.orig_h]" -> "id.orig_h", the ndjson-native shape, NOT nested
    bracket notation) — this matches suburban-soc-ecs.yml's raw Sigma field
    name convention exactly either way, unlike a target path, which
    genuinely nests and needs segment-by-segment decomposition. Asserts
    that assumption rather than silently mis-slicing a genuinely nested
    source into a corrupted key if one is ever introduced (code-reviewer
    follow-up) — fails loudly pointing at the real cause instead of
    surfacing as a confusing spurious drift mismatch downstream."""
    key = bracket_key.strip()
    assert key.count("[") == 1 and key.count("]") == 1, (
        f"rename source {bracket_key!r} is not a single bracket pair — "
        f"_normalize_raw's one-bracket-pair assumption no longer holds")
    return key[1:-1]


def _parse_rename_pairs(rename_block_text: str) -> dict:
    return {
        _normalize_raw(k): _normalize_target(v)
        for k, v in re.findall(r'"(\[[^"]+\])"\s*=>\s*"(\[[^"]+\])"', rename_block_text)
    }


def extract_pipeline_renames(conf_text: Optional[str] = None, filebeat_text: Optional[str] = None) -> dict:
    """{dataset_scope: {raw_field: target_field}}. "*" applies to every
    zeek_logs event: the unconditional Category 0 rename block, plus the
    presence-gated `if [source] {...}` rename (scoped by field presence,
    not dataset, but never collides with a dataset-specific mapping in
    practice since `source` as a bare string only appears on files.log/
    http.log). "zeek.X" applies only when [event][dataset] == "zeek.X".

    Classifies EVERY `rename => {...}` block in Category 0 by POSITION —
    whichever `if [event][dataset] == "zeek.X" {...}` span (if any) contains
    it — rather than assuming "the first one is unconditional", since the
    presence-gated `if [source] {...}` rename actually appears earlier in
    the file than the real unconditional block.

    conf_text/filebeat_text default to the real repo files but are
    injectable (security-auditor follow-up) so this parser's own
    correctness can be regression-tested against synthetic config text —
    see ExtractPipelineRenamesSelfTests below, which is what actually would
    have caught the compound-condition misclassification bug this file
    already fixed once, rather than relying on the real file happening to
    still parse correctly."""
    if conf_text is None:
        conf_text = CONF
    if filebeat_text is None:
        filebeat_text = FILEBEAT_YML_PATH.read_text(encoding="utf-8")

    start = conf_text.index('if [log][file][path] =~ "zeek_logs"')
    cat0_open = conf_text.index("{", start)
    cat0_close = _matching_brace(conf_text, cat0_open)
    cat0 = conf_text[cat0_open:cat0_close + 1]

    # code-reviewer follow-up: [^{]*\{ (not a literal-adjacent \{) so a
    # compound condition — e.g. `if [event][dataset] == "zeek.notice" and
    # ![source][ip] and [src] {` (configs/logstash.conf's #267 fallback
    # rename) — still resolves to the right dataset scope instead of
    # silently falling through to "no enclosing span found" and getting
    # merged into "*" as if unconditional. That was the exact drift-checker-
    # has-its-own-drift-bug shape this file exists to prevent elsewhere.
    dataset_spans = []
    for dm in re.finditer(r'if \[event\]\[dataset\] == "(zeek\.\w+)"[^{]*\{', cat0):
        scope_open = cat0.index("{", dm.end() - 1)
        scope_close = _matching_brace(cat0, scope_open)
        dataset_spans.append((dm.group(1), scope_open, scope_close))

    renames: dict = {"*": {}}
    for m in re.finditer(r"rename\s*=>\s*\{", cat0):
        block_open = cat0.index("{", m.end() - 1)
        block_close = _matching_brace(cat0, block_open)
        pairs = _parse_rename_pairs(cat0[block_open + 1:block_close])
        # Innermost enclosing dataset span, if any (smallest span containing
        # this rename block's position) — nesting isn't expected in this
        # file today, but pick the tightest match rather than assume flat.
        enclosing = [s for s in dataset_spans if s[1] < block_open and block_close < s[2]]
        if enclosing:
            dataset = min(enclosing, key=lambda s: s[2] - s[1])[0]
            renames.setdefault(dataset, {}).update(pairs)
        else:
            renames["*"].update(pairs)

    fb = yaml.safe_load(filebeat_text)
    for inp in fb.get("filebeat.inputs", []):
        for proc in inp.get("processors", []):
            rename_spec = proc.get("rename")
            if not rename_spec:
                continue
            log_path_pattern = (rename_spec.get("when", {}).get("regexp", {}).get("log.file.path", ""))
            stream_match = re.search(r"([a-z0-9_]+)\\?\.log", log_path_pattern)
            # code-reviewer follow-up: fail loud rather than silently
            # default to unconditional ("*") scope if a future filebeat
            # rename's `when` condition doesn't match the expected
            # single-stream regexp shape — the same "unrecognized scope
            # defaults to global" risk class the dataset-span regex fix
            # above closed for logstash.conf's own conditions.
            assert stream_match, (
                f"filebeat.yml rename processor's when.regexp.log.file.path "
                f"{log_path_pattern!r} doesn't match the expected single-stream "
                f"pattern — can't safely infer which zeek dataset it scopes to")
            dataset = f"zeek.{stream_match.group(1)}"
            for field in rename_spec.get("fields", []):
                renames.setdefault(dataset, {})[field["from"]] = field["to"]

    # security-auditor follow-up: _matching_brace counts every literal '{'/
    # '}' byte, including inside comments (Category 0 currently balances
    # only because every brace in a comment happens to pair up, e.g. the
    # "output{}" reference at configs/logstash.conf:411). A future comment
    # with a lone brace would silently reshape cat0_close. This tripwire
    # doesn't fix that root cause but converts a silent reshape into a loud
    # failure: the real Category 0 span is immediately followed by a
    # "Category 1" comment, so if the span landed short/long that landmark
    # won't be where expected right after it.
    if conf_text is CONF:
        assert "Category 1" in conf_text[cat0_close:cat0_close + 500], (
            "Category 0 span extraction landed somewhere unexpected — "
            "configs/logstash.conf structure may have drifted, or an "
            "unbalanced brace inside a comment/string reshaped the span")

    return renames


def extract_sigma_zeek_mappings() -> dict:
    """{dataset: {raw_field: target_field}} for every product:zeek
    field_name_mapping transformation in suburban-soc-ecs.yml.

    security-auditor follow-up: guards the same 2 assumptions
    tests/detections/test_live_fire.py's own load_pipeline_field_mapping()
    already asserts for the identical file — at most one logsource
    rule_condition per transformation (this repo's pipeline never uses
    pySigma's real AND-by-default multi-condition form), and at most one
    transformation per zeek/service (a second one would otherwise silently
    overwrite the first via plain dict assignment, and its fields would
    never be checked at all)."""
    pipeline = yaml.safe_load(PIPELINE_PATH.read_text(encoding="utf-8"))
    out = {}
    for t in pipeline.get("transformations", []):
        if t.get("type") != "field_name_mapping":
            continue
        zeek_conditions = [c for c in t.get("rule_conditions", [])
                            if c.get("type") == "logsource" and c.get("product") == "zeek"]
        assert len(zeek_conditions) <= 1, (
            f"transformation {t.get('id')!r} has multiple product:zeek logsource "
            f"rule_conditions — this parser's single-condition assumption no longer holds")
        for cond in zeek_conditions:
            service = cond.get("service")
            if not service:
                continue
            dataset = f"zeek.{service}"
            assert dataset not in out, (
                f"multiple field_name_mapping transformations scoped to {dataset!r} — "
                f"the second ({t.get('id')!r}) would silently overwrite the first, "
                f"and its fields would never be cross-checked")
            out[dataset] = dict(t.get("mapping", {}))
    return out


def find_mismatches(pipeline_renames: dict, sigma_mappings: dict) -> list:
    """The actual cross-file check, factored out of the test method so its
    own correctness can be regression-tested against synthetic input (see
    FindMismatchesSelfTests below), not just proven ad hoc during
    development. For every raw_field -> target pair a zeek/* field_name_
    mapping declares, the pipeline (Category 0's unconditional block, its
    own dataset-scoped block, or filebeat.yml) must rename raw_field to
    that EXACT target — a missing rename and a disagreeing rename are both
    flagged, since a field_name_mapping entry existing at all is itself
    evidence a real rename is expected (an identity mapping would be
    pointless)."""
    # security-auditor follow-up: dataset-scoped entries must NOT override
    # unconditional ones on a key collision — Logstash runs Category 0's
    # unconditional rename block FIRST (it appears earlier in the file), so
    # if it already consumed a source field, a later dataset-scoped rename
    # targeting that same source field finds nothing left to rename (mutate
    # rename REMOVES the source key) and is a real-world no-op. The
    # unconditional target is what actually happens at runtime, so it must
    # win here too. No dataset scope collides with "*" today (see
    # test_dataset_scopes_never_collide_with_unconditional below, which
    # makes that assumption an enforced invariant, not a silent one).
    mismatches = []
    for dataset, mapping in sorted(sigma_mappings.items()):
        applicable = {**pipeline_renames.get(dataset, {}),
                      **pipeline_renames.get("*", {})}
        for raw_field, expected_target in sorted(mapping.items()):
            actual_target = applicable.get(raw_field)
            if actual_target != expected_target:
                got = f"renames it to {actual_target!r}" if actual_target else "never renames it"
                mismatches.append(
                    f"{dataset}: suburban-soc-ecs.yml maps {raw_field!r} -> "
                    f"{expected_target!r}, but configs/logstash.conf/filebeat.yml {got}")
    return mismatches


class FieldMappingDriftTests(unittest.TestCase):
    def setUp(self):
        self.pipeline_renames = extract_pipeline_renames()
        self.sigma_mappings = extract_sigma_zeek_mappings()

    def test_pipeline_renames_extracted(self):
        # security-auditor follow-up: a size FLOOR alone can't catch the
        # realistic failure modes here — every one of them (dataset-span
        # regex stops matching, brace over-extension, filebeat scope
        # degrading to "*") makes renames["*"] GROW, not shrink, so a floor
        # passes right through them. Pin the exact scope set and specific
        # known entries instead, including negative assertions that a
        # dataset-scoped field is NOT ALSO present unconditionally — that's
        # what actually catches a scoping regression like the one this file
        # already found and fixed once (the zeek.notice compound-condition
        # bug: "src" briefly leaked into "*").
        self.assertEqual({"*", "zeek.software", "zeek.ssl", "zeek.intel", "zeek.notice", "zeek.http"},
                         set(self.pipeline_renames),
                         "pipeline rename scope set changed — either a real Category 0 edit "
                         "(update this set) or the parser mis-extracted a scope")
        self.assertGreaterEqual(len(self.pipeline_renames["*"]), 10,
                                "unconditional Category 0 rename table looks too small — "
                                "parser likely mis-extracted it")
        self.assertEqual("tls.client.server_name", self.pipeline_renames["zeek.ssl"]["server_name"])
        self.assertNotIn("server_name", self.pipeline_renames["*"],
                         "server_name leaked into the unconditional scope — should be zeek.ssl-only")
        self.assertEqual("zeek.http.host", self.pipeline_renames["zeek.http"]["host"])
        self.assertNotIn("host", self.pipeline_renames["*"],
                         "host leaked into the unconditional scope — should be zeek.http-only "
                         "(and is the exact real regression configs/network/filebeat.yml's own "
                         "comment describes fixing once already)")
        self.assertEqual("source.ip", self.pipeline_renames["zeek.notice"]["src"])
        self.assertNotIn("src", self.pipeline_renames["*"],
                         "src leaked into the unconditional scope — the compound-condition "
                         "misclassification bug this file already fixed once has recurred")

    def test_dataset_scopes_never_collide_with_unconditional(self):
        # Encodes find_mismatches's merge-precedence assumption (dataset-
        # scoped entries must not collide with "*") as an enforced
        # invariant rather than a silent one — see the comment in
        # find_mismatches for why the runtime semantics require this.
        for dataset, mapping in self.pipeline_renames.items():
            if dataset == "*":
                continue
            overlap = set(mapping) & set(self.pipeline_renames["*"])
            self.assertEqual(set(), overlap,
                             f"{dataset} renames the same raw field(s) as the unconditional "
                             f"block: {overlap} — find_mismatches's merge precedence assumption "
                             f"no longer holds, needs a real collision-resolution rule, not a "
                             f"silent dict-merge")

    def test_every_zeek_transformation_maps_the_core_connection_fields(self):
        # Encodes suburban-soc-ecs.yml's own documented INVARIANT (see
        # CORE_ZEEK_FIELDS above) as a CI gate.
        missing = []
        for dataset, mapping in sorted(self.sigma_mappings.items()):
            for raw_field, expected_target in CORE_ZEEK_FIELDS.items():
                if mapping.get(raw_field) != expected_target:
                    missing.append(f"{dataset}: missing or wrong core field {raw_field!r} "
                                   f"(expected -> {expected_target!r}, got {mapping.get(raw_field)!r})")
        self.assertEqual([], missing,
                         "suburban-soc-ecs.yml's own documented invariant violated — every "
                         "zeek/* field_name_mapping transformation must carry the core "
                         "connection 4-tuple + proto/service, or a rule that scopes a "
                         "detection to a source/destination is a silent no-op:\n" +
                         "\n".join(missing))

    def test_sigma_zeek_mappings_extracted(self):
        # security-auditor follow-up: this was a size floor (>=5) — the
        # exact same weakness test_pipeline_renames_extracted had before
        # this file's own review round. A floor lets a WHOLE transformation
        # silently vanish (6 exist today; 5 still passes) and every other
        # test here iterates self.sigma_mappings, so a missing transformation
        # can't be found missing anything — #228's own shape ("zero pipeline
        # transformations existed for zeek/dns/ssl/conn/http") on the
        # opposite side of the file.
        self.assertEqual({"zeek.files", "zeek.dns", "zeek.ssl", "zeek.conn", "zeek.smtp", "zeek.http"},
                         set(self.sigma_mappings),
                         "sigma field_name_mapping transformation set changed — either a real "
                         "suburban-soc-ecs.yml edit (update this set) or the parser mis-extracted one")

    def test_every_zeek_rule_logsource_service_has_a_mapping(self):
        # security-auditor follow-up: closes the forward-looking half of the
        # gap above. Globs the REAL rule corpus for every product:zeek
        # logsource service actually in use, and asserts each one has a
        # field_name_mapping transformation — not just that the 6
        # transformations that currently exist stay named the same 6
        # (test_sigma_zeek_mappings_extracted, above, would not notice a
        # 19th rule landing on a 7th, never-mapped zeek service).
        # zeek.notice is the one documented exception: suburban-soc-ecs.yml
        # itself says why (its field-mapping-zeek-dns comment) — the 2
        # existing notice rules only select on `note`, which Category 0
        # leaves untouched, so no mapping is needed YET. That comment also
        # says this stops being true "the moment a notice-scoped rule adds
        # a source/destination condition" — if that ever happens, remove
        # "notice" from this allowlist rather than let the new rule pass
        # silently.
        allowlisted_unmapped_services = {"notice"}
        services_in_use = set()
        for rule_path in sorted((ROOT / "rules" / "sigma").glob("*.yml")):
            rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
            logsource = rule.get("logsource", {})
            if logsource.get("product") == "zeek" and logsource.get("service"):
                services_in_use.add(logsource["service"])
        mapped_services = {ds.split(".", 1)[1] for ds in self.sigma_mappings}
        unmapped = services_in_use - mapped_services - allowlisted_unmapped_services
        self.assertEqual(set(), unmapped,
                         f"zeek Sigma rule(s) use service(s) {unmapped} with no "
                         f"field_name_mapping transformation in suburban-soc-ecs.yml — any "
                         f"field they select on beyond the raw untouched ones (note/"
                         f"auth_success/mime_type/trans_depth) compiles against a name real "
                         f"data never has")

    def test_sigma_zeek_field_mappings_match_pipeline_renames(self):
        # #287: the real files, cross-referenced against each other.
        mismatches = find_mismatches(self.pipeline_renames, self.sigma_mappings)
        self.assertEqual([], mismatches,
                         "field-mapping drift between logstash.conf (+ filebeat.yml) and "
                         "suburban-soc-ecs.yml — a Sigma rule selecting one of these fields "
                         "compiles fine and passes its fixture test but is a silent no-op "
                         "against real telemetry:\n" + "\n".join(mismatches))


class FindMismatchesSelfTests(unittest.TestCase):
    """code-reviewer follow-up: the tests above only prove the two real
    files currently agree — they say nothing about whether find_mismatches
    itself would notice if they stopped agreeing (a silently-broken
    comparison, e.g. a flipped != to ==, would leave every test in this
    module green regardless, since real content has zero drift either way).
    Commits the mutation testing already run ad hoc during development as
    permanent regression coverage, matching the house precedent of
    test_field_truncation.py's test_flat_dotted_key_no_longer_matched."""

    def test_catches_a_sigma_mapping_with_no_pipeline_counterpart(self):
        # The #233/#234 shape: suburban-soc-ecs.yml claims a rename
        # logstash.conf never performs at all.
        pipeline = {"*": {"query": "dns.question.name"}}
        sigma = {"zeek.dns": {"totally_fake_field": "some.fake.target"}}
        mismatches = find_mismatches(pipeline, sigma)
        self.assertEqual(1, len(mismatches))
        self.assertIn("totally_fake_field", mismatches[0])
        self.assertIn("never renames it", mismatches[0])

    def test_catches_a_disagreeing_target(self):
        # A subtler shape: the pipeline DOES rename the field, but to a
        # different ECS target than suburban-soc-ecs.yml's mapping claims.
        pipeline = {"*": {"rcode_name": "dns.response_code"}}
        sigma = {"zeek.dns": {"rcode_name": "dns.response.code"}}  # wrong: dotted, not underscore
        mismatches = find_mismatches(pipeline, sigma)
        self.assertEqual(1, len(mismatches))
        self.assertIn("dns.response_code", mismatches[0])

    def test_dataset_scoped_rename_satisfies_dataset_scoped_mapping(self):
        # The non-bug case for a dataset-scoped (not unconditional) pipeline
        # rename — confirms the "*" + dataset merge itself works, not just
        # the unconditional path every other test here exercises.
        pipeline = {"*": {}, "zeek.ssl": {"server_name": "tls.client.server_name"}}
        sigma = {"zeek.ssl": {"server_name": "tls.client.server_name"}}
        self.assertEqual([], find_mismatches(pipeline, sigma))

    def test_agreeing_mappings_produce_no_mismatches(self):
        pipeline = {"*": {"query": "dns.question.name"}}
        sigma = {"zeek.dns": {"query": "dns.question.name"}}
        self.assertEqual([], find_mismatches(pipeline, sigma))


_SYNTHETIC_CONF = '''
filter {
  if [log][file][path] =~ "zeek_logs" {
    mutate {
      rename => {
        "[unconditional_field]" => "[some][target]"
      }
    }
    if [event][dataset] == "zeek.ssl" {
      mutate {
        rename => {
          "[simple_scoped]" => "[tls][simple]"
        }
      }
    }
    if [event][dataset] == "zeek.notice" and ![source][ip] and [src] {
      mutate {
        rename => {
          "[compound_scoped]" => "[source][ip]"
        }
      }
    }
  }
}
'''

_SYNTHETIC_FILEBEAT = '''
filebeat.inputs:
  - type: filestream
    processors:
      - rename:
          when:
            regexp:
              log.file.path: 'http\\.log$'
          fields:
            - {from: "synthetic_host", to: "zeek.http.synthetic_host"}
'''


class ExtractPipelineRenamesSelfTests(unittest.TestCase):
    """security-auditor follow-up: FindMismatchesSelfTests above only
    regression-tests the COMPARISON logic (find_mismatches) against
    synthetic dicts — it says nothing about whether the PARSER
    (extract_pipeline_renames) itself would notice a regression, since it
    always ran against the real file, which happens to still parse
    correctly. This is what actually would have caught the compound-
    condition misclassification bug (the zeek.notice "src" leak) as a
    committed regression test, rather than relying on a live session
    catching it by hand."""

    def test_compound_dataset_condition_is_correctly_scoped(self):
        # The exact real bug shape, reproduced in miniature: a dataset
        # condition ANDed with extra predicates must still resolve to its
        # own dataset scope, not fall through to unconditional.
        renames = extract_pipeline_renames(conf_text=_SYNTHETIC_CONF, filebeat_text=_SYNTHETIC_FILEBEAT)
        self.assertNotIn("compound_scoped", renames["*"])
        self.assertEqual("source.ip", renames["zeek.notice"]["compound_scoped"])

    def test_simple_dataset_condition_is_correctly_scoped(self):
        renames = extract_pipeline_renames(conf_text=_SYNTHETIC_CONF, filebeat_text=_SYNTHETIC_FILEBEAT)
        self.assertNotIn("simple_scoped", renames["*"])
        self.assertEqual("tls.simple", renames["zeek.ssl"]["simple_scoped"])

    def test_unconditional_field_stays_unconditional(self):
        renames = extract_pipeline_renames(conf_text=_SYNTHETIC_CONF, filebeat_text=_SYNTHETIC_FILEBEAT)
        self.assertEqual("some.target", renames["*"]["unconditional_field"])

    def test_filebeat_rename_scoped_to_its_stream(self):
        renames = extract_pipeline_renames(conf_text=_SYNTHETIC_CONF, filebeat_text=_SYNTHETIC_FILEBEAT)
        self.assertEqual("zeek.http.synthetic_host", renames["zeek.http"]["synthetic_host"])
        self.assertNotIn("synthetic_host", renames["*"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
