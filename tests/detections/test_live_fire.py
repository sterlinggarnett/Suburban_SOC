#!/usr/bin/env python3
"""
test_live_fire.py — issue #221: fire real compiled Sigma detections against a
real Elasticsearch, end to end.

sigma_eval.py (test_sigma_detections.py) validates rule *logic* with a Python
re-implementation of Sigma matching — fast, but proven this session (#217's
MEDIUM-3/MEDIUM-4 findings) to miss an entire class of bug: a rule whose field
names do not survive the real suburban-soc-ecs.yml pipeline conversion, or do
not exist in real ECS-shaped data, passes sigma_eval.py's fixture tests while
being a complete no-op in production. This module closes that gap by:

  1. Running the REAL `sigma convert` (same command detections.yml already
     runs) to get the actual compiled Lucene query for a rule.
  2. Translating each fixture event from raw Sigma field names into the same
     ECS-shaped document real telemetry has, using the SAME mapping table
     (configs/detections/suburban-soc-ecs.yml) the pipeline itself uses — not
     a second, hand-maintained translation that could drift from it.
  3. Indexing those documents into a throwaway index carrying the REAL
     production index template's mappings (so string-vs-keyword,
     lowercase_normalizer, and ignore_above behave exactly as they do against
     real telemetry — a dynamic-default mapping would silently pass a test
     that fails in production, or vice versa).
  4. Running the compiled query against that index via Elasticsearch itself,
     not a Python re-implementation.

One rule per category named in the issue's acceptance criteria:
  - process_creation: proc_creation_win_powershell_encoded.yml
  - network:          net_zeek_executable_download.yml — chosen over the other
                       two net_zeek_*.yml rules specifically because its
                       logsource (product: zeek, service: files) IS covered
                       by a real pipeline transformation (source -> zeek.source
                       in suburban-soc-ecs.yml) - this is the exact rule #217's
                       MEDIUM-4 finding was about (the rule queried the
                       pre-rename field name and could never fire), so this
                       is a direct regression test for a documented
                       production incident, not a synthetic example.
  - threshold:         rules/elastic/threshold/auth-win-bruteforce-failed-logons.ndjson

Two known scope limits, security-auditor/code-reviewer verified (both reviews
run in parallel per this repo's standing rules) but not fully closed here:
  - Query execution uses a bare query_string with no time-range filter and no
    attempt to reproduce every option Kibana's Detection Engine adds when it
    runs a language:lucene rule (e.g. analyze_wildcard) - confirming exact
    parity needs a live capture from a real Kibana rule execution, not
    something inspectable from this repo alone. The threshold tests DO now
    apply the rule's own from/to window (see _bucket_count), which is the
    property that actually matters for that rule's documented purpose.
  - load_pipeline_field_mapping() intentionally reimplements a SIMPLIFIED
    subset of pySigma's real field-mapping precedence (OR across conditions
    and last-transformation-wins on overlap, vs pySigma's real AND-by-default
    and first-transformation-wins) - dormant today because every condition in
    suburban-soc-ecs.yml is a single, mutually-exclusive product/category/
    service triple, but guarded below so a future pipeline change that would
    make the simplification wrong fails loudly instead of silently drifting.

Requires a real, reachable Elasticsearch — SKIPPED (not failed) if one is not
configured, so `pytest tests/` stays runnable with no live cluster. CI
provides an ephemeral, unauthenticated single-node ES service container
(.github/workflows/detections.yml) for exactly this purpose; point
LIVE_FIRE_ES_URL at a real dev-stack cluster to run it locally instead
(defaults assume no auth/TLS, matching the CI container — the dev stack
needs LIVE_FIRE_ES_USER/LIVE_FIRE_ES_PASS/LIVE_FIRE_ES_CA set to authenticate).

Run:  pytest tests/detections/test_live_fire.py
      LIVE_FIRE_ES_URL=https://localhost:9200 LIVE_FIRE_ES_USER=elastic \
        LIVE_FIRE_ES_PASS=... LIVE_FIRE_ES_CA=/path/to/ca.crt \
        pytest tests/detections/test_live_fire.py
"""
import json
import os
import shutil
import subprocess
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SIGMA_DIR = ROOT / "rules" / "sigma"
THRESHOLD_DIR = ROOT / "rules" / "elastic" / "threshold"
PIPELINE_PATH = ROOT / "configs" / "detections" / "suburban-soc-ecs.yml"
INDEX_TEMPLATE_PATH = ROOT / "configs" / "elasticsearch" / "logstash-security-template.json"
FIXTURES = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))

ES_URL = os.environ.get("LIVE_FIRE_ES_URL", "http://localhost:9200")
ES_USER = os.environ.get("LIVE_FIRE_ES_USER", "")
ES_PASS = os.environ.get("LIVE_FIRE_ES_PASS", "")
ES_CA = os.environ.get("LIVE_FIRE_ES_CA", "")
ES_AUTH = (ES_USER, ES_PASS) if ES_USER else None
ES_VERIFY = ES_CA if ES_CA else True


def _es_reachable() -> bool:
    """True only if ES is both up AND usable with the configured credentials.
    A bare `status_code < 500` treats 401/403 as "reachable", which would
    make an auth-protected-but-not-TLS-terminated ES fail setUp's index
    creation with an unhandled HTTPError instead of skipping — the opposite
    of what this function exists to guarantee (security-auditor review)."""
    try:
        r = requests.get(ES_URL, auth=ES_AUTH, verify=ES_VERIFY, timeout=3)
        return r.status_code < 400
    except requests.RequestException:
        return False


def _sigma_binary() -> str:
    """Same resolution order deploy_detections.sh uses: PATH first (always
    wins in CI, since the workflow pip-installs sigma-cli before this runs),
    then the .venv-detections toolchain this repo's own detection tooling
    lives in for local runs. Validated the same way deploy_detections.sh
    validates its own PATH resolution (`"$SIGMA" version | grep -qi sigma`)
    rather than trusting whatever a bare `shutil.which` found — an empty or
    hijacked PATH entry named `sigma` would otherwise execute silently
    (security-auditor review)."""
    def _looks_like_sigma(path: str) -> bool:
        # `sigma version` prints a bare version number with no product name
        # in it at all (empirically checked — deploy_detections.sh:59 greps
        # its own `version` output for "sigma", which would fail identically
        # against the real binary; a pre-existing latent bug there, not
        # something to fix from this file). `--help` reliably mentions
        # "Sigma" multiple times in its own command descriptions.
        try:
            out = subprocess.run([path, "--help"], capture_output=True, text=True, timeout=5)
            return "sigma" in out.stdout.lower()
        except (OSError, subprocess.SubprocessError):
            return False

    on_path = shutil.which("sigma")
    if on_path and _looks_like_sigma(on_path):
        return on_path
    # CI always installs sigma-cli onto PATH (detections.yml) — this
    # checkout-relative fallback is local-developer convenience only, and is
    # deliberately never trusted in CI even if PATH resolution somehow failed
    # (security-auditor review: a force-added executable under the gitignored
    # .venv-detections/ path should never run in an untrusted PR checkout).
    if not os.environ.get("CI"):
        venv_sigma = ROOT / ".venv-detections" / "bin" / "sigma"
        if venv_sigma.exists() and _looks_like_sigma(str(venv_sigma)):
            return str(venv_sigma)
    raise RuntimeError("sigma CLI not found (or did not identify itself as sigma) on PATH"
                        + ("" if os.environ.get("CI") else " or in .venv-detections/bin")
                        + " — install with: pip install sigma-cli pysigma-backend-elasticsearch")


def sigma_convert_one(rule_path: Path) -> dict:
    """Run the real `sigma convert` (matches .github/workflows/detections.yml's
    invocation) and return the single converted rule object — the exact
    compiled query this stack would deploy, not a re-implementation of it."""
    proc = subprocess.run(
        [_sigma_binary(), "convert", "-t", "lucene", "-f", "siem_rule_ndjson",
         "-p", str(PIPELINE_PATH), str(rule_path)],
        capture_output=True, text=True, cwd=ROOT,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"sigma convert failed for {rule_path.name} "
                            f"(exit {proc.returncode}): {proc.stderr.strip()}")
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip().startswith("{")]
    if len(lines) != 1:
        raise RuntimeError(f"expected exactly one converted rule for {rule_path.name}, "
                            f"got {len(lines)}. stdout: {proc.stdout!r}")
    return json.loads(lines[0])


def load_pipeline_field_mapping(rule_logsource: dict) -> dict:
    """Merge every field_name_mapping transformation in suburban-soc-ecs.yml
    whose rule_conditions match this rule's logsource — the SAME table
    deploy_detections.sh's real `sigma convert -p ...` invocation applies to
    the query, applied here to fixture DATA instead so the two never drift
    apart. Mirrors pysigma's own LogsourceCondition equality check for the
    simple product/category/service conditions this repo's pipeline uses.

    Deliberately simplified vs. real pySigma semantics in two ways
    (code-reviewer finding): multiple rule_conditions entries on one
    transformation are OR'd here, not pySigma's real AND-by-default; and if
    two transformations both matched, the LAST one's mapping wins here, not
    pySigma's real first-applied-consumes-the-field precedence. Both are
    currently dormant — every transformation in the pipeline today has
    exactly one rule_conditions entry, and the 7 conditions are mutually
    exclusive product/category/service triples, so at most one transformation
    can ever match a given rule. Asserted below so a future pipeline change
    that breaks either assumption fails this test loudly instead of silently
    producing a translation that has drifted from what `sigma convert`
    actually does."""
    pipeline = yaml.safe_load(PIPELINE_PATH.read_text(encoding="utf-8"))
    matched_ids = []
    merged = {}
    for t in pipeline.get("transformations", []):
        if t.get("type") != "field_name_mapping":
            continue
        conditions = [c for c in t.get("rule_conditions", []) if c.get("type") == "logsource"]
        assert len(conditions) <= 1, (
            f"transformation {t.get('id')!r} has multiple rule_conditions entries — "
            f"load_pipeline_field_mapping()'s OR simplification no longer matches "
            f"pySigma's real AND-by-default semantics; needs a real fix, not a bigger assumption")
        for cond in conditions:
            check = {k: v for k, v in cond.items() if k in ("category", "product", "service")}
            if check and all(rule_logsource.get(k) == v for k, v in check.items()):
                matched_ids.append(t.get("id"))
                merged.update(t["mapping"])
    assert len(matched_ids) <= 1, (
        f"logsource {rule_logsource} matched multiple pipeline transformations "
        f"{matched_ids} — load_pipeline_field_mapping()'s last-wins merge no longer matches "
        f"pySigma's real first-transformation-consumes-the-field precedence")
    return merged


def translate_fixture(fixture: dict, field_mapping: dict) -> dict:
    """Rename fixture keys per field_mapping, building a nested ES document
    from dotted target paths (e.g. "winlog.event_data.ImagePath" ->
    {"winlog": {"event_data": {"ImagePath": ...}}}) — the real shape
    Winlogbeat/the pipeline produces, not the flat raw-Sigma-field shape
    sigma_eval.py's fixtures are written in. Stamps @timestamp (real telemetry
    always carries one; a document with none is not realistic input)."""
    doc: dict = {"@timestamp": datetime.now(timezone.utc).isoformat()}
    for key, value in fixture.items():
        target = field_mapping.get(key, key)
        parts = target.split(".")
        cur = doc
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = value
    return doc


class LiveFireTestCase(unittest.TestCase):
    """Shared ES plumbing: a fresh, realistically-mapped index per test,
    torn down after — tests never share state or leak indices on failure."""

    @classmethod
    def setUpClass(cls):
        if not _es_reachable():
            raise unittest.SkipTest(
                f"No reachable Elasticsearch at {ES_URL} (set LIVE_FIRE_ES_URL) — "
                f"live-fire tests skipped, not failed (#221: this suite validates "
                f"against a REAL cluster and is not meant to require one for every "
                f"`pytest tests/` run)")
        template = json.loads(INDEX_TEMPLATE_PATH.read_text(encoding="utf-8"))["template"]
        # The real template targets a DATA STREAM (index_patterns +
        # data_stream: {} in the parent file, logstash.conf writes with
        # action=>"create"), which mandates @timestamp on every doc and
        # rejects a bare `PUT _doc/<id>` upsert entirely — neither of which
        # this plain throwaway index models or needs to (it exists to test
        # field mapping/analyzer behavior, not data-stream write semantics).
        # index.lifecycle.name references a policy (logstash-security-ilm)
        # that does not exist on the ephemeral CI cluster or a throwaway
        # local one; dropped rather than attaching a production ILM policy
        # name to a test index (code-reviewer/security-auditor review).
        cls.index_settings = {k: v for k, v in template["settings"].items()
                               if not k.startswith("index.lifecycle")}
        cls.index_mappings = template["mappings"]

    def setUp(self):
        self.index = f"livefire-test-{uuid.uuid4().hex[:12]}"
        # Registered before the PUT so a fresh index is always cleaned up
        # even if index creation itself times out or errors after ES already
        # created it — unittest does not call tearDown() when setUp() raises,
        # so a bare tearDown() alone can leak an index on that path
        # (security-auditor review).
        self.addCleanup(self._delete_index)
        r = requests.put(f"{ES_URL}/{self.index}", auth=ES_AUTH, verify=ES_VERIFY, timeout=10,
                          json={"settings": self.index_settings, "mappings": self.index_mappings})
        r.raise_for_status()

    def _delete_index(self):
        r = requests.delete(f"{ES_URL}/{self.index}", auth=ES_AUTH, verify=ES_VERIFY, timeout=10)
        # 404 is fine (index was never created, or already gone); anything
        # else is worth knowing about even though it can't fail the test at
        # this point — a leaked index only matters against a real, persistent
        # cluster (never CI, which discards the whole service container).
        if r.status_code not in (200, 404):
            print(f"WARNING: failed to delete test index {self.index}: "
                  f"HTTP {r.status_code}: {r.text[:200]}")

    def _index(self, doc_id: str, doc: dict):
        r = requests.put(f"{ES_URL}/{self.index}/_doc/{doc_id}", auth=ES_AUTH, verify=ES_VERIFY,
                          timeout=10, json=doc)
        r.raise_for_status()

    def _refresh(self):
        requests.post(f"{ES_URL}/{self.index}/_refresh", auth=ES_AUTH, verify=ES_VERIFY, timeout=10)

    def _matched_ids(self, lucene_query: str) -> set:
        # size=100: comfortably above the 1-TP + a handful of TN fixtures any
        # rule in this repo has today; bumped if a fixture list ever grows
        # past it, rather than a value inferred from that list's current
        # length (code-reviewer review).
        r = requests.post(f"{ES_URL}/{self.index}/_search", auth=ES_AUTH, verify=ES_VERIFY, timeout=10,
                           json={"query": {"query_string": {"query": lucene_query}},
                                 "_source": False, "size": 100})
        r.raise_for_status()
        return {hit["_id"] for hit in r.json()["hits"]["hits"]}

    def assert_rule_fires_correctly(self, rule_filename: str):
        """The core live-fire assertion: compile the rule for real, translate
        its fixtures through the real pipeline mapping, index them into a
        realistically-mapped index, and require the compiled query to match
        the true_positive doc and NONE of the true_negative docs."""
        rule_path = SIGMA_DIR / rule_filename
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        fx = FIXTURES[rule_filename]

        compiled = sigma_convert_one(rule_path)
        mapping = load_pipeline_field_mapping(rule.get("logsource", {}))

        self._index("tp", translate_fixture(fx["true_positive"], mapping))
        for i, neg in enumerate(fx.get("true_negatives", [])):
            self._index(f"tn-{i}", translate_fixture(neg, mapping))
        self._refresh()

        matched = self._matched_ids(compiled["query"])
        self.assertIn("tp", matched,
                       f"{rule_filename}: compiled query did NOT match its own true_positive "
                       f"fixture against a real, realistically-mapped Elasticsearch index — "
                       f"logic that passes sigma_eval.py can still be a no-op in production")
        false_positives = {m for m in matched if m.startswith("tn-")}
        self.assertFalse(false_positives,
                          f"{rule_filename}: compiled query matched true_negative fixture(s) "
                          f"{sorted(false_positives)} against a real index")


class ProcessCreationLiveFireTests(LiveFireTestCase):
    def test_powershell_encoded_command_fires_against_real_es(self):
        self.assert_rule_fires_correctly("proc_creation_win_powershell_encoded.yml")


class NetworkLiveFireTests(LiveFireTestCase):
    def test_zeek_executable_download_fires_against_real_es(self):
        # net_zeek_executable_download.yml over the other two net_zeek_*.yml
        # rules specifically because ITS logsource (product: zeek, service:
        # files) is the one covered by a real pipeline transformation
        # (source -> zeek.source) — this is the exact rule #217's MEDIUM-4
        # finding was about (queried the pre-rename field name, could never
        # fire). net_zeek_port_scan.yml's `note` field has no pipeline
        # mapping at all, so it would exercise zero field translation — the
        # one thing this whole test module exists to catch (security-auditor
        # + code-reviewer review, independently).
        self.assert_rule_fires_correctly("net_zeek_executable_download.yml")

    def test_zeek_dns_dga_burst_fires_against_real_es(self):
        # #228 (M13 US5): before this batch, 0 of the 5 new zeek/dns-ssl-conn-
        # http-smtp logsources had live-fire coverage — exactly where a
        # pipeline mapping this repo added but never proved against a real
        # cluster could be self-consistently wrong (sigma_eval.py and the
        # real backend both trusting the same untested assumption about how
        # Lucene's `re` modifier behaves is not independent verification).
        # This rule specifically exercises two things that couldn't be
        # confirmed without a real Elasticsearch in the environment this
        # batch was authored in: (1) that field-mapping-zeek-dns's
        # rcode_name -> dns.response_code rename (corrected from the wrong
        # dns.response.code during review) actually matches real ingested
        # data, and (2) that the `re` Sigma modifier's Lucene-compiled
        # regexp query genuinely performs the assumed full-string,
        # no-anchors-needed match against a real keyword-mapped field, not
        # just against sigma_eval.py's Python re.fullmatch reimplementation
        # of that same assumption.
        self.assert_rule_fires_correctly("net_zeek_dns_dga_nxdomain_burst.yml")


class LinuxAuthLiveFireTests(LiveFireTestCase):
    def test_su_session_opened_fires_against_real_es(self):
        # M13 US7 (#230/#243): `message` is the first field this whole rule
        # corpus has ever selected on that's mapped `text` (analyzed,
        # tokenized) rather than `keyword` in the real index template -
        # every other field in every other rule is keyword-mapped, where
        # bare Sigma field equality and Elasticsearch's query_string term
        # mean the same "whole value equals target" thing. For a `text`
        # field they don't: a bare (non-wildcard) query_string term IS
        # analyzed at query time, so it matches any document where the
        # target is ONE OF THE TOKENS in the field, not where the field's
        # entire value equals it. sigma_eval.py was extended to model this
        # (_TEXT_MAPPED_FIELDS, word-boundary match instead of whole-string
        # equality) based on that reasoning plus a `sigma convert` probe
        # showing the compiled query shape - but neither of those proves
        # real Elasticsearch's query_string parser actually behaves this
        # way for an unquoted bare term against a `text` field. This rule
        # is the best stress test available: FOUR separate bare-equality
        # word selectors ANDed together (su, session, opened, plus
        # event.module) against one message value, the most co-occurring
        # conditions any rule in this batch asks the real backend to
        # satisfy at once.
        self.assert_rule_fires_correctly("auth_linux_su_session_opened.yml")


class WindowsSecurityLiveFireTests(LiveFireTestCase):
    def test_pass_the_hash_logon_fires_against_real_es(self):
        # M13 US6 (#229/#242): before this batch, field-mapping-windows-
        # security had never been live-fire tested at all — every prior
        # Security-channel rule's coverage came from sigma_eval.py fixtures
        # only. This batch adds 5 new fields to that mapping (LogonType,
        # AuthenticationPackageName, SubStatus, ObjectType, ObjectName);
        # auth_win_pass_the_hash_logon.yml exercises two of them together
        # (LogonType + AuthenticationPackageName), proving the rename
        # actually lands as winlog.event_data.* against a real,
        # realistically-mapped index rather than just against
        # suburban-soc-ecs.yml's own self-consistent assumption about it.
        self.assert_rule_fires_correctly("auth_win_pass_the_hash_logon.yml")


class ThresholdLiveFireTests(LiveFireTestCase):
    """Threshold rules (rules/elastic/threshold/*.ndjson) have no fixtures.json
    entry — sigma_eval.py can't express cardinality logic at all (see that
    module's own docstring), which is exactly the gap this issue exists to
    close. Live-fire tests the aggregation directly: index enough matching
    events to cross threshold.value and confirm the terms aggregation Kibana's
    Detection Engine would use actually buckets them; index one fewer and
    confirm it does not. Also tests the rule's own from/to lookback window —
    the property its own description calls out as the actual security-
    relevant one (a tumbling, non-overlapping window lets an attacker
    straddle two scheduled runs and stay under threshold in either)."""

    NDJSON = THRESHOLD_DIR / "auth-win-bruteforce-failed-logons.ndjson"

    def _threshold_rule(self) -> dict:
        line = next(ln for ln in self.NDJSON.read_text(encoding="utf-8").splitlines() if ln.strip())
        return json.loads(line)

    def _index_failed_logon(self, doc_id: str, target_user: str, timestamp: str):
        self._index(doc_id, {"@timestamp": timestamp, "winlog": {
            "event_id": 4625, "event_data": {"TargetUserName": target_user}}})

    def _bucket_count(self, rule: dict, target_user: str) -> int:
        # The rule's own from/to (ES understands "now-6m"/"now" date math
        # natively, same syntax Kibana's Detection Engine passes through) —
        # a bare query with no range filter would count events the rule
        # itself would never see, and could not catch a broken lookback
        # window (security-auditor review).
        r = requests.post(f"{ES_URL}/{self.index}/_search", auth=ES_AUTH, verify=ES_VERIFY, timeout=10,
                           json={"query": {"bool": {"must": [
                                     {"query_string": {"query": rule["query"]}},
                                     {"range": {"@timestamp": {"gte": rule["from"], "lte": rule["to"]}}},
                                 ]}},
                                 "size": 0,
                                 "aggs": {"by_field": {"terms": {
                                     "field": rule["threshold"]["field"][0],
                                     "min_doc_count": rule["threshold"]["value"]}}}})
        r.raise_for_status()
        buckets = r.json()["aggregations"]["by_field"]["buckets"]
        matching = [b for b in buckets if b["key"] == target_user]
        return matching[0]["doc_count"] if matching else 0

    def test_threshold_crossed_when_value_met(self):
        rule = self._threshold_rule()
        n = rule["threshold"]["value"]
        now = datetime.now(timezone.utc).isoformat()
        for i in range(n):
            self._index_failed_logon(f"hit-{i}", "victim.crossed", now)
        self._refresh()
        self.assertGreaterEqual(
            self._bucket_count(rule, "victim.crossed"), n,
            f"threshold companion for {self.NDJSON.name}: {n} matching events did not "
            f"cross its own threshold.value against a real terms aggregation")

    def test_threshold_not_crossed_below_value(self):
        rule = self._threshold_rule()
        n = rule["threshold"]["value"] - 1
        now = datetime.now(timezone.utc).isoformat()
        for i in range(n):
            self._index_failed_logon(f"hit-{i}", "victim.notcrossed", now)
        self._refresh()
        self.assertEqual(
            self._bucket_count(rule, "victim.notcrossed"), 0,
            f"threshold companion for {self.NDJSON.name}: {n} events (one below "
            f"threshold.value) incorrectly crossed the threshold — min_doc_count is not "
            f"actually enforcing the documented value")

    def test_threshold_events_outside_lookback_window_do_not_count(self):
        """Enough events to cross threshold.value, but timestamped well
        before the rule's own `from` — must NOT cross. A rule whose from/to
        got dropped or widened would silently pass the other two tests
        (which only ever index "now") but fail this one."""
        rule = self._threshold_rule()
        n = rule["threshold"]["value"]
        stale = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        for i in range(n):
            self._index_failed_logon(f"hit-{i}", "victim.stale", stale)
        self._refresh()
        self.assertEqual(
            self._bucket_count(rule, "victim.stale"), 0,
            f"threshold companion for {self.NDJSON.name}: {n} events timestamped an hour "
            f"before the rule's own \"from\": {rule['from']!r} still crossed threshold — "
            f"the lookback window is not actually being enforced")


if __name__ == "__main__":
    unittest.main(verbosity=2)
