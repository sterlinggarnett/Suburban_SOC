#!/usr/bin/env python3
"""
Threat-hunt runner — measurement-error visibility tests (audit #165 / NIST SI-11).

run_hunts.py must distinguish "a hunt's ES query failed" from "a hunt
genuinely found 0 matches", and must exit non-zero if any hunt failed to
query or the final bulk index write failed — it must never silently exit 0.

Run:  pytest tests/hunts/test_run_hunts.py
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# ES_PASS is read at import time; must be truthy or main() exits(1) immediately.
os.environ["ES_PASS"] = "unit_test_pass"

import env_loader
import run_hunts


HUNT_A = """
id: HUNT-TEST-A
title: Test hunt A
attack: ["T1110"]
index: logstash-security-*
query: "*"
threshold: 1
"""

HUNT_B = """
id: HUNT-TEST-B
title: Test hunt B
attack: ["T1046"]
index: logstash-security-*
query: "*"
threshold: 1
"""


class _FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class EsCountTests(unittest.TestCase):
    def test_raises_on_request_exception(self):
        with mock.patch.object(run_hunts.SESSION, "post", side_effect=ConnectionError("refused")):
            with self.assertRaises(run_hunts.HuntQueryUnavailable):
                run_hunts.es_count("logstash-security-*", "*")

    def test_raises_on_non_200(self):
        with mock.patch.object(run_hunts.SESSION, "post", return_value=_FakeResponse(503)):
            with self.assertRaises(run_hunts.HuntQueryUnavailable):
                run_hunts.es_count("logstash-security-*", "*")

    def test_returns_real_zero_when_es_is_healthy(self):
        with mock.patch.object(run_hunts.SESSION, "post",
                               return_value=_FakeResponse(200, {"count": 0})):
            self.assertEqual(run_hunts.es_count("logstash-security-*", "*"), 0)


class MainExitCodeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        hunts_dir = Path(self._tmp.name)
        (hunts_dir / "HUNT-TEST-A.yml").write_text(HUNT_A, encoding="utf-8")
        (hunts_dir / "HUNT-TEST-B.yml").write_text(HUNT_B, encoding="utf-8")
        self._hunts_patch = mock.patch.object(run_hunts, "HUNTS_DIR", hunts_dir)
        self._hunts_patch.start()

    def tearDown(self):
        self._hunts_patch.stop()
        self._tmp.cleanup()

    def _run_main_capturing_exit(self):
        try:
            run_hunts.main()
        except SystemExit as e:
            return e.code
        return None

    def test_all_hunts_healthy_exits_0(self):
        with mock.patch.object(run_hunts.SESSION, "post") as post:
            post.side_effect = [
                _FakeResponse(200, {"count": 0}),   # HUNT-TEST-A query
                _FakeResponse(200, {"count": 0}),   # HUNT-TEST-B query
                _FakeResponse(200, {}),             # bulk index
            ]
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 0)

    def test_one_hunt_query_failure_exits_2_and_skips_that_hunt(self):
        with mock.patch.object(run_hunts.SESSION, "post") as post:
            post.side_effect = [
                ConnectionError("refused"),         # HUNT-TEST-A query fails
                _FakeResponse(200, {"count": 0}),   # HUNT-TEST-B query succeeds
                _FakeResponse(200, {}),             # bulk index (only B's doc)
            ]
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 2)
        # Only HUNT-TEST-B's doc pair should have been bulk-indexed — a failed
        # hunt must never fabricate a "0 matches" finding.
        bulk_call = post.call_args_list[-1]
        sent = bulk_call.kwargs["data"]
        self.assertIn("HUNT-TEST-B", sent)
        self.assertNotIn("HUNT-TEST-A", sent)

    def test_bulk_index_failure_exits_3(self):
        with mock.patch.object(run_hunts.SESSION, "post") as post:
            post.side_effect = [
                _FakeResponse(200, {"count": 0}),
                _FakeResponse(200, {"count": 0}),
                ConnectionError("refused"),         # bulk index fails
            ]
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 3)

    def test_hunt_meeting_threshold_is_a_finding(self):
        # HUNT-TEST-A's threshold is 1; a count of 3 must register as a finding
        # and be bulk-indexed with finding=true.
        with mock.patch.object(run_hunts.SESSION, "post") as post:
            post.side_effect = [
                _FakeResponse(200, {"count": 3}),   # HUNT-TEST-A: finding
                _FakeResponse(200, {"count": 0}),   # HUNT-TEST-B: no finding
                _FakeResponse(200, {}),             # bulk index
            ]
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 0)
        bulk_call = post.call_args_list[-1]
        sent = bulk_call.kwargs["data"]
        # The finding doc for HUNT-TEST-A must carry finding:true and the real count.
        # (Not the preceding bulk action line — audit #176's deterministic _id
        # embeds the hunt id there too, so a bare substring match would grab
        # either line.)
        parsed = [json.loads(line) for line in sent.splitlines() if line.strip()]
        doc = next(d for d in parsed if d.get("hunt", {}).get("id") == "HUNT-TEST-A")
        self.assertTrue(doc["finding"])
        self.assertEqual(doc["match_count"], 3)

    def test_bulk_action_uses_deterministic_per_day_id(self):
        # audit #176: same hunt, same day -> same _id, so a re-run overwrites
        # (upserts) the prior doc via ES's index op instead of accumulating a
        # new one every hourly cron tick.
        import datetime as _dt
        today = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
        with mock.patch.object(run_hunts.SESSION, "post") as post:
            post.side_effect = [
                _FakeResponse(200, {"count": 0}),
                _FakeResponse(200, {"count": 0}),
                _FakeResponse(200, {}),
            ]
            self._run_main_capturing_exit()
        sent = post.call_args_list[-1].kwargs["data"]
        parsed = [json.loads(line) for line in sent.splitlines() if line.strip()]
        actions = [p for p in parsed if "index" in p]
        ids = {a["index"]["_id"] for a in actions}
        self.assertEqual(ids, {f"HUNT-TEST-A:{today}", f"HUNT-TEST-B:{today}"})
        for a in actions:
            self.assertEqual(a["index"]["_index"], "soc-hunts")


class HuntIdValidationTests(unittest.TestCase):
    """#432: run_hunts.py's composite ES _id (hunt_id:day_bucket) is a
    deliberate UPSERT — an unsafe character in a hunt id, or two hunts
    colliding on the same composite key, must fail loudly BEFORE any bulk
    write, not silently overwrite one hunt's stored findings with
    another's."""

    def _run_main_capturing_exit(self):
        try:
            run_hunts.main()
        except SystemExit as e:
            return e.code
        return None

    def test_real_hunt_corpus_passes_validation_unchanged(self):
        # The actual real hunts/*.yml files, not a synthetic fixture.
        real_hunts = sorted(run_hunts.REPO.joinpath("hunts").glob("*.yml"))
        self.assertGreater(len(real_hunts), 0)
        run_hunts._validate_hunt_ids(real_hunts)  # must not raise/exit

    def test_colon_in_hunt_id_exits_1_before_any_bulk_write(self):
        with tempfile.TemporaryDirectory() as d:
            hunts_dir = Path(d)
            (hunts_dir / "bad.yml").write_text(
                "id: HUNT:BAD\ntitle: Bad\nattack: [\"T1110\"]\n"
                "index: logstash-security-*\nquery: \"*\"\nthreshold: 1\n",
                encoding="utf-8")
            with mock.patch.object(run_hunts, "HUNTS_DIR", hunts_dir), \
                 mock.patch.object(run_hunts.SESSION, "post") as post:
                code = self._run_main_capturing_exit()
            self.assertEqual(code, 1)
            post.assert_not_called()

    def test_colliding_explicit_ids_exits_1_before_any_bulk_write(self):
        with tempfile.TemporaryDirectory() as d:
            hunts_dir = Path(d)
            body = ("id: HUNT-SAME\ntitle: {}\nattack: [\"T1110\"]\n"
                    "index: logstash-security-*\nquery: \"*\"\nthreshold: 1\n")
            (hunts_dir / "one.yml").write_text(body.format("One"), encoding="utf-8")
            (hunts_dir / "two.yml").write_text(body.format("Two"), encoding="utf-8")
            with mock.patch.object(run_hunts, "HUNTS_DIR", hunts_dir), \
                 mock.patch.object(run_hunts.SESSION, "post") as post:
                code = self._run_main_capturing_exit()
            self.assertEqual(code, 1)
            post.assert_not_called()

    def test_valid_ids_are_unaffected(self):
        # Regression guard: the validation itself must not false-positive
        # on the ordinary [A-Za-z0-9_-]+ shape every real hunt id uses.
        with tempfile.TemporaryDirectory() as d:
            hunts_dir = Path(d)
            (hunts_dir / "HUNT-TEST-A.yml").write_text(HUNT_A, encoding="utf-8")
            (hunts_dir / "HUNT-TEST-B.yml").write_text(HUNT_B, encoding="utf-8")
            run_hunts._validate_hunt_ids(sorted(hunts_dir.glob("*.yml")))  # must not raise


class MainNoHuntsAndMissingCredsTests(unittest.TestCase):
    def test_no_hunts_found_exits_1(self):
        with tempfile.TemporaryDirectory() as empty_dir:
            with mock.patch.object(run_hunts, "HUNTS_DIR", Path(empty_dir)):
                try:
                    run_hunts.main()
                except SystemExit as e:
                    code = e.code
                else:
                    code = None
        self.assertEqual(code, 1)

    def test_missing_es_pass_exits_1(self):
        with mock.patch.object(run_hunts, "ES_PASS", ""):
            try:
                run_hunts.main()
            except SystemExit as e:
                code = e.code
            else:
                code = None
        self.assertEqual(code, 1)


class EnvLineParsingTests(unittest.TestCase):
    """#259: run_hunts.py had this repo's other hand-rolled .env-comment bug
    (byte-for-byte identical loader to slo_metrics.py's, before both were
    fixed to share env_loader.parse_env_line — full edge-case coverage in
    tests/setup/test_env_loader.py). This test exists specifically to prove
    run_hunts.py is actually WIRED to the shared parser, not a reverted-to-
    private-copy regression."""

    def test_run_hunts_is_wired_to_the_shared_env_loader(self):
        # security-auditor review: the actual production call path is
        # load_env_file(), not parse_env_line() directly.
        self.assertIs(run_hunts.env_loader.parse_env_line, env_loader.parse_env_line)
        self.assertIs(run_hunts.env_loader.load_env_file, env_loader.load_env_file)


if __name__ == "__main__":
    unittest.main(verbosity=2)
