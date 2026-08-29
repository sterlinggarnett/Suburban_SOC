#!/usr/bin/env python3
"""
#373: `vanished_claims` is edge-triggered (see slo_metrics.py's own
metric_vanished_claims()/`_vanished_claims_detail()` docstrings) — once the
prior-sample baseline rolls forward past a deleted claim doc, the metric
returns to 0 on the very next run regardless of whether anyone
investigated. Unlike `stuck_approval_claims`/`orphaned_claims`, the metric
existed and alerted via ntfy, but `configs/server/slo_dashboard.ndjson` had
no panel for it at all — the SLO dashboard itself showed nothing for a
metric this security-sensitive.

Static structural check that the panel exists, is wired to the correct
soc-slo-metrics field, and is actually placed on the dashboard (not just a
saved-object orphan that never renders anywhere) — no live Kibana needed,
matching this directory's existing convention (see
test_dashboard_field_mapping.py).

Run:  python -m pytest tests/dashboards/test_slo_vanished_claims_panel.py
"""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_PATH = ROOT / "configs" / "server" / "slo_dashboard.ndjson"


def _load_objects():
    with open(DASHBOARD_PATH, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class VanishedClaimsPanelTests(unittest.TestCase):
    def setUp(self):
        self.objects = _load_objects()
        self.panel = next(
            (o for o in self.objects
             if o.get("type") == "visualization" and o.get("id") == "slo-vanished-claims"),
            None)
        self.dashboard = next(
            (o for o in self.objects if o.get("type") == "dashboard" and o.get("id") == "soc-slo"),
            None)

    def test_panel_exists(self):
        self.assertIsNotNone(self.panel, "expected a 'slo-vanished-claims' visualization saved object")

    def test_panel_references_the_vanished_claims_metric_field(self):
        vis_state = json.loads(self.panel["attributes"]["visState"])
        fields = [agg["params"]["field"] for agg in vis_state["aggs"] if "field" in agg.get("params", {})]
        self.assertIn("slo.vanished_claims.value", fields)

    def test_panel_targets_the_soc_slo_index_pattern(self):
        # Same index-pattern reference every other panel here uses — a
        # panel pointed at the wrong pattern renders empty, same symptom
        # as no data existing at all (see test_dashboard_field_mapping.py's
        # own module docstring for this exact failure class).
        refs = {r["name"]: r["id"] for r in self.panel["references"]}
        self.assertEqual(
            refs.get("kibanaSavedObjectMeta.searchSourceJSON.index"), "soc-slo-pattern")

    def test_panel_is_actually_placed_on_the_dashboard(self):
        # A saved-object visualization that exists but was never added to
        # soc-slo's own panelsJSON/references is invisible to anyone
        # opening the dashboard — this is the check that would have caught
        # a "created the panel, forgot to wire it in" mistake.
        self.assertIsNotNone(self.dashboard, "expected the 'soc-slo' dashboard saved object")
        ref_ids = {r["id"] for r in self.dashboard["references"] if r["type"] == "visualization"}
        self.assertIn("slo-vanished-claims", ref_ids)

        panel_ref_names = {r["name"].split(":", 1)[1] for r in self.dashboard["references"]
                            if r["id"] == "slo-vanished-claims"}
        panels = json.loads(self.dashboard["attributes"]["panelsJSON"])
        placed_ref_names = {p["panelRefName"] for p in panels}
        self.assertTrue(
            panel_ref_names & placed_ref_names,
            "slo-vanished-claims is referenced by the dashboard but has no "
            "corresponding entry in panelsJSON — it would never actually render")

    def test_panel_target_matches_the_metric_module_target(self):
        # vanished_claims' target is hardcoded 0 in slo_metrics.py's own
        # TARGETS dict (not overridable in a way this static test can read
        # live) — lock in that the panel's displayed subtext agrees with
        # the metric it's presenting, so a future target change to one
        # doesn't silently drift from the other.
        vis_state = json.loads(self.panel["attributes"]["visState"])
        sub_text = vis_state["params"]["metric"]["style"]["subText"]
        self.assertEqual(sub_text, "target <= 0")


if __name__ == "__main__":
    unittest.main()
