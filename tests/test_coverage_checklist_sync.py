#!/usr/bin/env python3
"""
coverage_checklist.md <-> emulation_telemetry.map row-count drift guard (#414).

coverage_checklist.md's Network/Windows lanes list one bold-headed row per
emulation->detection pairing in configs/detections/emulation_telemetry.map,
by design duplicating the map's own [EMULATION: ...] section count. #414
found this checklist one row short of the map (missing
CREDENTIAL_ACCESS_SSH_CADENCE) with 3 technique IDs disagreeing between the
two files — silent drift nothing else in CI would have caught, since
validate_emulation_map.py checks the map against reality but never checks
the checklist against the map. This test closes that gap so a future
[EMULATION: ...] section added without a matching checklist row (or vice
versa) fails CI instead of going stale again.

Run:  pytest tests/test_coverage_checklist_sync.py
"""
import re
import unittest
from pathlib import Path

from validate_emulation_map import parse_map

REPO = Path(__file__).resolve().parents[1]
MAP_PATH = REPO / "configs" / "detections" / "emulation_telemetry.map"
CHECKLIST_PATH = REPO / "coverage_checklist.md"

# A checklist row is a top-level checkbox bullet whose visible text starts
# with a bold **NAME** — this is what distinguishes an emulation-pairing row
# from an "Operational to-dos" / "Global" checkbox bullet (plain text or a
# `code span`, never bold) in the same file.
CHECKLIST_ROW_RE = re.compile(r"^- \[[ x]\]\s*(?:\S+\s+)?\*\*([A-Z0-9_]+)\*\*", re.M)


def _map_section_names():
    emulations, errors = parse_map(MAP_PATH.read_text(encoding="utf-8"))
    assert not errors, f"emulation_telemetry.map failed to parse: {errors}"
    return [em.name for em in emulations]


def _checklist_row_names():
    return CHECKLIST_ROW_RE.findall(CHECKLIST_PATH.read_text(encoding="utf-8"))


class ChecklistMapSyncTests(unittest.TestCase):
    def test_checklist_row_count_matches_map_section_count(self):
        map_names = _map_section_names()
        checklist_names = _checklist_row_names()
        self.assertEqual(
            len(checklist_names), len(map_names),
            f"coverage_checklist.md has {len(checklist_names)} emulation rows "
            f"but configs/detections/emulation_telemetry.map has "
            f"{len(map_names)} [EMULATION: ...] sections — every map section "
            f"needs exactly one matching checklist row, and vice versa "
            f"(checklist: {sorted(checklist_names)}, map: {sorted(map_names)})")

    def test_every_map_section_has_a_matching_checklist_row(self):
        map_names = set(_map_section_names())
        checklist_names = set(_checklist_row_names())
        missing = map_names - checklist_names
        self.assertFalse(
            missing,
            f"[EMULATION: ...] section(s) with no coverage_checklist.md row: "
            f"{sorted(missing)}")

    def test_every_checklist_row_has_a_matching_map_section(self):
        map_names = set(_map_section_names())
        checklist_names = set(_checklist_row_names())
        extra = checklist_names - map_names
        self.assertFalse(
            extra,
            f"coverage_checklist.md row(s) with no matching [EMULATION: ...] "
            f"section in emulation_telemetry.map: {sorted(extra)}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
