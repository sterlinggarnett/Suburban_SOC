#!/usr/bin/env python3
"""
Regression guard for the 2026-09-07 zeek-host-capture.service outage.

Root cause: both capture units run as root but set CapabilityBoundingSet=
WITHOUT CAP_DAC_OVERRIDE, so ordinary DAC checks apply to them. ${SOC_REPO}
lives under /home/tjlam (mode 750, tjlam:tjlam) and root is neither the owner
nor in that group, so the units cannot even traverse into the checkout. Every
ExecStartPre/ExecStart that reads from ${SOC_REPO} fails with EACCES.

Three separate defects came out of it, one assertion group each:

1. The traversal itself. Fixed with SupplementaryGroups=tjlam rather than
   CAP_DAC_OVERRIDE: group tjlam already holds r-x on /home/tjlam and the files
   the units read are mode 644, so it grants exactly what is needed instead of
   restoring filesystem-wide root read+write to a unit that runs tcpdump.
   suricata-host-capture.service carries the identical defect (it reads
   ${SOC_REPO}/configs/suricata/suricata.yaml from ExecStart=) and is fixed
   here too -- it has simply never been hit, because it is not installed on the
   capture host.

2. The silenced refresh. The config.zeek/intel.dat refresh cp's were written
   `2>/dev/null || true`, so an EACCES produced no journal line at all. #389's
   guard then reported the deployed copy as "stale" -- true, but the symptom,
   not the cause. A one-line permission error became a 1181-restart mystery.
   The cp's now capture stderr and warn with it, and the FATAL says explicitly
   that a preceding WARNING is the real cause.

3. The unbounded loop -- DIAGNOSED, NOT FIXED HERE. StartLimitIntervalSec=0
   disables the restart limiter outright, so a PERMANENT ExecStartPre failure
   retries forever (~26h, 1181+ restarts, no capture and no alert). Bounding it
   would fix that but would also give up on a slow Docker engine start, which is
   the scenario that line exists for and which
   test_zeek_capture_iface_validation.py / test_suricata_config.py both assert.
   Left for an owner decision; recorded in the unit's own comments and in
   plans/20260907-restore-zeek-capture-and-deploy-m26.md.

   Measured 2026-09-07 with a throwaway --user unit: RestartPreventExitStatus=
   does NOT cover an ExecStartPre control process (a unit whose ExecStartPre
   exits 78 still restart-loops; NRestarts climbed with
   ActiveState=activating/auto-restart). So the #551 CAPTURE_IFACE preflight
   must STAY inside ExecStart -- moving it into an ExecStartPre= would silently
   break the parking behaviour it exists to provide. Asserted below so nobody
   "tidies" it into an ExecStartPre later. This is also why defect 3 above has
   no clean in-unit fix: an ExecStartPre guard can neither park via exit 78 nor
   exhaust a disabled limiter.

Static text assertions against the real unit files, same convention as this
directory's other Zeek-capture-path checks (see
test_zeek_capture_iface_hardening.py, test_intel_dir_perms_hardening.py) --
no live systemd/Docker needed.

Run:  python tests/pipeline/test_capture_unit_repo_access.py  (or: pytest tests/pipeline)
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ZEEK_UNIT_PATH = ROOT / "configs" / "systemd" / "zeek-host-capture.service"
SURICATA_UNIT_PATH = ROOT / "configs" / "systemd" / "suricata-host-capture.service"
HOST_CAPTURE_SH = ROOT / "scripts" / "setup" / "host_capture.sh"

ZEEK_UNIT = ZEEK_UNIT_PATH.read_text(encoding="utf-8")
SURICATA_UNIT = SURICATA_UNIT_PATH.read_text(encoding="utf-8")

CAPTURE_UNITS = (
    (ZEEK_UNIT_PATH.name, ZEEK_UNIT),
    (SURICATA_UNIT_PATH.name, SURICATA_UNIT),
)


def _directive(text: str, key: str) -> list:
    """Every value assigned to `key`, ignoring comment lines."""
    return [
        line.split("=", 1)[1].strip()
        for line in text.splitlines()
        if not line.lstrip().startswith("#") and line.startswith(key + "=")
    ]


class RepoTraversalTests(unittest.TestCase):
    """Defect 1 -- the units must be able to read ${SOC_REPO}."""

    def test_units_reading_soc_repo_declare_supplementary_group(self):
        for name, unit in CAPTURE_UNITS:
            with self.subTest(unit=name):
                if "${SOC_REPO}" not in unit:
                    self.skipTest(f"{name} no longer reads ${{SOC_REPO}}")
                self.assertEqual(
                    _directive(unit, "SupplementaryGroups"),
                    ["tjlam"],
                    f"{name} reads ${{SOC_REPO}} (under /home/tjlam, mode 750) but does not "
                    "declare SupplementaryGroups=tjlam. Without it a root process whose "
                    "CapabilityBoundingSet= omits CAP_DAC_OVERRIDE cannot traverse into the "
                    "checkout, and every read from ${SOC_REPO} fails with EACCES.",
                )

    def test_dac_capabilities_are_not_used_as_the_fix(self):
        for name, unit in CAPTURE_UNITS:
            with self.subTest(unit=name):
                for value in _directive(unit, "CapabilityBoundingSet"):
                    self.assertNotIn(
                        "CAP_DAC_OVERRIDE",
                        value,
                        f"{name}: CAP_DAC_OVERRIDE restores filesystem-wide root read AND write "
                        "to a raw-capture unit. SupplementaryGroups= grants only the traversal "
                        "actually needed -- see this file's module docstring.",
                    )
                    self.assertNotIn(
                        "CAP_DAC_READ_SEARCH",
                        value,
                        f"{name}: CAP_DAC_READ_SEARCH is still filesystem-wide read bypass; "
                        "SupplementaryGroups= is the narrower fix.",
                    )


class SilentRefreshFailureTests(unittest.TestCase):
    """Defect 2 -- a failed refresh must say so."""

    def test_refresh_cp_does_not_discard_stderr(self):
        refresh = [
            line
            for line in ZEEK_UNIT.splitlines()
            if line.startswith("ExecStartPre=") and "cp --remove-destination" in line
        ]
        self.assertTrue(
            refresh, "could not find the config/intel refresh ExecStartPre line"
        )
        for line in refresh:
            self.assertNotIn(
                "2>/dev/null",
                line,
                "the refresh cp must not discard stderr: swallowing EACCES here is exactly "
                "what turned a one-line permission error into a 1181-restart outage whose "
                "only symptom pointed at the wrong file.",
            )

    def test_stale_config_fatal_points_at_the_preceding_warning(self):
        self.assertRegex(
            ZEEK_UNIT,
            r"FATAL: deployed [^\"']*config\.zeek is stale",
            "the stale-config guard's FATAL message changed shape unexpectedly",
        )
        self.assertIn(
            "WARNING",
            ZEEK_UNIT,
            "the refresh failure must be reported as a WARNING that the FATAL then refers to",
        )


class PreflightPlacementTests(unittest.TestCase):
    """RestartPreventExitStatus= does not cover ExecStartPre -- keep the preflight in ExecStart."""

    def test_preflight_runs_from_execstart_not_execstartpre(self):
        self.assertIn(
            "capture_iface_preflight.sh",
            HOST_CAPTURE_SH.read_text(encoding="utf-8"),
            "the CAPTURE_IFACE preflight should be invoked from host_capture.sh (ExecStart)",
        )
        for line in ZEEK_UNIT.splitlines():
            if line.startswith("ExecStartPre="):
                self.assertNotIn(
                    "capture_iface_preflight",
                    line,
                    "the preflight must NOT move into ExecStartPre=: measured 2026-09-07, "
                    "RestartPreventExitStatus= only covers the MAIN process, so an "
                    "ExecStartPre exiting 78 restart-loops instead of parking the unit. "
                    "Moving it here would silently disable #551's parking behaviour.",
                )

    def test_exit_78_is_still_reserved_to_the_preflight(self):
        for line in ZEEK_UNIT.splitlines():
            if line.startswith("ExecStartPre=") and re.search(r"\bexit 78\b", line):
                self.fail(
                    "an ExecStartPre= mints exit 78, which cannot park the unit "
                    "(RestartPreventExitStatus= covers the main process only) and muddies "
                    "the EX_CONFIG contract host_capture.sh documents. Bound the loop with "
                    "StartLimitBurst= instead."
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
