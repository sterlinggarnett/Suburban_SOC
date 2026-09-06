#!/usr/bin/env python3
"""
#558 — the sandboxing directive set must not drift between sibling units.

`intel-refresh.service` carried seven directives that `slo-metrics.service` did
not, and its own comment claimed the set had been "verified against this exact
directive set working for slo-metrics.service in production" — while the unit it
named as the reference had none of them. The porting had only ever gone one way.
Both run as the same `User=`, make the same class of outbound HTTPS calls, and
are `Type=oneshot` on a timer, so nothing about either argued for the difference.

Measured, not asserted (`systemd-analyze security --offline=true`):
`slo-metrics.service` was **3.8 OK** before and **1.6 OK** after, which is
exactly what `intel-refresh.service`, `checkpoints-compact.service`,
`threat-intel-compact.service` and `stack-health.service` all score.

These tests exist so the next unit added to the family has to make an explicit
decision rather than inheriting a gap by omission.

Run:  python tests/pipeline/test_systemd_sandbox_parity.py
      (or: pytest tests/pipeline)
"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SYSTEMD = ROOT / "configs" / "systemd"

# Every Type=oneshot unit that runs as the repo owner and makes outbound HTTPS
# calls to the stack. Adding a unit here without the directives below fails.
SANDBOXED_ONESHOT_UNITS = [
    "slo-metrics.service",
    "stack-health.service",
    "intel-refresh.service",
    "checkpoints-compact.service",
    "threat-intel-compact.service",
]

# The set #558 ported. `SystemCallErrorNumber=EPERM` is paired with
# `SystemCallFilter=` deliberately: without it a filtered call kills the process
# with SIGSYS instead of returning an error the program can report.
REQUIRED_DIRECTIVES = [
    "RestrictAddressFamilies",
    "SystemCallFilter",
    "SystemCallErrorNumber",
    "PrivateDevices",
    "ProtectProc",
    "ProcSubset",
]

# MemoryMax= is NOT required of every unit above, and that exemption is
# deliberate rather than an oversight. The three units that set it have a stated
# basis for the number: intel-refresh reads whole third-party HTTP responses
# into bash variables (256M is a real control against a misbehaving feed), and
# the two self-monitoring lanes use 512M because an OOM-killed monitoring run is
# a silent gap in exactly the lane meant to notice gaps. The two compactors do
# bulk deletion whose working set has never been measured — neither is installed
# on this host — and inventing a ceiling for a retention job that could then be
# OOM-killed mid-run is worse than leaving it unbounded until someone can
# measure it. Listed explicitly so the exemption is a decision, not a silence.
MEMORY_BOUNDED_UNITS = [
    "slo-metrics.service",
    "stack-health.service",
    "intel-refresh.service",
]


def _text(unit):
    return (SYSTEMD / unit).read_text(encoding="utf-8")


def _directive_values(text, key):
    return [ln.split("=", 1)[1].strip()
            for ln in text.splitlines() if ln.startswith(key + "=")]


class SandboxParityTests(unittest.TestCase):
    def test_every_unit_in_the_family_exists(self):
        for unit in SANDBOXED_ONESHOT_UNITS:
            with self.subTest(unit=unit):
                self.assertTrue((SYSTEMD / unit).is_file(), f"{unit} is missing")

    def test_every_unit_carries_the_full_directive_set(self):
        for unit in SANDBOXED_ONESHOT_UNITS:
            text = _text(unit)
            for directive in REQUIRED_DIRECTIVES:
                with self.subTest(unit=unit, directive=directive):
                    self.assertTrue(
                        _directive_values(text, directive),
                        f"{unit} is missing {directive}= — the set is shared across "
                        "the whole oneshot family (#558); a new unit must opt in "
                        "explicitly or be added to an exemption list with a reason",
                    )

    def test_netlink_is_permitted_everywhere_in_the_family(self):
        """Retained as a measured precaution, not a demonstrated requirement —
        see the corrected comment in each unit. Paired --user probes on this
        host showed getaddrinfo() succeeding with AND without AF_NETLINK, while
        AF_PACKET stayed blocked in both (proving the restriction really is
        enforced). It stays because getaddrinfo() does use netlink where
        AI_ADDRCONFIG has to enumerate interfaces, so dropping it would trade a
        free allowance for a portability failure on someone else's host."""
        for unit in SANDBOXED_ONESHOT_UNITS:
            with self.subTest(unit=unit):
                families = _directive_values(_text(unit), "RestrictAddressFamilies")[0]
                self.assertIn("AF_NETLINK", families)
                self.assertIn("AF_UNIX", families)

    def test_syscall_filter_returns_an_error_rather_than_killing(self):
        """`SystemCallFilter=` alone raises SIGSYS on a filtered call, which
        kills the process with no usable diagnostic. Paired with
        `SystemCallErrorNumber=` it returns EPERM, which the program can report
        — the difference between a monitoring lane that says what went wrong and
        one that vanishes."""
        for unit in SANDBOXED_ONESHOT_UNITS:
            with self.subTest(unit=unit):
                text = _text(unit)
                self.assertEqual(["@system-service"],
                                 _directive_values(text, "SystemCallFilter"))
                self.assertEqual(["EPERM"],
                                 _directive_values(text, "SystemCallErrorNumber"))

    def test_memory_bounded_units_declare_a_ceiling(self):
        for unit in MEMORY_BOUNDED_UNITS:
            with self.subTest(unit=unit):
                self.assertTrue(_directive_values(_text(unit), "MemoryMax"),
                                f"{unit} lost its MemoryMax= ceiling")

    def test_the_memory_exemption_list_is_a_subset_of_the_family(self):
        """A typo here would silently stop asserting the ceiling."""
        self.assertTrue(set(MEMORY_BOUNDED_UNITS) <= set(SANDBOXED_ONESHOT_UNITS))

    def test_remove_ipc_is_absent_across_the_family(self):
        """All of these run as the interactive login account and are
        Type=oneshot on timers, so `RemoveIPC=true` would tear down IPC
        belonging to the operator's own desktop session on every run.
        intel-refresh.service reached this conclusion first."""
        for unit in SANDBOXED_ONESHOT_UNITS:
            with self.subTest(unit=unit):
                offenders = [v for v in _directive_values(_text(unit), "RemoveIPC")
                             if "true" in v]
                self.assertEqual([], offenders, f"RemoveIPC set in {unit}")

    def test_no_unit_claims_netlink_is_required_for_dns(self):
        """The claim propagated from intel-refresh.service to two other units
        before anyone measured it, and it does not hold on this host. Guard
        against it being pasted back in with the next unit."""
        for unit in SANDBOXED_ONESHOT_UNITS:
            with self.subTest(unit=unit):
                self.assertNotIn("AF_NETLINK is required, not optional", _text(unit))


if __name__ == "__main__":
    unittest.main(verbosity=2)
