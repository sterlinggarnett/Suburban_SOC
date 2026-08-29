#!/usr/bin/env python3
"""
#321: regression guard for the /storage/PCAP/intel symlink/ownership hardening.

Three independent findings, each with its own assertion here:

1. configs/systemd/zeek-host-capture.service's self-heal chown/chmod
   ExecStartPre (chown -h ... && chmod 1775 ...) has no way to guard chmod
   itself against a symlink swap between the chown and chmod steps (chmod
   has no -h/no-dereference equivalent on Linux). A hard, non-"-"-prefixed
   ExecStartPre immediately before that line narrows the window by refusing
   to start if the path is already missing or a symlink.

2. The same unit's intel.dat fallback `cp` (used only when the primary
   config-sync cp left intel.dat missing/empty) lacked --remove-destination,
   unlike the primary `cp -r` on the same line — since intel.dat is
   tjlam-OWNED (not just group-writable), tjlam could unlink it and plant a
   dangling symlink that the next restart's fallback cp would then write
   through as root.

3. Three sibling manual-capture scripts (stream_capture.sh,
   zeek_connect_host.sh, zeek_run_pcap.sh) each `sudo mkdir -p
   /storage/PCAP/intel` with no chown/chmod of their own, silently
   reintroducing the root:root 0755 state the systemd unit's own fix
   corrects if run by hand on a host where the directory doesn't exist yet.
   A shared helper (scripts/setup/lib/intel_dir_perms.sh) now applies the
   same chown -h/chmod 1775 fix in all three.

Static text/regex assertions against the real files, same convention as
this directory's other Zeek-capture-path checks (see
test_zeek_capture_iface_hardening.py, test_zeek_image_pin.py) — no live
systemd/Docker needed.

Run:  python tests/pipeline/test_intel_dir_perms_hardening.py  (or: pytest tests/pipeline)
"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICE_UNIT = (ROOT / "configs" / "systemd" / "zeek-host-capture.service").read_text(encoding="utf-8")
LIB_HELPER = ROOT / "scripts" / "setup" / "lib" / "intel_dir_perms.sh"
SIBLING_SCRIPTS = [
    ROOT / "scripts" / "setup" / "stream_capture.sh",
    ROOT / "scripts" / "setup" / "zeek_connect_host.sh",
    ROOT / "scripts" / "setup" / "zeek_run_pcap.sh",
]


def _lines(text: str) -> list:
    return text.splitlines()


class ChownChmodSymlinkGuardTests(unittest.TestCase):
    def test_hard_symlink_guard_immediately_precedes_the_chown_chmod_execstartpre(self):
        lines = _lines(SERVICE_UNIT)
        chown_idx = next(
            (i for i, line in enumerate(lines) if "chown -h root:${SOC_USER}" in line and "chmod 1775" in line),
            None,
        )
        self.assertIsNotNone(
            chown_idx,
            "could not find the self-heal 'chown -h root:${SOC_USER} ... && "
            "chmod 1775 ...' ExecStartPre line — did it move or get rewritten?",
        )
        self.assertTrue(
            lines[chown_idx].startswith("ExecStartPre=-"),
            "the chown/chmod self-heal line should stay '-'-prefixed "
            "(best-effort — capture availability outranks intel freshness)",
        )
        guard_line = lines[chown_idx - 1]
        self.assertTrue(
            guard_line.startswith("ExecStartPre=/bin/bash"),
            "expected a hard (non-'-'-prefixed) ExecStartPre immediately "
            "before the chown/chmod self-heal line, found: " + guard_line,
        )
        self.assertIn(
            "[ -d /storage/PCAP/intel ]", guard_line,
            "the guard line should check /storage/PCAP/intel is a directory",
        )
        self.assertIn(
            "[ ! -L /storage/PCAP/intel ]", guard_line,
            "the guard line should refuse to proceed if /storage/PCAP/intel "
            "is a symlink",
        )

    def test_guard_line_is_not_best_effort(self):
        # A "-"-prefixed guard here would defeat its own purpose: it exists
        # specifically to hard-fail ExecStart when the directory is already
        # a symlink, not to degrade quietly like the self-heal chain below it.
        lines = _lines(SERVICE_UNIT)
        guard_idx = next(
            (
                i
                for i, line in enumerate(lines)
                if line.startswith("ExecStartPre=/bin/bash") and "/storage/PCAP/intel" in line and "-L" in line
            ),
            None,
        )
        self.assertIsNotNone(guard_idx, "could not find the #321 hard symlink guard ExecStartPre line")
        self.assertFalse(
            lines[guard_idx].startswith("ExecStartPre=-"),
            "the #321 symlink guard must NOT be '-'-prefixed — a symlinked "
            "intel dir here means it's already compromised, so ExecStart "
            "should hard-fail rather than silently continue",
        )


class IntelDatFallbackCpHardeningTests(unittest.TestCase):
    def _intel_sync_execstartpre(self) -> str:
        for line in _lines(SERVICE_UNIT):
            if line.startswith("ExecStartPre=") and "intel.seed.dat" in line:
                return line
        raise AssertionError("could not find the intel.dat-sync ExecStartPre line")

    def test_both_cp_invocations_use_remove_destination(self):
        line = self._intel_sync_execstartpre()
        self.assertIn(
            "cp -r --remove-destination", line,
            "the primary config-sync 'cp -r' should keep --remove-destination",
        )
        self.assertIn(
            "cp --remove-destination ${SOC_REPO}/configs/intel/intel.seed.dat", line,
            "the intel.dat fallback cp is missing --remove-destination — "
            "without it, a dangling symlink planted at intel.dat (tjlam "
            "owns that file, not just the directory) would have this cp "
            "write through it as root instead of replacing it (#321)",
        )


class SiblingScriptsApplyIntelDirPermsTests(unittest.TestCase):
    def test_lib_helper_exists_and_defines_the_shared_function(self):
        self.assertTrue(LIB_HELPER.is_file(), f"expected {LIB_HELPER} to exist")
        helper_text = LIB_HELPER.read_text(encoding="utf-8")
        self.assertIn("harden_intel_dir_perms()", helper_text)
        self.assertIn("chown -h", helper_text)
        self.assertIn("chmod 1775", helper_text)

    def test_every_sibling_script_sources_the_helper_and_calls_it_after_mkdir(self):
        for script_path in SIBLING_SCRIPTS:
            text = script_path.read_text(encoding="utf-8")
            lines = _lines(text)
            mkdir_idx = next(
                (i for i, line in enumerate(lines) if "mkdir -p /storage/PCAP/intel" in line),
                None,
            )
            self.assertIsNotNone(
                mkdir_idx, f"{script_path.name}: could not find 'mkdir -p /storage/PCAP/intel'"
            )
            source_idx = next(
                (i for i, line in enumerate(lines) if "lib/intel_dir_perms.sh" in line and line.strip().startswith("source")),
                None,
            )
            self.assertIsNotNone(
                source_idx, f"{script_path.name}: does not source lib/intel_dir_perms.sh"
            )
            self.assertGreater(
                source_idx, mkdir_idx,
                f"{script_path.name}: sources intel_dir_perms.sh before the "
                "mkdir -p that creates the directory it's meant to harden",
            )
            call_idx = next(
                (i for i, line in enumerate(lines) if "harden_intel_dir_perms /storage/PCAP/intel tjlam" in line),
                None,
            )
            self.assertIsNotNone(
                call_idx, f"{script_path.name}: never calls harden_intel_dir_perms /storage/PCAP/intel tjlam"
            )
            self.assertGreater(
                call_idx, mkdir_idx,
                f"{script_path.name}: calls harden_intel_dir_perms before the "
                "directory it hardens is created",
            )

    def test_set_dash_e_scripts_suffix_the_call_with_or_true(self):
        # stream_capture.sh is the only sibling with `set -euo pipefail` —
        # a hard failure in the (best-effort, self-heal) permission fix must
        # not abort capture startup under its own set -e. The other two
        # scripts have no set -e, so they don't need the suffix.
        for script_path in SIBLING_SCRIPTS:
            text = script_path.read_text(encoding="utf-8")
            has_set_e = any(line.startswith("set -e") for line in _lines(text))
            call_line = next(
                (line for line in _lines(text) if "harden_intel_dir_perms /storage/PCAP/intel tjlam" in line),
                None,
            )
            self.assertIsNotNone(call_line, f"{script_path.name}: missing the harden_intel_dir_perms call")
            if has_set_e:
                self.assertIn(
                    "|| true", call_line,
                    f"{script_path.name} has 'set -e' — its "
                    "harden_intel_dir_perms call must end in '|| true' so a "
                    "permission-fix failure can't abort capture startup",
                )
            else:
                self.assertNotIn(
                    "|| true", call_line,
                    f"{script_path.name} has no 'set -e' — the '|| true' "
                    "suffix isn't needed there and its presence would only "
                    "suggest (incorrectly) that this script has one",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
