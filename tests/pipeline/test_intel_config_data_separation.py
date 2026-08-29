#!/usr/bin/env python3
"""
#270 (finding 1): separate intel-refresh.service's DATA (intel.dat,
regenerated every run) from CODE (config.zeek, executed as root Zeek policy
on the capture host; refresh_intel.sh itself) inside configs/intel/.

Before this fix, intel-refresh.service's ReadWritePaths sandbox grant
covered the whole configs/intel/ directory — config.zeek included. A
compromise of that sandboxed, unprivileged process via any vector OTHER
than feed content (already fully IPv4/bogon-sanitized before it reaches any
sink) would have had write access to a file that gets executed as root
Zeek policy inside a container with real capture data mounted, once
zeek-host-capture.service's own cp propagated it on the next restart.

Fix: intel.dat now lives in its own configs/intel/data/ subdirectory.
refresh_intel.sh writes there; intel-refresh.service's ReadWritePaths is
scoped to only that subdirectory (config.zeek/refresh_intel.sh/
intel.seed.dat stay read-only to it via ProtectHome=read-only, no explicit
grant needed); the 4 real capture invocations (zeek-host-capture.service
and its 3 manual-script siblings) each copy config.zeek and intel.dat
separately instead of one blanket `cp -r configs/intel/*`, since that
wildcard would otherwise silently stop picking up intel.dat at all once it
moved out of configs/intel/ directly.

Static text/regex assertions against the real files, same convention as
this directory's other Zeek-capture-path checks (see
test_capture_loss_monitoring.py, test_intel_dir_perms_hardening.py) — no
live systemd/Docker needed.

Run:  python tests/pipeline/test_intel_config_data_separation.py  (or: pytest tests/pipeline)
"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REFRESH_INTEL_SH = (ROOT / "configs" / "intel" / "refresh_intel.sh").read_text(encoding="utf-8")
INTEL_REFRESH_SERVICE = (ROOT / "configs" / "systemd" / "intel-refresh.service").read_text(encoding="utf-8")
ZEEK_HOST_CAPTURE_SERVICE = (
    ROOT / "configs" / "systemd" / "zeek-host-capture.service").read_text(encoding="utf-8")
GITIGNORE = (ROOT / ".gitignore").read_text(encoding="utf-8")
SIBLING_SCRIPTS = [
    ROOT / "scripts" / "setup" / "stream_capture.sh",
    ROOT / "scripts" / "setup" / "zeek_connect_host.sh",
    ROOT / "scripts" / "setup" / "zeek_run_pcap.sh",
]


class RefreshIntelWritesToDataSubdirTests(unittest.TestCase):
    def test_out_points_at_data_subdirectory(self):
        self.assertIn('DATA_DIR="$HERE/data"', REFRESH_INTEL_SH)
        self.assertIn('OUT="$DATA_DIR/intel.dat"', REFRESH_INTEL_SH)
        self.assertNotIn('OUT="$HERE/intel.dat"', REFRESH_INTEL_SH,
                          "OUT still points directly at configs/intel/ — the "
                          "code/data split this test guards was reverted")

    def test_seed_stays_outside_the_data_subdirectory(self):
        # intel.seed.dat is curated, deterministic, git-tracked code-adjacent
        # data (never written by this script) — it must stay a sibling of
        # config.zeek, not move into data/ alongside the regenerated output.
        self.assertIn('SEED="$HERE/intel.seed.dat"', REFRESH_INTEL_SH)

    def test_atomic_write_temp_file_shares_the_data_subdirectory(self):
        # The atomic write (build under a temp name, then mv onto $OUT) only
        # stays atomic if the temp file is on the same filesystem/directory
        # as $OUT — see the script's own comment on this. A temp file left
        # under $HERE (now just the code directory) instead of $DATA_DIR
        # would still work but silently reopen the non-atomic-write risk if
        # $HERE and $DATA_DIR were ever on different filesystems.
        self.assertIn('mktemp -p "$DATA_DIR"', REFRESH_INTEL_SH)


class IntelRefreshServiceReadWritePathsTests(unittest.TestCase):
    def test_read_write_paths_scoped_to_data_subdirectory_not_parent(self):
        self.assertIn(
            "ReadWritePaths=/home/tjlam/projects/Suburban-SOC/configs/intel/data",
            INTEL_REFRESH_SERVICE,
        )
        self.assertNotIn(
            "ReadWritePaths=/home/tjlam/projects/Suburban-SOC/configs/intel\n",
            INTEL_REFRESH_SERVICE,
            "ReadWritePaths still grants write access to the whole "
            "configs/intel/ directory, including config.zeek — the #270 "
            "narrowing this test guards was reverted",
        )

    def test_live_dir_sync_path_unaffected(self):
        # The separate /storage/PCAP/intel sync (best-effort, "-" prefixed)
        # is a different mechanism entirely (refresh_intel.sh's own LIVE_DIR
        # logic writing straight to the runtime capture directory) and is
        # out of scope for the code/data split — must still be present.
        self.assertIn("ReadWritePaths=-/storage/PCAP/intel", INTEL_REFRESH_SERVICE)


class RealCaptureInvocationsCopyConfigAndDataSeparatelyTests(unittest.TestCase):
    """All 4 real capture invocations must copy config.zeek and intel.dat as
    two explicit, separate copies now that intel.dat lives in
    configs/intel/data/ — a blanket `cp -r configs/intel/*` would silently
    stop picking up intel.dat at all."""

    def _intel_sync_execstartpre(self) -> str:
        for line in ZEEK_HOST_CAPTURE_SERVICE.splitlines():
            if line.startswith("ExecStartPre=") and "config.zeek" in line and "intel.seed.dat" in line:
                return line
        raise AssertionError("could not find the intel-sync ExecStartPre line")

    def test_systemd_unit_no_longer_does_a_blanket_wildcard_copy(self):
        line = self._intel_sync_execstartpre()
        self.assertNotIn(
            "configs/intel/*", line,
            "zeek-host-capture.service still does a blanket 'cp -r "
            "configs/intel/*' — this would silently stop picking up "
            "intel.dat now that it lives in configs/intel/data/ instead",
        )

    def test_systemd_unit_copies_config_zeek_and_data_intel_dat_separately(self):
        line = self._intel_sync_execstartpre()
        self.assertIn("${SOC_REPO}/configs/intel/config.zeek /storage/PCAP/intel/config.zeek", line)
        self.assertIn("${SOC_REPO}/configs/intel/data/intel.dat /storage/PCAP/intel/intel.dat", line)

    def test_sibling_scripts_no_longer_do_a_blanket_wildcard_copy(self):
        for script_path in SIBLING_SCRIPTS:
            text = script_path.read_text(encoding="utf-8")
            self.assertNotIn(
                'configs/intel/"*', text,
                f"{script_path.name}: still does a blanket 'cp -r "
                f"configs/intel/*' — this would silently stop picking up "
                f"intel.dat now that it lives in configs/intel/data/ instead",
            )

    def test_sibling_scripts_copy_config_zeek_and_data_intel_dat_separately(self):
        for script_path in SIBLING_SCRIPTS:
            text = script_path.read_text(encoding="utf-8")
            self.assertIn(
                'configs/intel/config.zeek" /storage/PCAP/intel/config.zeek', text,
                f"{script_path.name}: missing an explicit config.zeek copy",
            )
            self.assertIn(
                'configs/intel/data/intel.dat" /storage/PCAP/intel/intel.dat', text,
                f"{script_path.name}: missing an explicit copy of "
                f"configs/intel/data/intel.dat",
            )

    def test_sibling_scripts_config_zeek_copy_runs_after_its_symlink_guard(self):
        for script_path in SIBLING_SCRIPTS:
            text = script_path.read_text(encoding="utf-8")
            guard_pos = text.index("if [ -L /storage/PCAP/intel/config.zeek ]")
            copy_pos = text.index('configs/intel/config.zeek" /storage/PCAP/intel/config.zeek')
            self.assertLess(guard_pos, copy_pos,
                             f"{script_path.name}: config.zeek copy must run "
                             f"after its own symlink guard")


class GitignoreAndDataDirTests(unittest.TestCase):
    def test_gitignore_ignores_the_new_data_path(self):
        self.assertIn("configs/intel/data/intel.dat", GITIGNORE)
        self.assertNotRegex(
            GITIGNORE, r"(?m)^configs/intel/intel\.dat$",
            "old .gitignore entry for the pre-#270 intel.dat path should be "
            "replaced, not left alongside the new one",
        )

    def test_data_directory_exists_in_a_fresh_checkout(self):
        # A .gitkeep so `configs/intel/data/` (otherwise empty pre-refresh)
        # survives a fresh clone rather than only appearing after the first
        # run — refresh_intel.sh's own `mkdir -p` also creates it at
        # runtime, but a tracked directory means intel-refresh.service's
        # narrowed ReadWritePaths grant has a real path to point at from the
        # very first install, not just after the first successful run.
        self.assertTrue((ROOT / "configs" / "intel" / "data" / ".gitkeep").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
