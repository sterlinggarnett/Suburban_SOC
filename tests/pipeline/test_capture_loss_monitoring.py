#!/usr/bin/env python3
"""
#288: capture-loss/resource-guard monitoring for validate-certs' per-
connection OpenSSL cert-chain verification (#228), plus its related
finding: all 4 real Zeek capture invocations swallowed a failed
configs/intel/* -> /storage/PCAP/intel/ copy with `|| true` and no
verification the deployed config.zeek actually matches the repo.

Two things this checks, both static text/regex assertions against the real
files — no live Zeek/Elasticsearch, matching this directory's existing
convention (see test_mac_correlation.py's identical ZeekLoadOrderTests
shape):

  1. configs/intel/config.zeek loads policy/misc/capture-loss on the real
     capture path (the only config any real invocation passes to Zeek).
  2. Every real capture invocation that copies configs/intel/* into
     /storage/PCAP/intel/ before running Zeek verifies that copy actually
     landed a current config.zeek, rather than silently proceeding against
     a stale one if the cp failed.

Run:  python tests/pipeline/test_capture_loss_monitoring.py  (or: pytest tests/pipeline)
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG_ZEEK = (ROOT / "configs" / "intel" / "config.zeek").read_text(encoding="utf-8")
ZEEK_RUN_PCAP = (ROOT / "scripts" / "setup" / "zeek_run_pcap.sh").read_text(encoding="utf-8")
STREAM_CAPTURE = (ROOT / "scripts" / "setup" / "stream_capture.sh").read_text(encoding="utf-8")
ZEEK_CONNECT_HOST = (ROOT / "scripts" / "setup" / "zeek_connect_host.sh").read_text(encoding="utf-8")
ZEEK_HOST_CAPTURE_SERVICE = (
    ROOT / "configs" / "systemd" / "zeek-host-capture.service").read_text(encoding="utf-8")
SLO_METRICS = (ROOT / "scripts" / "setup" / "ai_agent" / "slo_metrics.py").read_text(encoding="utf-8")

# The 4 real capture invocations named in #288, as (label, source text) pairs —
# a list, not a dict, so a duplicate label can't silently shadow a prior entry.
REAL_CAPTURE_SOURCES = [
    ("zeek_run_pcap.sh", ZEEK_RUN_PCAP),
    ("stream_capture.sh", STREAM_CAPTURE),
    ("zeek_connect_host.sh", ZEEK_CONNECT_HOST),
    ("zeek-host-capture.service", ZEEK_HOST_CAPTURE_SERVICE),
]


class ZeekCaptureLossLoadTests(unittest.TestCase):
    def test_config_zeek_loads_capture_loss(self):
        # The real capture path (every script under scripts/setup/ and
        # zeek-host-capture.service passes config.zeek).
        self.assertIn("@load policy/misc/capture-loss", CONFIG_ZEEK)

    def test_capture_loss_load_comes_after_validate_certs(self):
        # Not load-bearing for Zeek itself (order between unrelated @loads
        # doesn't matter), but the canary-check tests below rely on
        # capture-loss being the NEWEST @load line — pin the ordering so a
        # future edit that reorders these doesn't silently invalidate that
        # assumption without a test noticing.
        certs_pos = CONFIG_ZEEK.index("@load policy/protocols/ssl/validate-certs")
        loss_pos = CONFIG_ZEEK.index("@load policy/misc/capture-loss")
        self.assertLess(certs_pos, loss_pos)


class DeployedConfigVerificationTests(unittest.TestCase):
    """#288's related finding: a silently-failed intel config copy left every
    real capture invocation running a stale config.zeek with no verification
    anything actually landed. Every source that does the copy must also
    verify it, and must actually fail (not just log) on a bad copy."""

    def test_every_real_capture_invocation_copies_the_intel_config(self):
        # Self-check on the fixture list itself: if a future capture
        # invocation stops copying configs/intel/* at all, the verification
        # check below has nothing to guard and this test should say so
        # rather than silently passing an empty scope.
        for label, text in REAL_CAPTURE_SOURCES:
            self.assertIn("configs/intel/", text, f"{label}: expected an intel config copy")

    def test_every_real_capture_invocation_verifies_the_copy(self):
        for label, text in REAL_CAPTURE_SOURCES:
            self.assertIn("policy/misc/capture-loss", text,
                          f"{label}: no post-copy verification for the deployed config.zeek — "
                          f"a silently-failed intel config copy would run Zeek against a stale "
                          f"config with nothing catching it")

    def test_shell_scripts_cp_does_not_follow_a_symlinked_config(self):
        # security-auditor review: the systemd unit already guards against
        # a tjlam-level actor planting a symlink at config.zeek's path
        # before this cp runs (--remove-destination + a symlink sweep) —
        # the 3 shell scripts had neither, which meant the NEW verification
        # check itself could be defeated by reading straight through a
        # symlink to attacker-controlled content that happens to contain
        # the canary string.
        for label, text in (("zeek_run_pcap.sh", ZEEK_RUN_PCAP),
                            ("stream_capture.sh", STREAM_CAPTURE),
                            ("zeek_connect_host.sh", ZEEK_CONNECT_HOST)):
            self.assertIn("--remove-destination", text, f"{label}: cp missing --remove-destination")
            self.assertIn("-L /storage/PCAP/intel/config.zeek", text,
                          f"{label}: missing a symlink guard for config.zeek")

    def test_shell_scripts_symlink_guard_runs_before_the_cp(self):
        for label, text in (("zeek_run_pcap.sh", ZEEK_RUN_PCAP),
                            ("stream_capture.sh", STREAM_CAPTURE),
                            ("zeek_connect_host.sh", ZEEK_CONNECT_HOST)):
            guard_pos = text.index("if [ -L /storage/PCAP/intel/config.zeek ]")
            # #270: the guard protects config.zeek specifically, so pin against
            # that cp precisely rather than either cp in the (now two-line) pair.
            cp_pos = text.index("sudo cp --remove-destination")
            self.assertLess(guard_pos, cp_pos, f"{label}: symlink guard must run before the cp")

    def test_shell_scripts_check_the_intel_directory_itself_for_symlinks(self):
        # security-auditor review (2nd pass, HIGH): checking config.zeek
        # alone is not enough — if /storage/PCAP/intel ITSELF is a symlink
        # (e.g. to /etc/sudoers.d), `sudo mkdir -p` and `cp -r` both follow
        # it silently, and the file-level -L check then resolves THROUGH
        # the directory symlink to whatever sits at the real target,
        # blind to the swap. Same CWE-59 class the systemd unit already
        # guards at the directory level (zeek-host-capture.service:85).
        for label, text in (("zeek_run_pcap.sh", ZEEK_RUN_PCAP),
                            ("stream_capture.sh", STREAM_CAPTURE),
                            ("zeek_connect_host.sh", ZEEK_CONNECT_HOST)):
            self.assertIn("[ -L /storage/PCAP/intel ]", text,
                          f"{label}: missing a symlink guard for the intel directory itself")

    def test_shell_scripts_directory_guard_runs_before_mkdir(self):
        for label, text in (("zeek_run_pcap.sh", ZEEK_RUN_PCAP),
                            ("stream_capture.sh", STREAM_CAPTURE),
                            ("zeek_connect_host.sh", ZEEK_CONNECT_HOST)):
            guard_pos = text.index("[ -L /storage/PCAP/intel ]")
            mkdir_pos = text.index("sudo mkdir -p /storage/PCAP/intel")
            self.assertLess(guard_pos, mkdir_pos,
                            f"{label}: directory symlink guard must run before mkdir -p, "
                            f"which silently follows an existing directory symlink instead "
                            f"of failing on one")

    def test_shell_scripts_verification_grep_matches_the_copy_privilege(self):
        # security-auditor review: the cp runs under sudo but the original
        # verification grep did not, with its stderr suppressed
        # (`2>/dev/null`) — a real permission problem and a genuinely stale
        # file produced the identical FATAL message, misleading whoever
        # debugs it. sudo grep (no suppression needed) matches the cp's own
        # privilege and lets a real error surface distinctly.
        for label, text in (("zeek_run_pcap.sh", ZEEK_RUN_PCAP),
                            ("stream_capture.sh", STREAM_CAPTURE),
                            ("zeek_connect_host.sh", ZEEK_CONNECT_HOST)):
            self.assertIn('sudo grep -q "policy/misc/capture-loss"', text,
                          f"{label}: verification grep should run with sudo, matching the cp above")

    def test_every_real_capture_invocation_fails_loudly_on_a_bad_copy(self):
        # security-auditor review: a bare `exit 1` search anywhere in the
        # file would pass even if the capture-loss check itself never
        # exited non-zero (e.g. another, unrelated exit 1 elsewhere) — tie
        # the exit to the check's own block specifically, not just to the
        # file mentioning both somewhere.
        for label, text in REAL_CAPTURE_SOURCES:
            self.assertRegex(
                text, r"policy/misc/capture-loss[\s\S]{0,400}?exit 1",
                f"{label}: verification check exists but doesn't actually exit non-zero "
                f"on failure")

    def test_shell_scripts_check_before_starting_zeek(self):
        # The verification must run BEFORE the `docker run ... zeek` line,
        # not after — checking post-hoc would still let a stale-config Zeek
        # process start.
        for label, text in (("zeek_run_pcap.sh", ZEEK_RUN_PCAP),
                            ("stream_capture.sh", STREAM_CAPTURE),
                            ("zeek_connect_host.sh", ZEEK_CONNECT_HOST)):
            check_pos = text.index("policy/misc/capture-loss")
            docker_positions = [m.start() for m in re.finditer(r"docker run", text)]
            self.assertTrue(docker_positions, f"{label}: expected at least one docker run")
            self.assertTrue(all(check_pos < p for p in docker_positions),
                            f"{label}: verification check must precede every docker run")

    def test_systemd_check_runs_in_execstartpre_not_execstart(self):
        # ExecStartPre failing blocks ExecStart entirely (systemd default) —
        # the loud failure this finding asked for. If the check were only in
        # ExecStart, Zeek would already be starting by the time it ran.
        execstartpre_pos = ZEEK_HOST_CAPTURE_SERVICE.index("ExecStartPre=/bin/bash -c 'set -e; cp --remove-destination")
        check_pos = ZEEK_HOST_CAPTURE_SERVICE.index("policy/misc/capture-loss")
        execstart_pos = ZEEK_HOST_CAPTURE_SERVICE.index("\nExecStart=")
        self.assertLess(execstartpre_pos, check_pos)
        self.assertLess(check_pos, execstart_pos)

    def test_systemd_check_survives_under_set_dash_e(self):
        # security-auditor review: appending the capture-loss check made it
        # the LAST command in the bash -c string, and bash -c reports only
        # the last command's own exit status — a real failure in the
        # PRE-EXISTING intel.dat fallback (`[ -s ... ] || cp ...`) just
        # above it would have been silently swallowed instead of blocking
        # ExecStart the way #222 originally guaranteed. set -e at the front
        # of the string is what restores that; assert it is actually there,
        # not just that the capture-loss check itself exits non-zero.
        match = re.search(r"ExecStartPre=/bin/bash -c '(set -e;.*capture-loss.*)'\n",
                          ZEEK_HOST_CAPTURE_SERVICE)
        self.assertIsNotNone(match, "expected the capture-loss ExecStartPre line to start with set -e;")

    def test_systemd_bash_c_strings_have_no_unescaped_single_quote(self):
        # Every ExecStartPre=.../bin/bash -c '...' command is wrapped in a
        # single-quoted string — a literal apostrophe/single-quote anywhere
        # inside ANY of them would prematurely close that string and
        # corrupt the unit file (the same class of footgun this repo
        # already hit once with Logstash's single-quoted ruby code blocks —
        # see test_framework_enrichment.py's identical-shaped guard).
        # security-auditor review: re.search only finds the FIRST match —
        # this file has 3 separate ExecStartPre=.../bin/bash -c '...' lines
        # (one pre-existing at the symlink-sweep step, the #288 one this
        # fix added, and a dash-prefixed "ExecStartPre=-..." one at the
        # chown/chmod step) and a bug in the #288 line specifically would
        # have passed a single-match check silently. -? covers the
        # dash-prefixed form too.
        matches = re.findall(r"ExecStartPre=-?/bin/bash -c '(.*)'\n", ZEEK_HOST_CAPTURE_SERVICE)
        self.assertGreaterEqual(len(matches), 3,
                                f"expected at least 3 bash -c ExecStartPre lines, found {len(matches)}")
        for m in matches:
            self.assertNotIn("'", m)


class SloMetricsCaptureLossTests(unittest.TestCase):
    """Static checks that the SLO metric is actually wired up — the
    functional behavior (aggregation query, error handling) is covered by
    tests/ai_agent/test_slo_metrics.py; this just confirms the field/dataset
    names this metric depends on match what config.zeek/logstash.conf
    actually produce."""

    def test_metric_queries_the_capture_loss_dataset(self):
        self.assertIn('"event.dataset": "zeek.capture_loss"', SLO_METRICS)

    def test_metric_aggregates_percent_lost(self):
        # percent_lost is Zeek's own capture_loss.log field name (not
        # renamed by configs/logstash.conf, which has no capture_loss-
        # specific block) — must match exactly or the aggregation silently
        # returns no value against a field that doesn't exist.
        self.assertIn('"field": "percent_lost"', SLO_METRICS)

    def test_metric_is_registered_in_main(self):
        # A metric function that exists but isn't added to main()'s
        # metric_fns dict silently never runs — the exact bug shape
        # #216/#252/#263's tests already guard other metrics against.
        self.assertIn('"capture_loss_max_pct": metric_capture_loss_percent,', SLO_METRICS)


if __name__ == "__main__":
    unittest.main()
