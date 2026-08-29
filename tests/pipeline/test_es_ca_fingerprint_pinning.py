#!/usr/bin/env python3
"""
#270 (finding 2): trust-on-first-use (TOFU) pinning for the Elasticsearch CA
cert intel-refresh.service and slo-metrics.service both re-extract from the
`elasticsearch` container on every run, previously with no verification at
all — whatever sat at that container path each run silently became the sole
trust anchor for a request carrying an ES credential.

scripts/setup/verify_ca_fingerprint.sh pins the fingerprint seen on the
FIRST run a host makes (persisted under the caller's own StateDirectory=,
not RuntimeDirectory=, which is torn down between every Type=oneshot run)
and hard-fails + deletes the cert on any later mismatch. A repo-committed
static pin (the issue's own literal suggestion) isn't possible here — this
repo has no access to any real deployment's actual generated CA, and a
fabricated placeholder value would be worse than no check at all.

Two kinds of checks:
  1. Static text/regex assertions against the real systemd units, same
     convention as this directory's other checks (see
     test_intel_dir_perms_hardening.py) — no live systemd/Docker needed.
  2. A functional test that actually RUNS the script (via bash + openssl,
     both assumed present the way test_live_fire.py assumes sigma-cli) end
     to end against real self-signed certs — a purely static check can't
     catch a logic bug in the TOFU compare/persist/delete behavior itself.

Also covers a real bug the round-1 security review found in this same
change: refresh_intel.sh SOURCES scripts/setup/lib/es_common.sh (not a
subshell), and es_common.sh does its own hard `exit 1` when ES_CA is
missing/unreadable — appropriate for es_common.sh's other, ES-only callers,
but sourcing it directly means that exit unwinds refresh_intel.sh's WHOLE
PROCESS too. Before this change, ES_CA could only go missing via a rare
docker-cp extraction failure; verify_ca_fingerprint.sh's TOFU check now
DELETES ca.crt on every legitimate CA rotation (an expected, documented
case), which would otherwise turn every rotation into refresh_intel.sh
exiting 1 — and intel-refresh.service's SuccessExitStatus=0 2 does not cover
1, so systemd would report the whole unit FAILED over what is supposed to
be a "skip indexing only" case. Fixed by checking ES_CA usability in
refresh_intel.sh's own gate BEFORE ever sourcing es_common.sh.
TofuMismatchDoesNotCrashRefreshScriptTests below reproduces this exact
mechanism with a stand-in es_common.sh (no real ES/network needed) and
confirms it no longer fires.

Run:  python tests/pipeline/test_es_ca_fingerprint_pinning.py  (or: pytest tests/pipeline)
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "setup" / "verify_ca_fingerprint.sh"
REFRESH_INTEL_SH = ROOT / "configs" / "intel" / "refresh_intel.sh"
INTEL_REFRESH_SERVICE = (ROOT / "configs" / "systemd" / "intel-refresh.service").read_text(encoding="utf-8")
SLO_METRICS_SERVICE = (ROOT / "configs" / "systemd" / "slo-metrics.service").read_text(encoding="utf-8")


def _lines(text: str) -> list:
    return text.splitlines()


class ScriptExistsTests(unittest.TestCase):
    def test_script_exists(self):
        self.assertTrue(SCRIPT.is_file(), f"expected {SCRIPT} to exist")


class IntelRefreshServiceWiringTests(unittest.TestCase):
    def test_state_directory_present(self):
        self.assertIn("StateDirectory=suburban-soc-intel", INTEL_REFRESH_SERVICE)

    def test_verify_step_present_and_best_effort(self):
        lines = _lines(INTEL_REFRESH_SERVICE)
        verify_line = next((line for line in lines if line.startswith("ExecStartPre=") and "verify_ca_fingerprint.sh" in line), None)
        self.assertIsNotNone(verify_line, "no ExecStartPre calling verify_ca_fingerprint.sh")
        self.assertTrue(
            verify_line.startswith("ExecStartPre=-"),
            "intel-refresh.service's verify step should be '-'-prefixed "
            "(best-effort) — this unit already runs fine with no ES_CA at "
            "all, so a CA trust failure must not take down the primary "
            "intel.dat refresh over a credential-only concern",
        )

    def test_verify_step_runs_after_the_docker_cp_extraction(self):
        lines = _lines(INTEL_REFRESH_SERVICE)
        cp_idx = next((i for i, line in enumerate(lines) if line.strip().startswith("ExecStartPre=") and "docker cp elasticsearch" in line), None)
        verify_idx = next((i for i, line in enumerate(lines) if line.startswith("ExecStartPre=") and "verify_ca_fingerprint.sh" in line), None)
        self.assertIsNotNone(cp_idx)
        self.assertIsNotNone(verify_idx)
        self.assertLess(cp_idx, verify_idx, "verify step must run after the docker cp that extracts ca.crt")

    def test_verify_step_points_at_the_extracted_ca_and_a_state_directory_pin(self):
        verify_line = next(line for line in _lines(INTEL_REFRESH_SERVICE) if line.startswith("ExecStartPre=") and "verify_ca_fingerprint.sh" in line)
        self.assertIn("/run/suburban-soc-intel/ca.crt", verify_line)
        self.assertIn("/var/lib/suburban-soc-intel/", verify_line,
                      "pin file should live under StateDirectory= (/var/lib/...), "
                      "not RuntimeDirectory= (/run/...), so it survives across runs")


class SloMetricsServiceWiringTests(unittest.TestCase):
    def test_state_directory_present(self):
        self.assertIn("StateDirectory=suburban-soc-slo", SLO_METRICS_SERVICE)

    def test_verify_step_present_and_hard_failing(self):
        lines = _lines(SLO_METRICS_SERVICE)
        verify_line = next((line for line in lines if line.startswith("ExecStartPre=") and "verify_ca_fingerprint.sh" in line), None)
        self.assertIsNotNone(verify_line, "no ExecStartPre calling verify_ca_fingerprint.sh")
        self.assertFalse(
            verify_line.startswith("ExecStartPre=-"),
            "slo-metrics.service's verify step must NOT be '-'-prefixed — "
            "this unit's sole purpose is indexing into ES (its own docker cp "
            "extraction step is also not '-'-prefixed), so there is no "
            "degraded-but-useful mode to preserve if the CA can't be trusted",
        )

    def test_verify_step_runs_after_the_docker_cp_extraction(self):
        lines = _lines(SLO_METRICS_SERVICE)
        cp_idx = next((i for i, line in enumerate(lines) if line.strip().startswith("ExecStartPre=") and "docker cp elasticsearch" in line), None)
        verify_idx = next((i for i, line in enumerate(lines) if line.startswith("ExecStartPre=") and "verify_ca_fingerprint.sh" in line), None)
        self.assertIsNotNone(cp_idx)
        self.assertIsNotNone(verify_idx)
        self.assertLess(cp_idx, verify_idx, "verify step must run after the docker cp that extracts ca.crt")

    def test_verify_step_points_at_the_extracted_ca_and_a_state_directory_pin(self):
        verify_line = next(line for line in _lines(SLO_METRICS_SERVICE) if line.startswith("ExecStartPre=") and "verify_ca_fingerprint.sh" in line)
        self.assertIn("/run/suburban-soc-slo/ca.crt", verify_line)
        self.assertIn("/var/lib/suburban-soc-slo/", verify_line,
                      "pin file should live under StateDirectory= (/var/lib/...), "
                      "not RuntimeDirectory= (/run/...), so it survives across runs")


@unittest.skipUnless(shutil.which("openssl") and shutil.which("bash"), "openssl/bash not available")
class TofuBehaviorFunctionalTests(unittest.TestCase):
    """Actually runs verify_ca_fingerprint.sh against real self-signed certs —
    a static text check can't catch a logic bug in the TOFU compare/persist/
    delete behavior itself."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ca_path = str(Path(self.tmp) / "ca.crt")
        self.pin_path = str(Path(self.tmp) / "pin.sha256")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, ca_path=None, pin_path=None):
        return subprocess.run(
            ["bash", str(SCRIPT), ca_path or self.ca_path, pin_path or self.pin_path],
            capture_output=True, text=True, timeout=30,
        )

    def _make_cert(self, path, cn):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "/dev/null",
             "-out", path, "-days", "1", "-nodes", "-subj", f"/CN={cn}"],
            capture_output=True, text=True, timeout=30, check=True,
        )

    def test_missing_ca_is_a_no_op_success(self):
        result = self._run(ca_path=str(Path(self.tmp) / "nope.crt"))
        self.assertEqual(0, result.returncode)

    def test_first_run_learns_and_persists_the_pin(self):
        self._make_cert(self.ca_path, "CA-A")
        result = self._run()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(Path(self.pin_path).is_file())
        pinned = Path(self.pin_path).read_text().strip()
        self.assertRegex(pinned, r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")

    def test_matching_fingerprint_on_a_later_run_succeeds(self):
        self._make_cert(self.ca_path, "CA-A")
        self._run()  # learn
        result = self._run()  # verify against the now-persisted pin
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(Path(self.ca_path).is_file(), "cert must survive a matching run")

    def test_mismatched_fingerprint_fails_and_deletes_the_cert(self):
        self._make_cert(self.ca_path, "CA-A")
        self._run()  # learn pin from CA-A
        self._make_cert(self.ca_path, "CA-B")  # swap in a different cert
        result = self._run()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("FATAL", result.stderr)
        self.assertFalse(Path(self.ca_path).exists(),
                          "a mismatched cert must be deleted, not left in place "
                          "for a later step to trust")

    def test_deleting_the_pin_re_arms_tofu_for_a_new_cert(self):
        self._make_cert(self.ca_path, "CA-A")
        self._run()  # learn pin from CA-A
        self._make_cert(self.ca_path, "CA-B")
        Path(self.pin_path).unlink()  # operator-deliberate re-pin
        result = self._run()
        self.assertEqual(0, result.returncode, result.stderr)
        pinned = Path(self.pin_path).read_text().strip()
        # Learned the NEW cert's fingerprint, not still holding CA-A's.
        cert_fp = subprocess.run(
            ["openssl", "x509", "-in", self.ca_path, "-noout", "-fingerprint", "-sha256"],
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout.strip().split("=", 1)[1]
        self.assertEqual(cert_fp, pinned)


@unittest.skipUnless(shutil.which("bash"), "bash not available")
class TofuMismatchDoesNotCrashRefreshScriptTests(unittest.TestCase):
    """Reproduces the exact round-1-security-review bug this diff fixes:
    refresh_intel.sh SOURCES scripts/setup/lib/es_common.sh (not a subshell),
    and es_common.sh does its own `exit 1` when ES_CA is unreadable —
    appropriate for es_common.sh's other, ES-only callers, but sourcing it
    directly means that exit unwinds refresh_intel.sh's WHOLE PROCESS too.
    A TOFU-mismatch-deleted ca.crt would otherwise turn every legitimate CA
    rotation into refresh_intel.sh exiting 1, which intel-refresh.service's
    SuccessExitStatus=0 2 does not cover — systemd would report the whole
    unit FAILED over what is supposed to be a "skip indexing only" case.

    Builds a minimal repo skeleton (real refresh_intel.sh, a real
    intel.seed.dat, and a STAND-IN es_common.sh that unconditionally exits 1
    and leaves a marker file if sourced — reproducing es_common.sh's actual
    failure mode without needing real ES or network access) and runs the
    real script against it with ES_CA pointing at a nonexistent file (the
    exact post-TOFU-mismatch state) — no live ES/Docker/network needed."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "configs" / "intel").mkdir(parents=True)
        (self.tmp / "scripts" / "setup" / "lib").mkdir(parents=True)
        real_script = REFRESH_INTEL_SH.read_text(encoding="utf-8")
        (self.tmp / "configs" / "intel" / "refresh_intel.sh").write_text(real_script, encoding="utf-8")
        (self.tmp / "configs" / "intel" / "intel.seed.dat").write_text(
            "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\n"
            "198.51.100.66\tIntel::ADDR\ttest\ttest indicator\n",
            encoding="utf-8",
        )
        self.marker = self.tmp / "es_common_was_sourced"
        (self.tmp / "scripts" / "setup" / "lib" / "es_common.sh").write_text(
            f'touch "{self.marker}"\n'
            'echo "ERROR: no readable CA -- refusing to skip TLS verification." >&2\n'
            "exit 1\n",
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, es_pass, es_ca):
        env = {
            "PATH": "/usr/bin:/bin",
            "ES_PASS": es_pass,
            "ES_CA": es_ca,
            # Fails fast (connection refused), no real network dependency —
            # the fetches themselves are irrelevant to this bug.
            "FEODO_URL": "http://127.0.0.1:1/",
            "ET_COMPROMISED_URL": "http://127.0.0.1:1/",
        }
        return subprocess.run(
            ["bash", str(self.tmp / "configs" / "intel" / "refresh_intel.sh")],
            capture_output=True, text=True, timeout=30, env=env,
        )

    def test_unreadable_ca_skips_indexing_without_crashing_the_whole_script(self):
        # The post-TOFU-mismatch state: ES_PASS is set (indexing was
        # intended) but ES_CA points at nothing readable.
        result = self._run(es_pass="fake-password", es_ca=str(self.tmp / "does-not-exist.crt"))
        self.assertFalse(self.marker.exists(),
                          "es_common.sh was sourced despite an unreadable ES_CA -- "
                          "its own hard exit 1 would crash this whole script")
        self.assertEqual(2, result.returncode,
                          f"expected exit 2 (stale-but-successful, matching "
                          f"SuccessExitStatus=0 2), got {result.returncode}. "
                          f"stderr: {result.stderr}")
        self.assertIn("ES_CA", result.stdout)

    def test_es_pass_unset_still_skips_cleanly(self):
        # Unrelated pre-existing path — confirms the fix didn't disturb the
        # ES_PASS-unset case, which is a deliberate no-ES choice, not a
        # degraded one (no status=stale expected here).
        result = self._run(es_pass="", es_ca=str(self.tmp / "does-not-exist.crt"))
        self.assertFalse(self.marker.exists())
        self.assertIn("ES_PASS unset", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
