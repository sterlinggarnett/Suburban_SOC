#!/usr/bin/env python3
"""
#550 — slo-metrics.service must not die when the Docker CLI is unavailable.

`/usr/bin/docker` on the WSL capture host is a symlink into the docker-desktop
distro and dangles whenever Docker Desktop is stopped. slo-metrics.service was
the only one of the four ES-CA-extracting units whose `docker cp` ExecStartPre
was NOT "-"-prefixed, so that dangling symlink failed at the systemd exec layer
(203/EXEC) and killed the unit before ExecStart. Because this unit is the one
that computes metric_zeek_ingest_lag_seconds(), a single Docker Desktop outage
took down the capture lane and the monitoring that watches the capture lane at
the same time — the 2026-08-31 -> 09-05 Zeek blackout produced no alert at all.

Two kinds of checks, same convention as test_es_ca_fingerprint_pinning.py:

  1. Static assertions against the real systemd units — no live systemd or
     Docker needed. These are the regression guard: the whole defect was one
     missing character in one directive, and nothing would have caught it.
  2. Functional tests that actually RUN scripts/setup/es_ca_cache.sh against
     real self-signed certs, because a text check cannot catch a logic bug in
     the restore/save behaviour itself — in particular the two refusals that
     keep the cache from becoming a way to launder an unverified trust anchor.

Note on why the cache exists at all: "-"-prefixing the cp alone is not enough.
RuntimeDirectory= is torn down between every Type=oneshot run, so a cp that
no-ops leaves no ca.crt, and `requests` then reports a TLS *CA bundle* error
for every metric — telling the operator the certificate is missing when the
actual fact is that Elasticsearch is down. The cached copy makes the degraded
run report the true reason.

Run:  python tests/pipeline/test_slo_metrics_docker_independence.py
      (or: pytest tests/pipeline)
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CACHE_SCRIPT = ROOT / "scripts" / "setup" / "es_ca_cache.sh"
VERIFY_SCRIPT = ROOT / "scripts" / "setup" / "verify_ca_fingerprint.sh"
SLO_METRICS_SERVICE = (ROOT / "configs" / "systemd" / "slo-metrics.service").read_text(encoding="utf-8")

# Every unit that extracts the ES CA out of the `elasticsearch` container the
# same way. All four must degrade rather than die when the Docker CLI is gone.
CA_EXTRACTING_UNITS = [
    "slo-metrics.service",
    "intel-refresh.service",
    "checkpoints-compact.service",
    "threat-intel-compact.service",
]


def _lines(text):
    return text.splitlines()


def _exec_pre_lines(text):
    return [ln for ln in _lines(text) if ln.startswith("ExecStartPre=")]


def _index_of(text, needle):
    """Index of the first ExecStartPre directive containing `needle`, or None.
    Comments are excluded deliberately — several of them name these scripts."""
    for i, ln in enumerate(_lines(text)):
        if ln.startswith("ExecStartPre=") and needle in ln:
            return i
    return None


def _success_exit_statuses(text):
    """Exit codes the unit is configured to treat as a successful start.
    systemd applies these to ExecStartPre control processes too, not only the
    main process — confirmed empirically on the capture host."""
    out = set()
    for ln in _lines(text):
        if ln.startswith("SuccessExitStatus="):
            for tok in ln.split("=", 1)[1].split():
                if tok.isdigit():
                    out.add(int(tok))
    return out


class ScriptExistsTests(unittest.TestCase):
    def test_cache_script_exists(self):
        self.assertTrue(CACHE_SCRIPT.is_file(), f"expected {CACHE_SCRIPT} to exist")


class DockerCpIsBestEffortEverywhereTests(unittest.TestCase):
    """The actual #550 regression guard, applied to the whole unit family."""

    def test_every_ca_extracting_unit_has_a_best_effort_docker_cp(self):
        for unit in CA_EXTRACTING_UNITS:
            with self.subTest(unit=unit):
                text = (ROOT / "configs" / "systemd" / unit).read_text(encoding="utf-8")
                cp = next((ln for ln in _exec_pre_lines(text) if "docker cp elasticsearch" in ln), None)
                self.assertIsNotNone(cp, f"{unit}: no ExecStartPre extracting the ES CA")
                self.assertTrue(
                    cp.startswith("ExecStartPre=-"),
                    f"{unit}: the ES-CA `docker cp` must be '-'-prefixed. /usr/bin/docker "
                    "is a Docker Desktop symlink that dangles when the engine is stopped; "
                    "without the prefix systemd fails the whole unit with 203/EXEC before "
                    "ExecStart runs (#550).",
                )

    def test_no_unprefixed_docker_invocation_survives_in_slo_metrics(self):
        """slo-metrics is the monitoring lane — nothing Docker-shaped in its
        start path may be able to fail it, or the monitor shares a single
        point of failure with the sensors it watches."""
        offenders = [ln for ln in _exec_pre_lines(SLO_METRICS_SERVICE)
                     if "/usr/bin/docker" in ln and not ln.startswith("ExecStartPre=-")]
        self.assertEqual([], offenders, f"unprefixed docker ExecStartPre in slo-metrics.service: {offenders}")


class DockerCallIsTimeBoundedTests(unittest.TestCase):
    """`-` suppresses a FAILED exit status and does nothing for a cp that
    BLOCKS — the Docker Desktop half-up state (socket present, daemon not
    answering). A blocked cp eats the start job's timeout and gets the unit
    killed: no ExecStart, no alert, the same net effect as the 203/EXEC #550
    removed (security-auditor, MEDIUM)."""

    def test_docker_cp_is_wrapped_in_a_timeout(self):
        cp = next(ln for ln in _exec_pre_lines(SLO_METRICS_SERVICE) if "docker cp elasticsearch" in ln)
        self.assertIn("/usr/bin/timeout", cp,
                      "the ES-CA `docker cp` must be time-bounded, not just '-'-prefixed")
        self.assertLess(cp.index("/usr/bin/timeout"), cp.index("/usr/bin/docker"),
                        "timeout must wrap docker, not the other way round")

    def test_unit_bounds_its_own_start_job(self):
        self.assertIn("TimeoutStartSec=", SLO_METRICS_SERVICE,
                      "without an explicit TimeoutStartSec= the whole start path "
                      "inherits DefaultTimeoutStartSec; the sibling intel-refresh.service "
                      "sets its own for the same reason")


class TrustGateCannotReturnAForgivenStatusTests(unittest.TestCase):
    """`SuccessExitStatus=0 2` covers ExecStartPre control processes, and
    `bash` exits 2 on a script syntax error — so a truncated or corrupted
    verify_ca_fingerprint.sh would fail OPEN, letting the unit proceed with an
    unverified ca.crt. The wrapper normalises every non-zero status to 1."""

    def test_verify_step_normalises_its_exit_status(self):
        verify = next(ln for ln in _exec_pre_lines(SLO_METRICS_SERVICE)
                      if "verify_ca_fingerprint.sh" in ln)
        self.assertIn("|| exit 1", verify,
                      "the trust gate must not be able to return a status listed in "
                      "SuccessExitStatus=; wrap it so every failure becomes 1")
        self.assertNotIn(1, _success_exit_statuses(SLO_METRICS_SERVICE),
                         "the normalised failure status is itself forgiven — pick another")


class RemoveIpcTests(unittest.TestCase):
    def test_remove_ipc_is_not_set_on_an_interactive_login_account(self):
        """`RemoveIPC=` tears down every SysV/POSIX IPC object owned by the
        unit's UID when the unit stops. User=tjlam is the interactive login
        account and this is a Type=oneshot on a 15-minute timer — 96 teardowns
        a day against the operator's own desktop session. intel-refresh.service
        reached this conclusion first and names slo-metrics.service while doing
        so; the decision was simply never applied here."""
        offenders = [ln for ln in _lines(SLO_METRICS_SERVICE)
                     if ln.startswith("RemoveIPC=") and "true" in ln]
        self.assertEqual([], offenders, f"RemoveIPC set in slo-metrics.service: {offenders}")


class SloMetricsCaCacheWiringTests(unittest.TestCase):
    def test_state_directory_is_not_world_traversable(self):
        self.assertIn("StateDirectoryMode=0700", SLO_METRICS_SERVICE,
                      "StateDirectory= now holds the cached CA itself, not just its "
                      "fingerprint pin — a trust anchor should not sit in a 0755 directory")

    def test_restore_and_save_steps_are_wired(self):
        restore = _index_of(SLO_METRICS_SERVICE, "es_ca_cache.sh restore")
        save = _index_of(SLO_METRICS_SERVICE, "es_ca_cache.sh save")
        self.assertIsNotNone(restore, "no ExecStartPre calling es_ca_cache.sh restore")
        self.assertIsNotNone(save, "no ExecStartPre calling es_ca_cache.sh save")

    def test_restore_verifies_before_use_and_save_only_caches_verified_certs(self):
        """Ordering is the security property, not a style preference: restore
        BEFORE the pin check means a reinstated cert is still verified; save
        AFTER it means a cert that failed the pin (which verify_ca_fingerprint.sh
        deletes) can never reach the cache."""
        cp = _index_of(SLO_METRICS_SERVICE, "docker cp elasticsearch")
        restore = _index_of(SLO_METRICS_SERVICE, "es_ca_cache.sh restore")
        verify = _index_of(SLO_METRICS_SERVICE, "verify_ca_fingerprint.sh")
        save = _index_of(SLO_METRICS_SERVICE, "es_ca_cache.sh save")
        for name, idx in (("docker cp", cp), ("restore", restore), ("verify", verify), ("save", save)):
            self.assertIsNotNone(idx, f"{name} step missing from slo-metrics.service")
        self.assertLess(cp, restore, "restore must run after the cp it compensates for")
        self.assertLess(restore, verify, "a reinstated CA must still be pin-verified before use")
        self.assertLess(verify, save, "only a pin-verified CA may enter the cache")

    def test_cache_lives_under_state_directory_not_runtime_directory(self):
        for verb in ("restore", "save"):
            with self.subTest(verb=verb):
                line = _lines(SLO_METRICS_SERVICE)[_index_of(SLO_METRICS_SERVICE, f"es_ca_cache.sh {verb}")]
                self.assertIn("/run/suburban-soc-slo/ca.crt", line)
                self.assertIn("/var/lib/suburban-soc-slo/ca.crt", line,
                              "the cached CA must live under StateDirectory= (/var/lib/...) — "
                              "RuntimeDirectory= is torn down between every Type=oneshot run, "
                              "which is the entire reason the cache is needed")
                self.assertIn("/var/lib/suburban-soc-slo/ca_fingerprint.sha256", line,
                              "both verbs need the pin path: restore refuses during a TOFU "
                              "re-arm, save refuses to cache an unpinned cert")

    def test_es_ca_still_points_at_the_runtime_copy(self):
        """The cache is a fallback source, not the path handed to Python —
        slo_metrics.py must keep reading the pin-verified runtime copy."""
        self.assertIn("Environment=ES_CA=/run/suburban-soc-slo/ca.crt", SLO_METRICS_SERVICE)


@unittest.skipUnless(shutil.which("openssl") and shutil.which("bash"), "openssl/bash not available")
class CaCacheFunctionalTests(unittest.TestCase):
    """Runs es_ca_cache.sh for real against self-signed certs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.runtime_ca = str(Path(self.tmp) / "run" / "ca.crt")
        Path(self.runtime_ca).parent.mkdir(parents=True, exist_ok=True)
        self.cache_ca = str(Path(self.tmp) / "state" / "ca.crt")
        Path(self.cache_ca).parent.mkdir(parents=True, exist_ok=True)
        self.pin_path = str(Path(self.tmp) / "state" / "ca_fingerprint.sha256")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_cert(self, path, cn):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "/dev/null",
             "-out", path, "-days", "1", "-nodes", "-subj", f"/CN={cn}"],
            capture_output=True, text=True, timeout=30, check=True,
        )

    def _run(self, mode):
        return subprocess.run(
            ["bash", str(CACHE_SCRIPT), mode, self.runtime_ca, self.cache_ca, self.pin_path],
            capture_output=True, text=True, timeout=30,
        )

    def _verify(self):
        return subprocess.run(
            ["bash", str(VERIFY_SCRIPT), self.runtime_ca, self.pin_path],
            capture_output=True, text=True, timeout=30,
        )

    def _pin(self, path):
        out = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout", "-fingerprint", "-sha256"],
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout
        return out.split("=", 1)[1].strip()

    # --- restore -----------------------------------------------------------

    def test_restore_reinstates_the_cached_cert_when_extraction_did_not_run(self):
        self._make_cert(self.cache_ca, "CA-A")
        Path(self.pin_path).write_text(self._pin(self.cache_ca) + "\n")
        self.assertFalse(Path(self.runtime_ca).exists())

        result = self._run("restore")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(Path(self.runtime_ca).is_file(), "cached CA was not reinstated")
        self.assertEqual(Path(self.cache_ca).read_bytes(), Path(self.runtime_ca).read_bytes())

    def test_reinstated_cert_still_passes_the_pin_check(self):
        """The cache must not be a way around TOFU — what it restores is still
        verified by the very next ExecStartPre."""
        self._make_cert(self.cache_ca, "CA-A")
        Path(self.pin_path).write_text(self._pin(self.cache_ca) + "\n")
        self._run("restore")
        self.assertEqual(0, self._verify().returncode)

    def test_restore_is_written_with_owner_only_permissions(self):
        self._make_cert(self.cache_ca, "CA-A")
        Path(self.pin_path).write_text(self._pin(self.cache_ca) + "\n")
        self._run("restore")
        mode = stat.S_IMODE(os.stat(self.runtime_ca).st_mode)
        self.assertEqual(0o600, mode, f"reinstated CA is mode {mode:o}, expected 600")

    def test_a_live_extraction_always_wins_over_the_cache(self):
        self._make_cert(self.runtime_ca, "CA-FRESH")
        self._make_cert(self.cache_ca, "CA-STALE")
        Path(self.pin_path).write_text(self._pin(self.runtime_ca) + "\n")
        fresh = Path(self.runtime_ca).read_bytes()

        result = self._run("restore")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(fresh, Path(self.runtime_ca).read_bytes(),
                         "restore overwrote a cert that was successfully extracted this run")

    def test_restore_refuses_while_tofu_is_re_armed_for_a_rotation(self):
        """An operator deletes the pin file to re-pin a rotated cert. If the
        Docker engine also happens to be down in that window, reinstating the
        STALE cached cert would let it be re-pinned as the new trusted value —
        silently undoing the rotation. Refuse instead."""
        self._make_cert(self.cache_ca, "CA-OLD")
        self.assertFalse(Path(self.pin_path).exists())

        result = self._run("restore")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(Path(self.runtime_ca).exists(),
                         "restored a cached cert during a TOFU re-arm window")
        self.assertIn("refusing to restore", result.stderr)

    def test_restore_with_nothing_available_is_a_quiet_success(self):
        result = self._run("restore")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(Path(self.runtime_ca).exists())

    # --- save --------------------------------------------------------------

    def test_save_caches_a_verified_cert(self):
        self._make_cert(self.runtime_ca, "CA-A")
        self.assertEqual(0, self._verify().returncode, "first-use pin should succeed")

        result = self._run("save")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(Path(self.runtime_ca).read_bytes(), Path(self.cache_ca).read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(os.stat(self.cache_ca).st_mode))

    def test_save_refuses_when_no_pin_exists(self):
        """No pin means verify_ca_fingerprint.sh has not accepted this cert
        against anything, so it must not become the cached trust anchor."""
        self._make_cert(self.runtime_ca, "CA-A")
        result = self._run("save")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(Path(self.cache_ca).exists(), "cached an unpinned cert")
        self.assertIn("refusing to cache", result.stderr)

    def test_a_pin_mismatch_never_reaches_the_cache(self):
        """End to end: cert A is pinned and cached; a swapped cert B arrives.
        verify_ca_fingerprint.sh deletes it and fails, so systemd never reaches
        the save step — and even if it did, there is nothing to cache."""
        self._make_cert(self.runtime_ca, "CA-A")
        self.assertEqual(0, self._verify().returncode)
        self._run("save")
        good = Path(self.cache_ca).read_bytes()

        self._make_cert(self.runtime_ca, "CA-B")
        self.assertEqual(1, self._verify().returncode, "swapped cert should fail the pin")
        self.assertFalse(Path(self.runtime_ca).exists(), "verify should have deleted the bad cert")

        result = self._run("save")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(good, Path(self.cache_ca).read_bytes(),
                         "an unverified cert reached the CA cache")

    def test_save_with_no_extracted_cert_is_a_quiet_success(self):
        self._make_cert(self.cache_ca, "CA-A")
        Path(self.pin_path).write_text(self._pin(self.cache_ca) + "\n")
        good = Path(self.cache_ca).read_bytes()

        result = self._run("save")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(good, Path(self.cache_ca).read_bytes())

    # --- cache invalidation (security-auditor MEDIUM 1) --------------------

    def test_restore_discards_a_cache_that_no_longer_matches_the_pin(self):
        """Without this, a stale cache turns every Docker-down run into:
        restore installs it -> verify deletes it and exits 1 -> ExecStartPre
        failure -> unit dead before ExecStart. Permanently, because
        verify_ca_fingerprint.sh only ever deletes the RUNTIME copy — the cache
        is not in its argv. That is the #550 hard-fail loop, rebuilt."""
        self._make_cert(self.cache_ca, "CA-STALE")
        other = str(Path(self.tmp) / "other.crt")
        self._make_cert(other, "CA-CURRENT")
        Path(self.pin_path).write_text(self._pin(other) + "\n")

        result = self._run("restore")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(Path(self.runtime_ca).exists(),
                         "installed a cached cert the pin cannot accept")
        self.assertFalse(Path(self.cache_ca).exists(),
                         "stale cache was not discarded — the failure loop is still reachable")
        self.assertIn("no longer matches the pin", result.stderr)

    def test_save_refuses_a_cert_that_does_not_match_the_pin(self):
        """Closes the verify->save window: anything with the service UID could
        otherwise swap the runtime file after verification and poison the cache
        permanently. save must not trust systemd ordering alone."""
        self._make_cert(self.cache_ca, "CA-GOOD")
        Path(self.pin_path).write_text(self._pin(self.cache_ca) + "\n")
        good = Path(self.cache_ca).read_bytes()
        self._make_cert(self.runtime_ca, "CA-SWAPPED")

        result = self._run("save")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(good, Path(self.cache_ca).read_bytes(),
                         "an unverified cert reached the cache through the save window")
        self.assertIn("does not match the pin", result.stderr)

    def test_restore_refuses_a_symlinked_cache(self):
        self._make_cert(str(Path(self.tmp) / "elsewhere.crt"), "CA-ELSEWHERE")
        Path(self.cache_ca).symlink_to(Path(self.tmp) / "elsewhere.crt")
        Path(self.pin_path).write_text(self._pin(str(Path(self.tmp) / "elsewhere.crt")) + "\n")

        result = self._run("restore")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(Path(self.runtime_ca).exists())
        self.assertIn("symlink", result.stderr)

    def test_restore_refuses_an_expired_cached_cert(self):
        """A fingerprint match says nothing about validity — verify_ca_fingerprint.sh
        never looks at notAfter. An expired anchor cannot complete a handshake,
        so reinstating it only produces a more confusing error."""
        expired = str(Path(self.tmp) / "expired.crt")
        minted = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "/dev/null",
             "-out", expired, "-nodes", "-subj", "/CN=CA-EXPIRED",
             "-not_before", "20200101000000Z", "-not_after", "20200102000000Z"],
            capture_output=True, text=True, timeout=30,
        )
        if minted.returncode != 0 or not Path(expired).exists():
            self.skipTest("this openssl cannot mint an already-expired cert "
                          f"({subprocess.run(['openssl', 'version'], capture_output=True, text=True).stdout.strip()})")
        shutil.copyfile(expired, self.cache_ca)
        Path(self.pin_path).write_text(self._pin(self.cache_ca) + "\n")

        result = self._run("restore")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(Path(self.runtime_ca).exists())
        self.assertIn("expired", result.stderr)

    def test_expiry_guard_is_present_in_the_script(self):
        """Backstop for the skip above: on a toolchain that cannot mint an
        expired cert the functional test silently vanishes, so assert the guard
        still exists rather than losing the coverage entirely."""
        self.assertIn("-checkend 0", CACHE_SCRIPT.read_text(encoding="utf-8"))

    # --- contract ----------------------------------------------------------

    def test_neither_mode_can_fail_the_unit(self):
        """es_ca_cache.sh exists to make a degraded run legible. If it could
        itself fail the unit it would reintroduce exactly the failure class
        #550 is about — an auxiliary dependency killing the metrics lane.

        Each half asserts the specific stderr marker of the failure path, not
        just the exit code: an earlier version of this test pre-populated the
        runtime CA, which made `restore` return at its "a live extraction
        already won" branch without ever reaching the code under test
        (code-reviewer, MAJOR)."""
        unreachable = str(Path(self.tmp) / "no-such-dir" / "ca.crt")

        # restore: good pinned cache, but the runtime destination is unwritable.
        self._make_cert(self.cache_ca, "CA-A")
        Path(self.pin_path).write_text(self._pin(self.cache_ca) + "\n")
        result = subprocess.run(
            ["bash", str(CACHE_SCRIPT), "restore", unreachable, self.cache_ca, self.pin_path],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("failed to reinstate", result.stderr,
                      "restore did not reach its install-failure path — test is vacuous")

        # save: good pinned runtime cert, but the cache destination is unwritable.
        self._make_cert(self.runtime_ca, "CA-B")
        Path(self.pin_path).write_text(self._pin(self.runtime_ca) + "\n")
        result = subprocess.run(
            ["bash", str(CACHE_SCRIPT), "save", self.runtime_ca, unreachable, self.pin_path],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("could not write the ES CA cache", result.stderr,
                      "save did not reach its install-failure path — test is vacuous")

    def test_unknown_mode_uses_a_status_the_unit_cannot_forgive(self):
        """slo-metrics.service carries `SuccessExitStatus=0 2`, and that
        directive was confirmed empirically on this host to cover ExecStartPre
        CONTROL processes — a control process exiting 2 yields Result=success
        and ExecStart runs anyway. So no script in this unit's start path may
        exit 2 on failure (security-auditor, MEDIUM). 64 is sysexits EX_USAGE."""
        result = self._run("frobnicate")
        self.assertEqual(64, result.returncode)
        self.assertIn("unknown mode", result.stderr)
        forgiven = _success_exit_statuses(SLO_METRICS_SERVICE)
        self.assertNotIn(result.returncode, forgiven,
                         f"usage status {result.returncode} is listed in SuccessExitStatus={forgiven}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
