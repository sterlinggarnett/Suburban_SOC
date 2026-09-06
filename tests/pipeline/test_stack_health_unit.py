#!/usr/bin/env python3
"""
#555 — the SOC self-health lane must actually run, and must survive the outage
it exists to report.

`configs/monitoring/reliability.cron` has scheduled `stack_health.sh` every five
minutes since WS2.5, but that crontab was never installed on the capture host,
so `soc-health` froze on 2026-07-12 and nothing noticed for ~56 days. This
covers the systemd unit + timer that replace it, and the two changes that keep
the lane honest when the stack underneath it is down:

  * `ES_REQUIRE_CA=0` — es_common.sh's default is `exit 1` when no CA is
    readable, which killed the whole health run (container checks and ntfy push
    included) in exactly the Docker-down state #550 is about. The soft mode
    moves the failure to each ES call without relaxing TLS anywhere.
  * a single `docker ps` snapshot with a recorded reason, so "the engine is
    gone" stops being reported as "the containers are down".

Three kinds of checks:

  1. Static assertions against the real unit files — no live systemd needed.
     These are the regression guard, same convention as
     test_slo_metrics_docker_independence.py.
  2. Functional tests that source lib/es_common.sh for real, because a text
     check cannot catch a logic bug in the fail-closed branch itself.
  3. A hermetic end-to-end run of stack_health.sh behind a fake `curl` and a
     fake `docker`, so no network call and no ntfy push can escape the test.

Run:  python tests/pipeline/test_stack_health_unit.py
      (or: pytest tests/pipeline)
"""

import json
import os
import stat
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SYSTEMD = ROOT / "configs" / "systemd"
SERVICE_PATH = SYSTEMD / "stack-health.service"
TIMER_PATH = SYSTEMD / "stack-health.timer"
SCRIPT_PATH = ROOT / "scripts" / "setup" / "stack_health.sh"
ES_COMMON = ROOT / "scripts" / "setup" / "lib" / "es_common.sh"
RELIABILITY_CRON = ROOT / "configs" / "monitoring" / "reliability.cron"

SERVICE = SERVICE_PATH.read_text(encoding="utf-8")
TIMER = TIMER_PATH.read_text(encoding="utf-8")
SCRIPT = SCRIPT_PATH.read_text(encoding="utf-8")

RUNTIME_CA = "/run/suburban-soc-health/ca.crt"
STATE_CA = "/var/lib/suburban-soc-health/ca.crt"
STATE_PIN = "/var/lib/suburban-soc-health/ca_fingerprint.sha256"


def _lines(text):
    return text.splitlines()


def _directives(text, key):
    return [ln for ln in _lines(text) if ln.startswith(key + "=")]


def _exec_pre(text):
    return _directives(text, "ExecStartPre")


def _index_of(text, needle):
    """Index of the first ExecStartPre containing `needle`, or None. Comments
    are excluded deliberately — several of them name these scripts."""
    for i, ln in enumerate(_lines(text)):
        if ln.startswith("ExecStartPre=") and needle in ln:
            return i
    return None


def _success_exit_statuses(text):
    out = set()
    for ln in _directives(text, "SuccessExitStatus"):
        for tok in ln.split("=", 1)[1].split():
            if tok.isdigit():
                out.add(int(tok))
    return out


class UnitFilesExistTests(unittest.TestCase):
    def test_service_and_timer_exist(self):
        self.assertTrue(SERVICE_PATH.is_file(), f"expected {SERVICE_PATH}")
        self.assertTrue(TIMER_PATH.is_file(), f"expected {TIMER_PATH}")

    def test_exec_start_points_at_the_real_script(self):
        """The unit hardcodes the DEPLOY host's absolute path, which is not the
        checkout root anywhere else (CI runs under /home/runner/work/...), so
        compare the repo-relative tail and prove the file exists separately —
        not `str(SCRIPT_PATH)`, which only holds on the capture host."""
        execs = _directives(SERVICE, "ExecStart")
        self.assertEqual(1, len(execs), f"expected exactly one ExecStart=, got {execs}")
        self.assertTrue(execs[0].endswith("/scripts/setup/stack_health.sh"),
                        f"ExecStart must invoke scripts/setup/stack_health.sh: {execs[0]}")
        self.assertTrue(SCRIPT_PATH.is_file(), f"{SCRIPT_PATH} does not exist")

    def test_absolute_paths_match_the_sibling_units(self):
        """Every path in this unit is absolute and rooted at the same deploy
        prefix the other units use — a unit that names a path no other unit
        agrees on is a deployment bug nothing else would catch."""
        prefix = "/home/tjlam/projects/Suburban-SOC"
        sibling = (SYSTEMD / "slo-metrics.service").read_text(encoding="utf-8")
        self.assertIn(prefix, sibling,
                      "the reference prefix moved — update both units together")
        repo_refs = [ln for ln in _lines(SERVICE)
                     if ln.startswith(("ExecStart=", "ExecStartPre="))
                     and "/scripts/setup/" in ln]
        self.assertTrue(repo_refs, "no repo-rooted Exec* directives found")
        for ln in repo_refs:
            with self.subTest(line=ln):
                self.assertIn(f"{prefix}/scripts/setup/", ln)

    def test_script_is_invoked_through_an_explicit_interpreter(self):
        """`#!/usr/bin/env bash` resolves through PATH, which systemd does not
        set the way a login shell does. Name the interpreter explicitly."""
        exec_start = _directives(SERVICE, "ExecStart")[0]
        self.assertIn("/usr/bin/bash", exec_start)


class TimerCadenceTests(unittest.TestCase):
    def test_timer_fires_every_five_minutes(self):
        self.assertIn("OnCalendar=*:0/5", TIMER,
                      "the timer must keep reliability.cron's 5-minute cadence")

    def test_cadence_matches_the_cron_entry_it_replaces(self):
        """If someone retunes one schedule and not the other, the fallback
        path silently disagrees with the preferred one."""
        cron = RELIABILITY_CRON.read_text(encoding="utf-8")
        stack_line = next(ln for ln in cron.splitlines() if "stack_health.sh" in ln
                          and not ln.lstrip().startswith("#"))
        self.assertTrue(stack_line.startswith("*/5 "),
                        f"reliability.cron's stack_health entry is no longer */5: {stack_line}")

    def test_timer_catches_up_after_downtime(self):
        self.assertIn("Persistent=true", TIMER,
                      "a health lane that skips its missed run after a reboot leaves "
                      "soc-health stale for exactly the window that matters most")

    def test_persistent_is_paired_with_a_calendar_schedule(self):
        """security-auditor (#555, LOW 5): per systemd.timer(5), Persistent=
        replays a missed run only for timers with OnCalendar=. On a purely
        monotonic timer it is inert, so asserting Persistent= alone asserted a
        property the configuration could not deliver. Live-confirmed on this
        host: with OnCalendar present, `systemctl --user show` reports
        TimersCalendar={ OnCalendar=*-*-* *:00/5:00 } and Persistent=yes."""
        self.assertIn("Persistent=true", TIMER)
        self.assertRegex(TIMER, r"(?m)^OnCalendar=",
                         "Persistent= without OnCalendar= is a no-op")

    def test_timer_still_runs_shortly_after_boot(self):
        """A wall-clock schedule alone would leave up to 5 minutes of silence
        after a reboot — the window in which a failed stack is most likely."""
        self.assertIn("OnBootSec=", TIMER)

    def test_timer_is_installable(self):
        self.assertIn("WantedBy=timers.target", TIMER)

    def test_service_is_not_independently_enabled_by_the_timer_unit(self):
        self.assertIn("WantedBy=multi-user.target", SERVICE)


class DockerCpIsBestEffortTests(unittest.TestCase):
    """The #550 conclusion, applied to the new unit from the start: a monitor
    that dies when the Docker CLI is unavailable shares a single point of
    failure with the sensors it is supposed to be watching."""

    def test_docker_cp_is_dash_prefixed(self):
        cp = next((ln for ln in _exec_pre(SERVICE) if "docker cp elasticsearch" in ln), None)
        self.assertIsNotNone(cp, "no ExecStartPre extracting the ES CA")
        self.assertTrue(cp.startswith("ExecStartPre=-"),
                        "the ES-CA `docker cp` must be '-'-prefixed: /usr/bin/docker is a "
                        "Docker Desktop symlink that dangles when the engine is stopped, and "
                        "systemd fails the whole unit with 203/EXEC before ExecStart (#550)")

    def test_no_unprefixed_docker_invocation_survives(self):
        offenders = [ln for ln in _exec_pre(SERVICE)
                     if "/usr/bin/docker" in ln and not ln.startswith("ExecStartPre=-")]
        self.assertEqual([], offenders, f"unprefixed docker ExecStartPre: {offenders}")

    def test_docker_cp_is_time_bounded(self):
        cp = next(ln for ln in _exec_pre(SERVICE) if "docker cp elasticsearch" in ln)
        self.assertIn("/usr/bin/timeout", cp,
                      "'-' suppresses a FAILED status and does nothing for a cp that BLOCKS "
                      "(Docker Desktop half-up: socket present, daemon not answering)")
        self.assertLess(cp.index("/usr/bin/timeout"), cp.index("/usr/bin/docker"),
                        "timeout must wrap docker, not the other way round")

    def test_unit_bounds_its_own_start_job(self):
        self.assertIn("TimeoutStartSec=", SERVICE,
                      "without an explicit TimeoutStartSec= the start path inherits "
                      "DefaultTimeoutStartSec; both sibling units set their own")


class CaTrustChainTests(unittest.TestCase):
    def test_restore_verify_save_are_wired_in_that_order(self):
        cp = _index_of(SERVICE, "docker cp elasticsearch")
        restore = _index_of(SERVICE, "es_ca_cache.sh restore")
        verify = _index_of(SERVICE, "verify_ca_fingerprint.sh")
        save = _index_of(SERVICE, "es_ca_cache.sh save")
        for name, idx in (("docker cp", cp), ("restore", restore),
                          ("verify", verify), ("save", save)):
            self.assertIsNotNone(idx, f"{name} step missing from stack-health.service")
        self.assertLess(cp, restore, "restore must run after the cp it compensates for")
        self.assertLess(restore, verify, "a reinstated CA must still be pin-verified before use")
        self.assertLess(verify, save, "only a pin-verified CA may enter the cache")

    def test_cache_lives_under_state_directory(self):
        for verb in ("restore", "save"):
            with self.subTest(verb=verb):
                line = _lines(SERVICE)[_index_of(SERVICE, f"es_ca_cache.sh {verb}")]
                self.assertIn(RUNTIME_CA, line)
                self.assertIn(STATE_CA, line,
                              "the cached CA must live under StateDirectory= — "
                              "RuntimeDirectory= is torn down between Type=oneshot runs")
                self.assertIn(STATE_PIN, line)

    def test_trust_gate_cannot_return_a_forgiven_status(self):
        """`SuccessExitStatus=` covers ExecStartPre control processes, and bash
        exits 2 on a syntax error — an unwrapped trust check fails OPEN."""
        verify = next(ln for ln in _exec_pre(SERVICE) if "verify_ca_fingerprint.sh" in ln)
        self.assertIn("|| exit 1", verify)
        self.assertFalse(verify.startswith("ExecStartPre=-"),
                         "a cert that FAILS the pin is an active trust problem, not an "
                         "absent dependency — this step must be able to fail the unit")
        self.assertNotIn(1, _success_exit_statuses(SERVICE),
                         "the normalised failure status is itself forgiven — pick another")

    def test_es_ca_points_at_the_pin_verified_runtime_copy(self):
        self.assertIn(f"Environment=ES_CA={RUNTIME_CA}", SERVICE,
                      "the cache is a fallback source, not the path handed to the script")

    def test_trust_anchor_directories_are_not_world_traversable(self):
        self.assertIn("RuntimeDirectoryMode=0700", SERVICE)
        self.assertIn("StateDirectoryMode=0700", SERVICE)


class ExitContractTests(unittest.TestCase):
    def test_component_down_is_not_a_unit_failure(self):
        """stack_health.sh exits 2 when a component is DOWN — a successful run
        reporting degradation. If systemd scored that as a failure,
        `systemctl is-failed` would stop meaning anything for this unit."""
        self.assertIn(2, _success_exit_statuses(SERVICE),
                      "exit 2 (a component is DOWN) must be a successful run")
        self.assertIn(0, _success_exit_statuses(SERVICE))

    def test_script_still_exits_two_on_degradation(self):
        self.assertIn("exit 2", SCRIPT,
                      "SuccessExitStatus=0 2 in the unit is calibrated against this")


class EnvironmentHandlingTests(unittest.TestCase):
    def test_no_wholesale_environment_file_of_dotenv(self):
        """#259: EnvironmentFile= strips whole-line comments only, so loading
        the raw .env injects every SLO_*/override in it — with trailing
        comments attached — into the unit's environment. stack_health.sh does
        its own `set -a; . .env`, so the unit needs no EnvironmentFile at all."""
        offenders = [ln for ln in _directives(SERVICE, "EnvironmentFile")
                     if "scripts/setup/.env" in ln]
        self.assertEqual([], offenders, f"unit loads .env wholesale: {offenders}")
        # The one EnvironmentFile that IS allowed points at the single-secret
        # scratch file the ExecStartPre above writes, not at .env itself.
        for ln in _directives(SERVICE, "EnvironmentFile"):
            with self.subTest(line=ln):
                self.assertIn("/run/suburban-soc-health/", ln)

    def test_only_values_dotenv_does_not_define_are_set_by_systemd(self):
        """stack_health.sh sources .env AFTER systemd has built the environment,
        so any key .env also defines would silently win. These must stay absent
        from .env.example for the unit's settings to survive."""
        example = (ROOT / "scripts" / "setup" / ".env.example").read_text(encoding="utf-8")
        assigned = {ln.split("=", 1)[0].strip()
                    for ln in example.splitlines()
                    if "=" in ln and not ln.lstrip().startswith("#")}
        for key in ("ES_CA", "ES_URL", "ES_USER", "ES_PASS", "ES_INSECURE"):
            with self.subTest(key=key):
                self.assertNotIn(key, assigned,
                                 f"{key} is now set in .env.example — it would override "
                                 "stack-health.service's Environment= line when "
                                 "stack_health.sh sources .env")


class LeastPrivilegeCredentialTests(unittest.TestCase):
    """security-auditor (#555, HIGH 1 — T1078). The first draft of this unit
    pinned no ES_USER, so es_common.sh's `elastic` default applied and a
    5-minute timer would have authenticated as the ES superuser 288 times a
    day — reversing the audit #167/#222 posture the two sibling units already
    implement. The earlier version of this very test file made it worse by
    asserting ES_USER's ABSENCE from .env.example, which locked the default in."""

    def test_unit_pins_a_non_superuser_identity(self):
        users = [ln.split("=", 2)[-1].strip()
                 for ln in _directives(SERVICE, "Environment")
                 if ln.startswith("Environment=ES_USER=")]
        self.assertEqual(1, len(users), f"expected exactly one ES_USER pin, got {users}")
        self.assertNotEqual("elastic", users[0],
                            "the self-health lane must not run as the ES superuser")

    def test_unit_extracts_only_its_own_secret(self):
        """#259: EnvironmentFile= on the raw .env injects every variable in it,
        trailing comments included. Extract the one secret this unit needs."""
        extract = next((ln for ln in _exec_pre(SERVICE)
                        if "SOC_HEALTH_PASSWORD" in ln), None)
        self.assertIsNotNone(extract, "no ExecStartPre extracting SOC_HEALTH_PASSWORD")
        self.assertIn("ES_PASS=", extract, "the secret must be renamed to ES_PASS on the "
                                           "way out — systemd's Environment= does not "
                                           "expand ${VAR}")
        self.assertIn("/run/suburban-soc-health/", extract,
                      "the scratch file must live in the 0700 RuntimeDirectory")

    def test_missing_credential_fails_the_unit_loudly(self):
        """A blank or absent password must not silently fall back to `elastic`.
        `test -s` would not be enough — "SOC_HEALTH_PASSWORD=" still yields a
        non-empty "ES_PASS=\n" line."""
        extract = next(ln for ln in _exec_pre(SERVICE) if "SOC_HEALTH_PASSWORD" in ln)
        self.assertIn('grep -Eq "^ES_PASS=.{8,}"', extract)

    def test_environment_file_for_the_scratch_secret_is_optional_at_parse_time(self):
        """EnvironmentFile= applies to every Exec* in the unit including the
        ExecStartPre that CREATES the file — unprefixed, the unit could never
        start, on every run, since RuntimeDirectory= is torn down each time."""
        env_files = _directives(SERVICE, "EnvironmentFile")
        self.assertTrue(env_files, "no EnvironmentFile= for the extracted secret")
        for ln in env_files:
            with self.subTest(line=ln):
                self.assertTrue(ln.startswith("EnvironmentFile=-"), ln)

    def test_role_file_exists_and_is_least_privilege(self):
        role = json.loads((ROOT / "configs" / "elasticsearch" / "roles"
                           / "soc_health.json").read_text(encoding="utf-8"))
        grants = {name: set(e["privileges"])
                  for e in role["indices"] for name in e["names"]}
        self.assertEqual({"create_index", "create"}, grants["soc-health"],
                         "append-only: no delete/manage, so a compromised health "
                         "credential cannot erase its own outage history")
        self.assertEqual({"read"}, grants["soc-slo-metrics"],
                         "this lane READS the SLO lane's output and must never be "
                         "able to forge it")
        self.assertEqual(["monitor"], role["cluster"],
                         "cluster monitor is all GET /_cluster/health needs")

    def test_compose_inline_copy_matches_the_role_file(self):
        role_path = ROOT / "configs" / "elasticsearch" / "roles" / "soc_health.json"
        compact = json.dumps(json.loads(role_path.read_text(encoding="utf-8")),
                             separators=(",", ":"))
        compose = (ROOT / "scripts" / "setup" / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn(compact.replace('"', '\\"'), compose,
                      "docker-compose.yml's inline soc_health role PUT has drifted from "
                      "configs/elasticsearch/roles/soc_health.json — keep them in sync")

    def test_soc_admin_cannot_write_the_self_monitoring_output_indices(self):
        """security-auditor (#555, HIGH 2 — T1562.001): #555 promotes soc-health
        from dashboard data to a monitoring-integrity signal. soc_admin holds
        `all` on soc-* and already excludes -soc-slo-metrics for exactly this
        reason; soc-health was left in, so an analyst-tier role could forge a
        current @timestamp and pin the SLO lane's view of it to healthy."""
        role = json.loads((ROOT / "configs" / "elasticsearch" / "roles"
                           / "soc_admin.json").read_text(encoding="utf-8"))
        names = [n for e in role["indices"] for n in e["names"]]
        for index in ("soc-slo-metrics", "soc-health"):
            with self.subTest(index=index):
                self.assertIn(f"-{index}", names,
                              f"soc_admin can still write/delete {index}")


class SandboxParityTests(unittest.TestCase):
    """#558's parity list, applied on the first pass rather than retrofitted."""

    REQUIRED = [
        "NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=read-only",
        "PrivateTmp=true", "ProtectClock=true", "ProtectKernelLogs=true",
        "ProtectKernelModules=true", "ProtectKernelTunables=true",
        "ProtectControlGroups=true", "ProtectHostname=true", "RestrictNamespaces=true",
        "RestrictSUIDSGID=true", "RestrictRealtime=true", "LockPersonality=true",
        "UMask=0077", "CapabilityBoundingSet=", "SystemCallArchitectures=native",
        "SystemCallFilter=@system-service", "PrivateDevices=true",
        "ProtectProc=invisible", "ProcSubset=pid",
    ]

    def test_hardening_directives_are_present(self):
        for directive in self.REQUIRED:
            with self.subTest(directive=directive):
                self.assertIn(f"\n{directive}", "\n" + SERVICE)

    def test_memory_is_bounded(self):
        self.assertRegex(SERVICE, r"(?m)^MemoryMax=\S+")

    def test_netlink_is_permitted(self):
        """glibc's getaddrinfo() enumerates local addresses over netlink;
        omitting AF_NETLINK breaks DNS resolution outright for every curl call."""
        line = next(ln for ln in _directives(SERVICE, "RestrictAddressFamilies"))
        for fam in ("AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"):
            self.assertIn(fam, line)

    def test_remove_ipc_is_not_set_on_an_interactive_login_account(self):
        """User=tjlam is the interactive login account and this is a
        Type=oneshot on a 5-minute timer — 288 teardowns a day against the
        operator's own desktop session."""
        offenders = [ln for ln in _directives(SERVICE, "RemoveIPC") if "true" in ln]
        self.assertEqual([], offenders, f"RemoveIPC set: {offenders}")


class SoftCaModeIsRequestedTests(unittest.TestCase):
    def test_script_opts_into_the_soft_ca_mode(self):
        self.assertRegex(SCRIPT, r"(?m)^ES_REQUIRE_CA=0\b",
                         "without this the health run exits 1 whenever the CA could not be "
                         "extracted — losing the container checks and the ntfy push in "
                         "exactly the outage it exists to report")

    def test_script_does_not_disable_tls_verification(self):
        self.assertNotRegex(SCRIPT, r"(?m)^ES_INSECURE=true",
                            "the soft CA mode must never become an insecure-TLS opt-out")


class DockerReasonIsReportedTests(unittest.TestCase):
    def test_every_container_check_reports_the_snapshot_reason(self):
        """`docker ps` failing and `docker ps` returning nothing are different
        facts; both used to print 'container down'."""
        for component in ("ai_agent", "broker", "logstash"):
            with self.subTest(component=component):
                self.assertNotRegex(
                    SCRIPT, rf'check {component} 1 "container down"',
                    f"{component} still reports a hardcoded 'container down'")
        self.assertIn("container_detail()", SCRIPT)

    def test_docker_is_queried_once_not_per_component(self):
        """Three separate `docker ps` calls could disagree with each other
        mid-run, and each one pays the timeout again when the engine is wedged.
        Comment lines are excluded — several of them discuss the call."""
        code = [ln for ln in SCRIPT.splitlines() if not ln.lstrip().startswith("#")]
        calls = [ln for ln in code if "docker ps" in ln]
        self.assertEqual(1, len(calls),
                         f"expected a single `docker ps` snapshot, found {calls}")


class EsCommonSoftCaFunctionalTests(unittest.TestCase):
    """Sourcing lib/es_common.sh for real — a text check cannot catch a logic
    bug in the fail-closed branch itself."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.missing_ca = str(Path(self.tmp) / "no-such-ca.crt")

    def _source(self, env):
        script = (
            "set -uo pipefail\n"
            f"source {ES_COMMON}\n"
            'printf "TLS:%s\\n" "${ES_TLS[*]}"\n'
            "echo REACHED_END\n"
        )
        base = {"PATH": os.environ.get("PATH", ""), "ES_PASS": "not-a-real-secret",
                "ES_CA": self.missing_ca}
        base.update(env)
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              timeout=30, env=base)

    def test_default_still_aborts_the_sourcing_script(self):
        """The #166 fail-closed default must be untouched by #555."""
        r = self._source({})
        self.assertEqual(1, r.returncode, r.stdout + r.stderr)
        self.assertNotIn("REACHED_END", r.stdout)
        self.assertIn("refusing to skip TLS verification", r.stderr)

    def test_soft_mode_lets_the_script_continue(self):
        r = self._source({"ES_REQUIRE_CA": "0"})
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("REACHED_END", r.stdout)

    def test_soft_mode_does_not_relax_tls(self):
        """The whole point: the script survives, the connection does not."""
        r = self._source({"ES_REQUIRE_CA": "0"})
        tls = next(ln for ln in r.stdout.splitlines() if ln.startswith("TLS:"))
        self.assertIn("--cacert", tls)
        self.assertNotIn("-k", tls.split(":", 1)[1].split(),
                         f"soft CA mode fell back to insecure curl: {tls}")
        self.assertIn(self.missing_ca, tls)

    def test_soft_mode_call_fails_before_anything_leaves_the_host(self):
        """curl aborts with exit 77 during SSL setup — no connection, no
        credential, no unverified handshake.

        This asserts curl's behaviour rather than this repo's, which is
        deliberate (code-reviewer, NIT): ES_REQUIRE_CA=0's entire safety
        argument rests on it. If a future curl/OpenSSL build ever connected
        first and failed later, the soft mode would be sending credentials
        over an unverified channel and this test going red is exactly the
        signal we would want — an intentional canary, not an incidental
        environment dependency.
        """
        r = subprocess.run(
            ["curl", "-s", "--max-time", "5", "--cacert", self.missing_ca,
             "https://example.com/"],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(77, r.returncode,
                         "expected CURLE_SSL_CACERT_BADFILE before any connection")

    def test_explicit_insecure_opt_out_still_wins(self):
        r = self._source({"ES_INSECURE": "true"})
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        tls = next(ln for ln in r.stdout.splitlines() if ln.startswith("TLS:"))
        self.assertIn("-k", tls)

    def test_an_empty_ca_reaches_the_diagnostic_branch(self):
        """security-auditor (#555, MEDIUM 2): the guard used to be `[[ -f ]]` —
        existence of a regular file, not readability and not non-emptiness — so
        a 0-byte ca.crt took the FIRST branch and the "no readable CA" warning
        could never explain it. Reachable here: stack-health.service wraps its
        `docker cp` in `timeout 15`, and a cp killed mid-write leaves a
        truncated destination that es_ca_cache.sh and verify_ca_fingerprint.sh
        both correctly no-op on, so nothing upstream removes it."""
        empty = Path(self.tmp) / "empty.crt"
        empty.write_text("")
        r = self._source({"ES_CA": str(empty), "ES_REQUIRE_CA": "0"})
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("no readable CA", r.stderr,
                      "an empty CA still took the happy path — the operator gets a bare "
                      "TLS error instead of a reason")

    def test_an_empty_ca_still_fails_closed_by_default(self):
        empty = Path(self.tmp) / "empty.crt"
        empty.write_text("")
        r = self._source({"ES_CA": str(empty)})
        self.assertEqual(1, r.returncode, r.stdout + r.stderr)
        self.assertIn("refusing to skip TLS verification", r.stderr)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses the read permission bit")
    def test_an_unreadable_ca_reaches_the_diagnostic_branch(self):
        unreadable = Path(self.tmp) / "locked.crt"
        unreadable.write_text("-----BEGIN CERTIFICATE-----\n")
        unreadable.chmod(0o000)
        try:
            r = self._source({"ES_CA": str(unreadable), "ES_REQUIRE_CA": "0"})
        finally:
            unreadable.chmod(0o600)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("no readable CA", r.stderr)


class HealthyRunDocumentTests(unittest.TestCase):
    """The document a healthy run actually posts to soc-health. Runs the real
    script behind a fake `curl` that logs its own argv, so the emitted JSON is
    asserted rather than assumed."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = Path(self.tmp) / "bin"
        self.bin.mkdir()
        self.log = Path(self.tmp) / "curl.log"
        self.ca = Path(self.tmp) / "ca.crt"
        self.ca.write_text("not a real certificate\n")
        fresh = (datetime.now(timezone.utc) - timedelta(seconds=60)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        # A fake curl that answers every probe healthily. It emulates the
        # `-w '\n%{http_code}'` the Kibana probe passes by appending the status
        # line itself, since the script parses that back out.
        body = (
            "#!/bin/sh\n"
            f'printf "%s\\n" "$@" >> {self.log}\n'
            'for a in "$@"; do\n'
            '  case "$a" in\n'
            "    *_cluster/health*) printf '{\"status\":\"green\"}'; exit 0 ;;\n"
            "    *api/status*) printf '{\"level\":\"available\"}\n200'; exit 0 ;;\n"
            "    *9600/_node/stats*) printf '{\"pipelines\":{}}'; exit 0 ;;\n"
            "    *soc-slo-metrics*) printf '{\"hits\":{\"hits\":"
            f"[{{\"_source\":{{\"@timestamp\":\"{fresh}\"}}}}]}}'; exit 0 ;;\n"
            "    *soc-health/_doc*) printf '{}'; exit 0 ;;\n"
            "  esac\n"
            "done\n"
            "exit 7\n"
        )
        p = self.bin / "curl"
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        d = self.bin / "docker"
        d.write_text("#!/bin/sh\nfor c in elasticsearch logstash soc_ai_agent "
                     "hive_mind_broker; do echo \"$c|running\"; done\n")
        d.chmod(d.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _run(self):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        env["ES_CA"] = str(self.ca)
        env["ES_URL"] = "https://127.0.0.1:59200"
        env["KIBANA_URL"] = "https://127.0.0.1:55601"
        env["NTFY_TOPIC"] = ""
        return subprocess.run(["bash", str(SCRIPT_PATH)], capture_output=True,
                              text=True, timeout=60, env=env)

    def test_a_fully_healthy_stack_exits_zero(self):
        r = self._run()
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("All components healthy", r.stdout)

    def test_a_healthy_run_records_an_empty_down_array(self):
        """security-auditor (#555, LOW 4): `printf '"%s",' "${DOWN[@]}"` on an
        EMPTY array still applies the format once with an empty argument, so
        every healthy document recorded "down":[""] — one element, not zero. A
        panel written as "alert when `down` is non-empty" would match every
        healthy run: 288 false positives a day. There is no index template for
        soc-health, so the first document's dynamic mapping is authoritative."""
        self._run()
        logged = self.log.read_text()
        self.assertIn('"down":[]', logged,
                      f'healthy run did not post an empty down array; argv was:\n{logged}')
        self.assertNotIn('"down":[""]', logged)
        self.assertIn('"down_count":0', logged)
        self.assertIn('"status":"healthy"', logged)

    def test_a_degraded_run_records_the_failing_components(self):
        """The other half of the same assertion — an empty array must mean
        healthy, not "this field never populates"."""
        d = self.bin / "docker"
        d.write_text("#!/bin/sh\necho 'elasticsearch|running'\n")
        r = self._run()
        self.assertEqual(2, r.returncode)
        logged = self.log.read_text()
        self.assertIn('"ai_agent"', logged)
        self.assertNotIn('"down":[]', logged)

    def test_a_kibana_authorization_failure_is_not_reported_as_an_outage(self):
        """#555 moved this lane onto a least-privilege credential, so a missing
        Kibana grant is a real possibility — and paging someone for a
        permissions problem disguised as an outage is how a monitoring lane
        loses its audience."""
        p = self.bin / "curl"
        p.write_text(p.read_text().replace(
            "*api/status*) printf '{\"level\":\"available\"}\n200'; exit 0 ;;",
            "*api/status*) printf '{\"statusCode\":401}\n401'; exit 0 ;;"))
        r = self._run()
        kibana = next(ln for ln in r.stdout.splitlines() if ln.strip().startswith("kibana"))
        self.assertIn("DOWN", kibana)
        self.assertIn("401", kibana)
        self.assertIn("lacks Kibana access", kibana)
        self.assertNotIn("unreachable", kibana,
                         "an authorization failure was reported as an outage")


class StackHealthEndToEndTests(unittest.TestCase):
    """Runs stack_health.sh for real behind a fake `curl` and a fake `docker`,
    so the test cannot open a socket or fire an ntfy push no matter what the
    host's .env happens to contain."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = Path(self.tmp) / "bin"
        self.bin.mkdir()
        # Every network call in stack_health.sh goes through curl. Failing it the
        # way an unreachable host does keeps the run hermetic.
        self._stub("curl", "#!/bin/sh\nexit 7\n")
        self.ca = Path(self.tmp) / "ca.crt"
        self.ca.write_text("not a real certificate\n")

    def _stub(self, name, body):
        p = self.bin / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _run(self):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        env["ES_CA"] = str(self.ca)
        env["ES_URL"] = "https://127.0.0.1:59200"
        env["KIBANA_URL"] = "https://127.0.0.1:55601"
        return subprocess.run(["bash", str(SCRIPT_PATH)], capture_output=True,
                              text=True, timeout=60, env=env)

    def test_a_missing_docker_engine_is_reported_as_such(self):
        self._stub("docker", "#!/bin/sh\necho \"docker: command not found\" >&2\nexit 1\n")
        r = self._run()
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)
        self.assertIn("docker unavailable", r.stdout)
        self.assertNotIn("container down", r.stdout,
                         "a dead Docker engine was reported as dead containers")

    def test_a_live_engine_with_a_stopped_container_still_says_container_down(self):
        self._stub("docker", "#!/bin/sh\necho 'elasticsearch|running'\n")
        r = self._run()
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)
        self.assertIn("container down", r.stdout,
                      "with the engine answering, an absent container is genuinely down")
        self.assertNotIn("docker unavailable", r.stdout)

    def test_a_crash_looping_container_is_not_up(self):
        """security-auditor (#555, MEDIUM 5 — T1562.001): `docker ps` LISTS
        containers in the `restarting` state, and {{.Names}} carries no state
        field, so a crash-looping soc_ai_agent used to read as UP and never
        reach the ntfy path — the SOC reporting itself healthy while a
        component flapped. Name presence is not liveness."""
        self._stub("docker", "#!/bin/sh\n"
                             "echo 'soc_ai_agent|restarting'\n"
                             "echo 'hive_mind_broker|running'\n")
        r = self._run()
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)
        agent = next(ln for ln in r.stdout.splitlines() if ln.strip().startswith("ai_agent"))
        self.assertIn("DOWN", agent, "a restarting container read as UP")
        self.assertIn("restarting", agent, "the report should name the actual state")
        broker = next(ln for ln in r.stdout.splitlines() if ln.strip().startswith("broker"))
        self.assertIn("UP", broker, "a genuinely running container must still read UP")

    def test_a_paused_decoy_container_is_not_up(self):
        """Anyone with Docker socket access could otherwise pin the report to
        healthy with a container that merely exists under the right name."""
        self._stub("docker", "#!/bin/sh\necho 'soc_ai_agent|paused'\n")
        agent = next(ln for ln in self._run().stdout.splitlines()
                     if ln.strip().startswith("ai_agent"))
        self.assertIn("DOWN", agent)
        self.assertIn("paused", agent)

    def test_a_name_cannot_match_by_prefix(self):
        self._stub("docker", "#!/bin/sh\necho 'soc_ai_agent_decoy|running'\n")
        agent = next(ln for ln in self._run().stdout.splitlines()
                     if ln.strip().startswith("ai_agent"))
        self.assertIn("DOWN", agent)

    def test_systemd_run_refuses_an_env_supplied_insecure_opt_out(self):
        """security-auditor (#555, LOW 1 — T1557): .env is sourced AFTER systemd
        builds the environment, so an ES_INSECURE=true line there beats the
        unit and hands curl -k — sending this lane's credential over an
        unverified handshake every 5 minutes. That opt-out is for a lab operator
        at a terminal, never for a scheduled monitor."""
        self._stub("docker", "#!/bin/sh\necho 'elasticsearch|running'\n")
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        env["ES_CA"] = str(self.ca)
        env["ES_INSECURE"] = "true"
        env["INVOCATION_ID"] = "0123456789abcdef0123456789abcdef"
        r = subprocess.run(["bash", str(SCRIPT_PATH)], capture_output=True,
                           text=True, timeout=60, env=env)
        self.assertEqual(1, r.returncode, r.stdout + r.stderr)
        self.assertIn("must not disable TLS verification", r.stderr)

    def test_a_manual_run_keeps_the_lab_opt_out(self):
        """The refusal is scoped to systemd (INVOCATION_ID), not to everyone —
        a human debugging a broken first-run stack still has the escape hatch."""
        self._stub("docker", "#!/bin/sh\necho 'elasticsearch|running'\n")
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        env["ES_CA"] = str(Path(self.tmp) / "gone.crt")
        env["ES_INSECURE"] = "true"
        env.pop("INVOCATION_ID", None)
        r = subprocess.run(["bash", str(SCRIPT_PATH)], capture_output=True,
                           text=True, timeout=60, env=env)
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)
        self.assertIn("=== DOWN:", r.stdout)

    def test_run_survives_an_unreadable_ca(self):
        """The #555 property: no CA must not mean no health report."""
        self._stub("docker", "#!/bin/sh\necho elasticsearch\n")
        env_ca = Path(self.tmp) / "gone.crt"
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        env["ES_CA"] = str(env_ca)
        env["ES_URL"] = "https://127.0.0.1:59200"
        env["KIBANA_URL"] = "https://127.0.0.1:55601"
        r = subprocess.run(["bash", str(SCRIPT_PATH)], capture_output=True,
                           text=True, timeout=60, env=env)
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)
        self.assertIn("=== DOWN:", r.stdout,
                      "the run must still produce a report when the CA is unreadable")
        self.assertIn("TLS verification is NOT relaxed", r.stderr)


class SloMetricsFreshnessTests(unittest.TestCase):
    """#555 half one of the mutual cross-monitoring pair: stack_health.sh must
    notice that the SLO lane stopped producing.

    A staleness check on soc-slo-metrics cannot live inside slo_metrics.py —
    it could not fire when slo_metrics.py is the thing that stopped, which is
    exactly the condition it exists to detect and exactly what happened here
    (soc-slo-metrics frozen at 2026-08-17T01:31:42Z while the unit failed every
    15 minutes). Runs the real script behind a fake `curl`."""

    STALE_MAX_DEFAULT = 2700

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = Path(self.tmp) / "bin"
        self.bin.mkdir()
        self.ca = Path(self.tmp) / "ca.crt"
        self.ca.write_text("not a real certificate\n")
        # Engine answers, so container state cannot be confused with a dead CLI.
        self._stub("docker", "#!/bin/sh\necho elasticsearch\n")

    def _stub(self, name, body):
        p = self.bin / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _serve(self, payload, cluster_status="green"):
        """Fake curl: answers the cluster-health probe and the soc-slo-metrics
        search, and fails everything else the way an unreachable host does.

        Answering cluster health matters — the freshness check consults
        `es_status` to decide whether to blame Elasticsearch or the SLO lane,
        so a fake that let ES read as unreachable would silently exercise only
        one of the two branches."""
        health = "" if cluster_status is None else (
            '{"status":"%s"}' % cluster_status)
        health_case = (
            f"    *_cluster/health*) printf '%s' '{health}'; exit 0 ;;\n"
            if health else "")
        self._stub("curl",
                   "#!/bin/sh\n"
                   "for a in \"$@\"; do\n"
                   "  case \"$a\" in\n"
                   + health_case +
                   f"    *soc-slo-metrics*) printf '%s' '{payload}'; exit 0 ;;\n"
                   "  esac\n"
                   "done\n"
                   "exit 7\n")

    def _hit(self, when):
        return ('{"hits":{"hits":[{"_source":{"@timestamp":"%s"}}]}}'
                % when.strftime("%Y-%m-%dT%H:%M:%SZ"))

    def _run(self, extra_env=None):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        env["ES_CA"] = str(self.ca)
        env["ES_URL"] = "https://127.0.0.1:59200"
        env["KIBANA_URL"] = "https://127.0.0.1:55601"
        env.update(extra_env or {})
        return subprocess.run(["bash", str(SCRIPT_PATH)], capture_output=True,
                              text=True, timeout=60, env=env)

    def _slo_line(self, stdout):
        lines = [ln for ln in stdout.splitlines() if ln.strip().startswith("slo_metrics")]
        self.assertEqual(1, len(lines), f"expected one slo_metrics line, got {lines}")
        return lines[0]

    def test_a_fresh_index_reads_up(self):
        self._serve(self._hit(datetime.now(timezone.utc) - timedelta(seconds=120)))
        line = self._slo_line(self._run().stdout)
        self.assertIn("UP", line)
        self.assertIn("fresh", line)

    def test_a_stale_index_reads_down(self):
        """The live condition on the capture host: 20 days without a write."""
        self._serve(self._hit(datetime.now(timezone.utc) - timedelta(days=20)))
        r = self._run()
        line = self._slo_line(r.stdout)
        self.assertIn("DOWN", line)
        self.assertIn("stale", line)
        self.assertIn("slo_metrics", r.stdout.split("=== DOWN:")[-1],
                      "a stale SLO lane must reach the DOWN list that drives the ntfy push")
        self.assertEqual(2, r.returncode)

    def test_the_boundary_is_the_configured_threshold(self):
        """Just inside the window is healthy; just outside is not. Without both
        halves a check can pass by always answering the same way."""
        self._serve(self._hit(datetime.now(timezone.utc)
                              - timedelta(seconds=self.STALE_MAX_DEFAULT - 60)))
        self.assertIn("UP", self._slo_line(self._run().stdout))
        self._serve(self._hit(datetime.now(timezone.utc)
                              - timedelta(seconds=self.STALE_MAX_DEFAULT + 60)))
        self.assertIn("DOWN", self._slo_line(self._run().stdout))

    def test_threshold_is_overridable(self):
        self._serve(self._hit(datetime.now(timezone.utc) - timedelta(seconds=600)))
        self.assertIn("UP", self._slo_line(self._run().stdout))
        self.assertIn("DOWN", self._slo_line(
            self._run({"SOC_SLO_METRICS_STALE_MAX_S": "60"}).stdout))

    def test_default_tolerates_one_missed_timer_interval(self):
        """2700s = 3x the 15-minute slo-metrics.timer cadence — a single slow or
        missed run must not page anyone."""
        self._serve(self._hit(datetime.now(timezone.utc) - timedelta(minutes=20)))
        self.assertIn("UP", self._slo_line(self._run().stdout))

    def test_an_empty_index_is_not_healthy(self):
        """With Elasticsearch itself healthy, an empty soc-slo-metrics index is
        the SLO lane's own failure and must be reported as such."""
        self._serve('{"hits":{"hits":[]}}')
        line = self._slo_line(self._run().stdout)
        self.assertIn("DOWN", line)
        self.assertIn("index empty/absent, or credential rejected", line)

    def test_a_rejected_credential_is_not_healthy(self):
        self._serve('{"error":{"type":"security_exception"},"status":401}')
        self.assertIn("DOWN", self._slo_line(self._run().stdout))

    def test_an_elasticsearch_outage_is_named_as_the_cause(self):
        """The same DOWN entry, but the detail says WHY — during an ES outage
        this check fires alongside the `elasticsearch` one, and two entries for
        one root cause should not read as two independent failures."""
        self._serve('{"hits":{"hits":[]}}', cluster_status=None)
        r = self._run()
        line = self._slo_line(r.stdout)
        self.assertIn("DOWN", line)
        self.assertIn("elasticsearch is DOWN", line)
        self.assertIn("slo_metrics", r.stdout.split("=== DOWN:")[-1],
                      "naming the cause must not remove it from the DOWN list")

    def test_a_red_cluster_is_treated_as_an_outage_not_a_lane_failure(self):
        """`red` fails the elasticsearch check above, so the freshness check
        must attribute the miss to ES rather than to the SLO lane."""
        self._serve('{"hits":{"hits":[]}}', cluster_status="red")
        line = self._slo_line(self._run().stdout)
        self.assertIn("elasticsearch is DOWN (red)", line)

    def test_a_yellow_cluster_still_blames_the_lane(self):
        """yellow is a healthy-enough cluster (the elasticsearch check accepts
        it), so a missing document there is genuinely the lane's fault."""
        self._serve('{"hits":{"hits":[]}}', cluster_status="yellow")
        line = self._slo_line(self._run().stdout)
        self.assertIn("index empty/absent, or credential rejected", line)

    def test_an_unparseable_timestamp_is_not_healthy(self):
        """`date -d` failing must not silently become age 0. Carries a Z so it
        reaches the parse branch rather than the timezone guard below."""
        self._serve('{"hits":{"hits":[{"_source":{"@timestamp":"9999-99-99T99:99:99Z"}}]}}')
        line = self._slo_line(self._run().stdout)
        self.assertIn("DOWN", line)
        self.assertIn("unparseable", line)

    def test_a_timezone_less_timestamp_is_refused(self):
        """security-auditor (#555, LOW 3): `date -u` sets OUTPUT format; it does
        not make a naive input UTC. GNU date reads an offset-less value as
        host-local, shifting the age by up to the UTC offset — enough to make a
        dead lane read fresh against a 2700s window. Latent (no current writer
        emits one), so refusing it costs nothing and closes the case."""
        self._serve('{"hits":{"hits":[{"_source":{"@timestamp":"2026-09-06T01:31:42"}}]}}')
        line = self._slo_line(self._run().stdout)
        self.assertIn("DOWN", line)
        self.assertIn("carries no timezone", line)

    def test_an_explicit_offset_is_accepted(self):
        """Elasticsearch emits +00:00 rather than Z for some writers — the
        timezone guard must not reject a perfectly valid document."""
        when = (datetime.now(timezone.utc) - timedelta(seconds=90)).strftime(
            "%Y-%m-%dT%H:%M:%S+00:00")
        self._serve('{"hits":{"hits":[{"_source":{"@timestamp":"%s"}}]}}' % when)
        self.assertIn("UP", self._slo_line(self._run().stdout))

    def test_a_future_timestamp_is_an_anomaly_not_freshness(self):
        """security-auditor (#555, MEDIUM 1 — T1562.001): a negative age is
        trivially <= any positive threshold, so one future-dated document used
        to pin this check to `fresh` forever — the exact "watchdog reads healthy
        while the thing it watches is dead" failure the lane exists to prevent.
        Reachable from a compromised slo_metrics credential (it holds `create`
        on soc-slo-metrics), from a soc_admin write, or from host clock skew."""
        self._serve(self._hit(datetime.now(timezone.utc) + timedelta(days=20)))
        r = self._run()
        line = self._slo_line(r.stdout)
        self.assertIn("DOWN", line)
        self.assertIn("in the FUTURE", line)
        self.assertIn("slo_metrics", r.stdout.split("=== DOWN:")[-1])

    def test_small_forward_clock_skew_is_tolerated(self):
        """The indexer's clock being a few seconds ahead is benign and must not
        page anyone — only a skew past the tolerance is the anomaly."""
        self._serve(self._hit(datetime.now(timezone.utc) + timedelta(seconds=30)))
        self.assertIn("UP", self._slo_line(self._run().stdout))

    def test_a_non_numeric_threshold_falls_back_instead_of_evaluating(self):
        """security-auditor (#555, LOW 2 — T1059.004): bash recursively
        evaluates a variable's CONTENTS inside (( )), so a value naming another
        variable makes the comparison silently always-false, and x[$(cmd)]
        executes cmd. Reachable from the plain process environment."""
        self._serve(self._hit(datetime.now(timezone.utc) - timedelta(days=20)))
        r = self._run({"SOC_SLO_METRICS_STALE_MAX_S": "slo_age"})
        self.assertIn("ignoring non-numeric", r.stderr)
        self.assertIn("DOWN", self._slo_line(r.stdout),
                      "a 20-day-old index must still read DOWN under the fallback")

    def test_a_threshold_naming_a_command_substitution_is_not_executed(self):
        canary = Path(self.tmp) / "canary"
        r = self._run({"SOC_SLO_METRICS_STALE_MAX_S": f"x[$(touch {canary})]"})
        self.assertFalse(canary.exists(),
                         "the threshold reached an arithmetic context and executed")
        self.assertIn("ignoring non-numeric", r.stderr)


class CrossLaneOwnershipTests(unittest.TestCase):
    """The two staleness checks must stay in opposite lanes. If both ever end up
    in one script, the pair stops being mutual and the whole design collapses
    back into a monitor that cannot report its own death."""

    def test_stack_health_watches_the_slo_index(self):
        self.assertIn("soc-slo-metrics", SCRIPT)

    def test_stack_health_does_not_watch_its_own_output_index(self):
        code = [ln for ln in SCRIPT.splitlines() if not ln.lstrip().startswith("#")]
        searches = [ln for ln in code if "soc-health/_search" in ln]
        self.assertEqual([], searches,
                         "a soc-health freshness check inside stack_health.sh cannot fire "
                         "when stack_health.sh is the thing that stopped — that check "
                         "belongs to slo_metrics.py")


if __name__ == "__main__":
    unittest.main(verbosity=2)
