#!/usr/bin/env python3
"""
#549: zeek-host-capture.service can report `active (running)` while
capturing zero packets — observed live on 2026-09-05, a dead tcpdump leg
left `docker run` attached to a container whose Zeek had already exited,
and the hung `docker run` client never returns, so systemd reported
`active`/`running` for five days with zero packets captured.
`RestartPreventExitStatus=78` (#551) closes the TRIGGER seen in that
incident (a stale CAPTURE_IFACE); it does not close the wedge itself, since
the preflight only runs once, before the pipeline.

zeek_capture_liveness.sh derives liveness from sensor OUTPUT
(conn.log's mtime) instead: restart + alert only when the unit is `active`
AND stale, never when `failed`. Two kinds of checks, same convention as
test_zeek_capture_iface_validation.py and test_stack_health_unit.py:

  1. Static assertions against the real unit/timer files.
  2. Functional runs of the real script against a fake `systemctl`/`curl`
     on PATH — deterministic, no root, no live systemd needed.

Run:  python tests/pipeline/test_zeek_capture_liveness.py
      (or: pytest tests/pipeline)
"""

import os
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SYSTEMD = ROOT / "configs" / "systemd"
SERVICE_PATH = SYSTEMD / "zeek-capture-liveness.service"
TIMER_PATH = SYSTEMD / "zeek-capture-liveness.timer"
SCRIPT_PATH = ROOT / "scripts" / "setup" / "zeek_capture_liveness.sh"
ZEEK_UNIT_PATH = SYSTEMD / "zeek-host-capture.service"

SERVICE = SERVICE_PATH.read_text(encoding="utf-8")
TIMER = TIMER_PATH.read_text(encoding="utf-8")


def _lines(text):
    return text.splitlines()


def _directives(text, key):
    return [ln for ln in _lines(text) if ln.startswith(key + "=")]


class UnitFilesExistTests(unittest.TestCase):
    def test_service_timer_and_script_exist(self):
        self.assertTrue(SERVICE_PATH.is_file())
        self.assertTrue(TIMER_PATH.is_file())
        self.assertTrue(SCRIPT_PATH.is_file())

    def test_exec_start_points_at_the_real_script(self):
        execs = _directives(SERVICE, "ExecStart")
        self.assertEqual(1, len(execs), f"expected exactly one ExecStart=, got {execs}")
        self.assertTrue(execs[0].endswith("/scripts/setup/zeek_capture_liveness.sh"))

    def test_script_is_syntactically_valid_bash(self):
        r = subprocess.run(["bash", "-n", str(SCRIPT_PATH)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(0, r.returncode, r.stderr)

    def test_exit_two_is_a_successful_run(self):
        """A run that found and fixed a real problem (restarted a wedged
        sensor) is not a job failure — same contract as the sibling
        self-health units."""
        statuses = set()
        for ln in _directives(SERVICE, "SuccessExitStatus"):
            statuses.update(int(t) for t in ln.split("=", 1)[1].split() if t.isdigit())
        self.assertEqual({0, 2}, statuses)


class TimerCadenceTests(unittest.TestCase):
    def test_timer_fires_every_five_minutes(self):
        self.assertIn("OnCalendar=*:0/5", TIMER)

    def test_timer_catches_up_after_downtime(self):
        self.assertIn("Persistent=true", TIMER)

    def test_timer_is_installable(self):
        self.assertIn("WantedBy=timers.target", TIMER)

    def test_service_is_not_independently_enabled_by_the_timer_unit(self):
        self.assertIn("WantedBy=multi-user.target", SERVICE)


class OnFailureWiringTests(unittest.TestCase):
    def test_this_units_own_failure_is_dispatched(self):
        """Covers this unit's OWN failure (a bug in the script, a systemctl
        D-Bus error) — not the sensor wedge, which the script's own exit-2
        successful-run path alerts on directly."""
        self.assertIn("OnFailure=soc-alert-on-failure@%n.service", SERVICE)


class RunsAsRootTests(unittest.TestCase):
    def test_unit_runs_as_root(self):
        """`systemctl restart` on a system unit is a privileged operation;
        unlike the ES-backed self-health units there is no narrower
        identity to drop to for it."""
        self.assertIn("User=root", SERVICE)


class ZeekCaptureLivenessFunctionalTests(unittest.TestCase):
    """Runs the real script behind fake `systemctl`/`curl` on PATH."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = Path(self.tmp) / "bin"
        self.bin.mkdir()
        self.conn_log = Path(self.tmp) / "conn.log"
        self.systemctl_log = Path(self.tmp) / "systemctl.log"
        self.curl_log = Path(self.tmp) / "curl.log"

    def _stub(self, name, body):
        p = self.bin / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _stub_systemctl(self, is_active_state="active"):
        self._stub("systemctl", f"""#!/bin/sh
echo "$@" >> {self.systemctl_log}
if [ "$1" = "is-active" ]; then echo {is_active_state}; exit 0; fi
if [ "$1" = "restart" ]; then exit 0; fi
exit 0
""")

    def _stub_curl(self):
        self._stub("curl", f'#!/bin/sh\necho "$@" >> {self.curl_log}\nexit 0\n')

    def _run(self, extra_env=None):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        env["ZEEK_CONN_LOG"] = str(self.conn_log)
        env.pop("NTFY_TOPIC", None)
        env.update(extra_env or {})
        return subprocess.run(["bash", str(SCRIPT_PATH)], capture_output=True,
                              text=True, timeout=30, env=env)

    def test_fresh_log_is_healthy_no_restart(self):
        self._stub_systemctl()
        self.conn_log.write_text("")
        r = self._run()
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("OK", r.stdout)
        self.assertFalse(self.systemctl_log.exists() and "restart" in self.systemctl_log.read_text())

    def test_stale_log_while_active_restarts_and_exits_two(self):
        self._stub_systemctl()
        self.conn_log.write_text("")
        old = time.time() - 3600
        os.utime(self.conn_log, (old, old))
        r = self._run({"ZEEK_CAPTURE_STALE_MAX_S": "1800"})
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)
        self.assertIn("restart", self.systemctl_log.read_text())
        self.assertIn("STALE", r.stderr)

    def test_failed_unit_is_never_restarted(self):
        """The whole point: a genuine config error must stay parked and
        visible, not be papered over by an automatic restart loop."""
        self._stub_systemctl(is_active_state="failed")
        old = time.time() - 3600
        self.conn_log.write_text("")
        os.utime(self.conn_log, (old, old))
        r = self._run()
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        calls = self.systemctl_log.read_text()
        self.assertNotIn("restart", calls)

    def test_inactive_unit_is_never_restarted(self):
        self._stub_systemctl(is_active_state="inactive")
        r = self._run()
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertNotIn("restart", self.systemctl_log.read_text() if self.systemctl_log.exists() else "")

    def test_missing_conn_log_is_treated_as_stale(self):
        """The unit is active but has never written a first log at all —
        must not be silently skipped just because the file doesn't exist."""
        self._stub_systemctl()
        self.assertFalse(self.conn_log.exists())
        r = self._run()
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)
        self.assertIn("restart", self.systemctl_log.read_text())

    def test_missing_ntfy_topic_still_restarts_but_warns(self):
        self._stub_systemctl()
        old = time.time() - 3600
        self.conn_log.write_text("")
        os.utime(self.conn_log, (old, old))
        r = self._run()
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)
        self.assertIn("NTFY_TOPIC unset", r.stderr)

    def test_configured_topic_posts_the_alert(self):
        self._stub_systemctl()
        self._stub_curl()
        old = time.time() - 3600
        self.conn_log.write_text("")
        os.utime(self.conn_log, (old, old))
        r = self._run({"NTFY_TOPIC": "test-topic-xyz"})
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)
        logged = self.curl_log.read_text()
        self.assertIn("ntfy.sh/test-topic-xyz", logged)
        self.assertIn("restarted automatically", logged)

    def test_a_curl_failure_does_not_change_the_exit_code(self):
        self._stub_systemctl()
        self._stub("curl", "#!/bin/sh\nexit 7\n")
        old = time.time() - 3600
        self.conn_log.write_text("")
        os.utime(self.conn_log, (old, old))
        r = self._run({"NTFY_TOPIC": "test-topic-xyz"})
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)

    def test_non_numeric_threshold_falls_back_to_default_instead_of_evaluating(self):
        """security-auditor bug class (#555's own finding): bash
        recursively evaluates a variable's CONTENTS inside (( )), so a
        value naming a command substitution must never reach that
        context unvalidated."""
        self._stub_systemctl()
        old = time.time() - 3600
        self.conn_log.write_text("")
        os.utime(self.conn_log, (old, old))
        canary = Path(self.tmp) / "canary"
        r = self._run({"ZEEK_CAPTURE_STALE_MAX_S": f"x[$(touch {canary})]"})
        self.assertFalse(canary.exists(),
                         "the threshold reached an arithmetic/command-substitution context")
        self.assertIn("ignoring non-numeric", r.stderr)
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)

    def test_boundary_is_the_configured_threshold(self):
        self._stub_systemctl()
        just_inside = time.time() - 1700
        self.conn_log.write_text("")
        os.utime(self.conn_log, (just_inside, just_inside))
        r = self._run({"ZEEK_CAPTURE_STALE_MAX_S": "1800"})
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)

        just_outside = time.time() - 1900
        os.utime(self.conn_log, (just_outside, just_outside))
        r = self._run({"ZEEK_CAPTURE_STALE_MAX_S": "1800"})
        self.assertEqual(2, r.returncode, r.stdout + r.stderr)


class ZeekUnitCrossReferenceTests(unittest.TestCase):
    def test_zeek_host_capture_service_still_exists(self):
        """This whole supervisor is meaningless if the unit it restarts is
        ever renamed without this test file catching it."""
        self.assertTrue(ZEEK_UNIT_PATH.is_file())
        script = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn('UNIT="zeek-host-capture.service"', script)


if __name__ == "__main__":
    unittest.main(verbosity=2)
