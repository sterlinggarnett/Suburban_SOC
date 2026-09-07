#!/usr/bin/env python3
"""
#554 — the SOC self-health lane had no failure-delivery path: no unit carried
`OnFailure=`, so a unit that failed before its own body ever ran (an
ExecStartPre credential or CA-pin check, say) produced a journal line and
nothing else; and `NTFY_TOPIC` was unprovisioned, so even a metric-computed
breach had nowhere to go.

Two kinds of checks, same convention as test_stack_health_unit.py:

  1. Static assertions against the real unit/script files — no live systemd
     needed.
  2. A hermetic run of scripts/setup/soc_alert_on_failure.sh behind a fake
     `curl`, so no real network call can escape the test.

Run:  python tests/pipeline/test_soc_alert_on_failure.py
      (or: pytest tests/pipeline)
"""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SYSTEMD = ROOT / "configs" / "systemd"
DISPATCHER_UNIT = SYSTEMD / "soc-alert-on-failure@.service"
DISPATCHER_SCRIPT = ROOT / "scripts" / "setup" / "soc_alert_on_failure.sh"
SLO_METRICS_SERVICE = SYSTEMD / "slo-metrics.service"
ZEEK_CAPTURE_SERVICE = SYSTEMD / "zeek-host-capture.service"
SLO_METRICS_PY = ROOT / "scripts" / "setup" / "ai_agent" / "slo_metrics.py"
REDEPLOY = ROOT / "scripts" / "setup" / "redeploy_systemd_units.sh"


def _lines(text):
    return text.splitlines()


def _directives(text, key):
    return [ln for ln in _lines(text) if ln.startswith(key + "=")]


class DispatcherUnitExistsTests(unittest.TestCase):
    def test_template_unit_and_script_exist(self):
        self.assertTrue(DISPATCHER_UNIT.is_file(), f"expected {DISPATCHER_UNIT}")
        self.assertTrue(DISPATCHER_SCRIPT.is_file(), f"expected {DISPATCHER_SCRIPT}")

    def test_unit_invokes_the_real_script_with_the_instance_argument(self):
        text = DISPATCHER_UNIT.read_text(encoding="utf-8")
        execs = _directives(text, "ExecStart")
        self.assertEqual(1, len(execs), f"expected exactly one ExecStart=, got {execs}")
        self.assertTrue(execs[0].endswith("soc_alert_on_failure.sh %i"),
                        f"ExecStart must pass %i through as the failed unit name: {execs[0]}")

    def test_dispatcher_carries_no_docker_or_elasticsearch_dependency(self):
        """The whole point: this unit must stay reachable in exactly the
        outage class slo-metrics.service/zeek-host-capture.service report.
        Checks executable directives/code only — the header comments
        legitimately name both while explaining why neither is a dependency."""
        unit_code = [ln for ln in _lines(DISPATCHER_UNIT.read_text(encoding="utf-8"))
                     if not ln.lstrip().startswith("#") and ln.strip()]
        script_code = [ln for ln in _lines(DISPATCHER_SCRIPT.read_text(encoding="utf-8"))
                       if not ln.lstrip().startswith("#") and ln.strip()]
        for name, lines in (("unit", unit_code), ("script", script_code)):
            with self.subTest(source=name):
                joined = "\n".join(lines).lower()
                self.assertNotIn("docker", joined)
                self.assertNotIn("elasticsearch", joined)

    def test_script_is_syntactically_valid_bash(self):
        r = subprocess.run(["bash", "-n", str(DISPATCHER_SCRIPT)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(0, r.returncode, r.stderr)


class OnFailureWiringTests(unittest.TestCase):
    """The 'at minimum' unit set the issue names."""

    def test_slo_metrics_wires_onfailure_to_the_dispatcher(self):
        text = SLO_METRICS_SERVICE.read_text(encoding="utf-8")
        self.assertIn("OnFailure=soc-alert-on-failure@%n.service", text)

    def test_zeek_host_capture_wires_onfailure_to_the_dispatcher(self):
        text = ZEEK_CAPTURE_SERVICE.read_text(encoding="utf-8")
        self.assertIn("OnFailure=soc-alert-on-failure@%n.service", text)

    def test_onfailure_directive_lives_in_the_unit_section(self):
        """OnFailure= is only meaningful in [Unit] — assert it appears before
        the first [Service] header in both watched units."""
        for path in (SLO_METRICS_SERVICE, ZEEK_CAPTURE_SERVICE):
            with self.subTest(unit=path.name):
                text = path.read_text(encoding="utf-8")
                onfailure_idx = text.index("OnFailure=soc-alert-on-failure@%n.service")
                service_idx = text.index("\n[Service]")
                self.assertLess(onfailure_idx, service_idx,
                                "OnFailure= must precede [Service] to land in [Unit]")


class RedeployScriptInstallsTheDispatcherTests(unittest.TestCase):
    def test_redeploy_script_copies_the_template_unit(self):
        text = REDEPLOY.read_text(encoding="utf-8")
        self.assertIn("soc-alert-on-failure@.service", text)


class SlaMetricsStartupWarningTests(unittest.TestCase):
    """#554: an unprovisioned NTFY_TOPIC must be visible on every run, not
    just discoverable by someone who goes looking at docs or .env.example."""

    def test_main_warns_to_stderr_when_ntfy_topic_is_unset(self):
        text = SLO_METRICS_PY.read_text(encoding="utf-8")
        self.assertIn("NTFY_TOPIC is unset", text)
        self.assertIn("if not NTFY_TOPIC:", text)


class EnvExampleGuidanceTests(unittest.TestCase):
    def test_ntfy_topic_has_selection_guidance(self):
        example = (ROOT / "scripts" / "setup" / ".env.example").read_text(encoding="utf-8")
        lines = example.splitlines()
        idx = next(i for i, ln in enumerate(lines) if ln.startswith("NTFY_TOPIC="))
        preceding = "\n".join(lines[max(0, idx - 3):idx])
        self.assertIn("unguessable", preceding.lower())


class DispatcherFunctionalTests(unittest.TestCase):
    """Runs the real script behind a fake `curl`, so the test cannot open a
    socket no matter what the host's .env happens to contain."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = Path(self.tmp) / "bin"
        self.bin.mkdir()
        self.log = Path(self.tmp) / "curl.log"
        curl = self.bin / "curl"
        curl.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" >> {self.log}\nexit 0\n')
        curl.chmod(curl.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        # scripts/setup/.env is deliberately NOT written here — each test sets
        # NTFY_TOPIC directly via the process environment instead, since the
        # script only reads it FROM .env as a convenience and falls back to
        # whatever is already set (same `${NTFY_TOPIC:-}` pattern as
        # stack_health.sh).

    def _run(self, unit_name="slo-metrics.service", extra_env=None):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env.get('PATH', '')}"
        env.pop("NTFY_TOPIC", None)
        env.update(extra_env or {})
        return subprocess.run(["bash", str(DISPATCHER_SCRIPT), unit_name],
                              capture_output=True, text=True, timeout=30, env=env)

    def test_requires_a_unit_name_argument(self):
        r = subprocess.run(["bash", str(DISPATCHER_SCRIPT)],
                           capture_output=True, text=True, timeout=30)
        self.assertNotEqual(0, r.returncode)
        self.assertIn("usage:", r.stderr)

    def test_missing_ntfy_topic_warns_but_exits_zero(self):
        """The dispatcher itself must not become a second failure on top of
        the one it is reporting."""
        r = self._run()
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("NTFY_TOPIC is unset", r.stderr)
        self.assertIn("slo-metrics.service", r.stderr)
        self.assertFalse(self.log.exists(), "no ntfy call should be attempted with no topic")

    def test_configured_topic_posts_the_failed_unit_name(self):
        r = self._run(unit_name="zeek-host-capture.service",
                      extra_env={"NTFY_TOPIC": "test-topic-abc"})
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertTrue(self.log.exists(), "expected a curl call to be logged")
        logged = self.log.read_text()
        self.assertIn("ntfy.sh/test-topic-abc", logged)
        self.assertIn("zeek-host-capture.service", logged)

    def test_call_is_time_bounded(self):
        r = self._run(extra_env={"NTFY_TOPIC": "test-topic-abc"})
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("-m", self.log.read_text().split())

    def test_a_curl_failure_does_not_fail_the_dispatcher(self):
        curl = self.bin / "curl"
        curl.write_text("#!/bin/sh\nexit 7\n")
        curl.chmod(curl.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        r = self._run(extra_env={"NTFY_TOPIC": "test-topic-abc"})
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
