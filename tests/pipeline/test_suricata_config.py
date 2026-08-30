#!/usr/bin/env python3
"""
#443: Suricata boundary-tap sensor deployment — the first step of M23 (the
Suricata Signature Lane). Ships a real, structurally-verified config +
systemd unit for running Suricata (host package, not a Docker container —
see configs/suricata/suricata.yaml's own header for why) alongside Zeek on
the same capture interface, in IDS/EVE mode.

Static structure tests for the three pieces this fix touches:

  1. configs/suricata/suricata.yaml — HOME_NET pinned to the two real mesh
     subnets this repo's own capture tooling already names
     (scripts/setup/stream_capture.sh), eve-log enabled with bounded
     rotation, af-packet interface documented as CLI-overridden, and
     default-rule-path pointed at this repo's own rules/suricata/ tree
     (detection-as-code, not suricata-update against a live host path).
  2. configs/systemd/suricata-host-capture.service — modeled on
     zeek-host-capture.service: CAPTURE_IFACE env-var override convention,
     Restart=always/StartLimitIntervalSec=0, CapabilityBoundingSet=
     narrowing instead of a full unprivileged-user drop (this repo's own
     zeek unit has a documented, reverted sandboxing attempt — #182 — so
     this unit deliberately does not repeat an untested attempt).
  3. scripts/setup/redeploy_systemd_units.sh — the new unit wired into the
     same install/restart-prompt/verify loop zeek-host-capture.service and
     slo-metrics.service already use.

Pure stdlib, static text/regex assertions against the real config files —
no live systemd/capture host, matching this directory's established
convention (see test_auditd_execve_telemetry.py, test_mac_correlation.py).

One test in ConfigSyntaxTests actually invokes a real `suricata -T` binary
if one is installed (this sandbox has Suricata 7.0.3 from apt) — genuine
local verification the auditd telemetry work before it could not get.
SKIPS (does not fail) if the binary isn't present, same convention
test_zeek_mime_detection.py uses for its own environment-dependent check.

NOT exercised against a live capture host in the environment this was
authored in — no real interface to bind to, no way to measure CPU headroom
alongside Zeek (#443's own flagged, unmeasured resource risk), no way to
confirm reboot survival. See coverage_checklist.md's Suricata section.

Run:  python tests/pipeline/test_suricata_config.py
      (or: pytest tests/pipeline)
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SURICATA_YAML_PATH = ROOT / "configs" / "suricata" / "suricata.yaml"
SURICATA_YAML = SURICATA_YAML_PATH.read_text(encoding="utf-8")
SYSTEMD_UNIT_PATH = ROOT / "configs" / "systemd" / "suricata-host-capture.service"
SYSTEMD_UNIT = SYSTEMD_UNIT_PATH.read_text(encoding="utf-8")
# The real unit body, excluding the extensive header-comment prose above
# "[Unit]" — that prose deliberately discusses (in English, to explain the
# decision) directives and flags the unit itself does NOT use, so any
# "must not contain X" assertion has to be scoped here or it will false-
# match its own explanatory comments.
SYSTEMD_UNIT_BODY = SYSTEMD_UNIT[SYSTEMD_UNIT.index("[Unit]"):]
REDEPLOY_SCRIPT = (ROOT / "scripts" / "setup" / "redeploy_systemd_units.sh").read_text(encoding="utf-8")
LOCAL_RULES_PATH = ROOT / "rules" / "suricata" / "local.rules"


class SuricataYamlHomeNetTests(unittest.TestCase):
    def test_home_net_pinned_to_real_mesh_subnets(self):
        # scripts/setup/stream_capture.sh's own two real capture modes:
        # bat0 (10.18.81.1) and br-lan (192.168.1.233) — not the upstream
        # default's RFC1918-wide sweep.
        self.assertIn('HOME_NET: "[10.18.81.0/24,192.168.1.0/24]"', SURICATA_YAML)

    def test_upstream_default_left_as_a_documented_alternative_not_deleted(self):
        self.assertIn("192.168.0.0/16,10.0.0.0/8,172.16.0.0/12", SURICATA_YAML)


class SuricataYamlOutputTests(unittest.TestCase):
    def test_eve_log_enabled(self):
        idx = SURICATA_YAML.index("eve-log:")
        block = SURICATA_YAML[idx:idx + 400]
        self.assertIn("enabled: yes", block)
        self.assertIn('filename: eve.json', block)

    def test_eve_log_rotation_bounded(self):
        # #443 scope: "log rotation bounded for the capture host's disk".
        idx = SURICATA_YAML.index("eve-log:")
        block = SURICATA_YAML[idx:idx + 800]
        self.assertIn("rotate-interval: day", block)

    def test_default_log_dir_matches_zeek_storage_convention(self):
        # Mirrors Zeek's LOG_DIR default (/storage/PCAP/zeek_logs) so both
        # sensors' output lives under the same tree Filebeat already tails.
        self.assertIn("default-log-dir: /storage/PCAP/suricata/", SURICATA_YAML)


class SuricataYamlCaptureAndRulesTests(unittest.TestCase):
    def test_af_packet_interface_documents_cli_override(self):
        idx = SURICATA_YAML.index("af-packet:")
        block = SURICATA_YAML[idx:idx + 600]
        self.assertIn("interface: eth0", block)
        self.assertIn("CAPTURE_IFACE", block)

    def test_default_rule_path_is_repo_relative_not_var_lib(self):
        # Detection-as-code: rules checked into this repo (rules/sigma/'s
        # own precedent), not managed against /var/lib/suricata/rules.
        self.assertIn("default-rule-path: rules/suricata/", SURICATA_YAML)
        self.assertNotIn("default-rule-path: /var/lib/suricata/rules", SURICATA_YAML)

    def test_rule_files_references_local_rules(self):
        idx = SURICATA_YAML.index("rule-files:")
        block = SURICATA_YAML[idx:idx + 700]
        self.assertIn("local.rules", block)

    def test_local_rules_placeholder_exists_on_disk(self):
        # rule-files above references local.rules — it must actually exist,
        # or `suricata -T` fails to load (verified in ConfigSyntaxTests).
        self.assertTrue(LOCAL_RULES_PATH.is_file())


class SystemdUnitTests(unittest.TestCase):
    def test_capture_iface_env_var_override_convention(self):
        self.assertIn("Environment=CAPTURE_IFACE=eth0", SYSTEMD_UNIT)
        self.assertIn("EnvironmentFile=-/etc/default/suricata-host-capture", SYSTEMD_UNIT)

    def test_restart_always_no_rate_limit(self):
        # Same crash-loop-tolerant posture as zeek-host-capture.service —
        # required for metric_suricata_ingest_lag_seconds() (slo_metrics.py)
        # to be the thing that actually catches a dead sensor, since
        # Restart=always/StartLimitIntervalSec=0 means it never reaches
        # systemd's own `failed` state.
        self.assertIn("Restart=always", SYSTEMD_UNIT)
        self.assertIn("StartLimitIntervalSec=0", SYSTEMD_UNIT)

    def test_capability_bounding_set_narrowed_not_full_root(self):
        self.assertIn("CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN", SYSTEMD_UNIT)

    def test_no_untested_sandboxing_directives_copied_from_stock_unit(self):
        # #182's own lesson, deliberately not repeated here — see this
        # unit's header comment for the reverted zeek-host-capture.service
        # sandboxing attempt this is avoiding blindly copying.
        self.assertNotIn("ProtectSystem=", SYSTEMD_UNIT_BODY)
        self.assertNotIn("ProtectHome=", SYSTEMD_UNIT_BODY)

    def test_exec_start_uses_af_packet_override_and_absolute_paths(self):
        self.assertIn("--af-packet=${CAPTURE_IFACE}", SYSTEMD_UNIT)
        self.assertIn("${SOC_REPO}/configs/suricata/suricata.yaml", SYSTEMD_UNIT)
        self.assertIn("default-rule-path=${SOC_REPO}/rules/suricata/", SYSTEMD_UNIT)

    def test_type_simple_no_daemonize_flag(self):
        # Foreground under systemd supervision, matching zeek-host-capture.
        # service's own Type=simple choice — not the stock package unit's
        # Type=forking + -D + PIDFile pattern. Checked on the actual
        # ExecStart= line specifically, not the surrounding body text,
        # since the body's own explanatory comment legitimately mentions
        # "-D" in prose (why it's NOT used) without that being a real flag.
        self.assertIn("Type=simple", SYSTEMD_UNIT_BODY)
        exec_start_line = next(
            line for line in SYSTEMD_UNIT_BODY.splitlines() if line.startswith("ExecStart=")
        )
        self.assertNotIn(" -D", exec_start_line)
        self.assertFalse(
            any(line.startswith("PIDFile=") for line in SYSTEMD_UNIT_BODY.splitlines())
        )


class RedeploySystemdUnitsWiringTests(unittest.TestCase):
    def test_unit_copied_into_etc_systemd(self):
        self.assertIn(
            "sudo cp configs/systemd/suricata-host-capture.service "
            "/etc/systemd/system/suricata-host-capture.service",
            REDEPLOY_SCRIPT,
        )

    def test_unit_included_in_before_and_after_security_scores(self):
        occurrences = REDEPLOY_SCRIPT.count(
            "systemd-analyze security --no-pager suricata-host-capture.service"
        )
        # Once in "Before scores", once in "After scores" — same treatment
        # zeek-host-capture.service and slo-metrics.service already get.
        self.assertEqual(occurrences, 2)

    def test_unit_gets_its_own_restart_prompt(self):
        self.assertIn("Restarting suricata-host-capture.service", REDEPLOY_SCRIPT)
        self.assertIn("sudo systemctl restart suricata-host-capture.service", REDEPLOY_SCRIPT)


class ConfigSyntaxTests(unittest.TestCase):
    """Real `suricata -T` validation, not just structural text assertions —
    possible here because #443 chose host-package deployment specifically
    so this could run without a Docker daemon (see suricata.yaml's header).
    SKIPS, does not fail, if suricata isn't installed — same convention
    test_zeek_mime_detection.py uses for its own real-image invocation."""

    def test_suricata_dash_t_accepts_the_real_config(self):
        suricata_bin = shutil.which("suricata")
        if not suricata_bin:
            self.skipTest("suricata binary not installed in this environment")
        with tempfile.TemporaryDirectory() as log_dir:
            result = subprocess.run(
                [
                    suricata_bin, "-T",
                    "-c", str(SURICATA_YAML_PATH),
                    "-l", log_dir,
                    "--af-packet=lo",
                    "--set", f"default-rule-path={LOCAL_RULES_PATH.parent}",
                ],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(
                result.returncode, 0,
                f"suricata -T failed:\nstdout: {result.stdout}\nstderr: {result.stderr}",
            )
            self.assertIn("Configuration provided was successfully loaded", result.stdout)


if __name__ == "__main__":
    unittest.main()
