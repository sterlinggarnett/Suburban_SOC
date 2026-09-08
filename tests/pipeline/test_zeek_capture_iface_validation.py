#!/usr/bin/env python3
"""
Regression guard: a stale/wrong CAPTURE_IFACE pin must fail LOUDLY and
TERMINALLY, not crash-loop forever behind an `active` systemd status.

Observed live on this host 2026-09-05: `/etc/default/zeek-host-capture`
pinned `CAPTURE_IFACE=eth6`, but WSL2 renumbered the NICs across a reboot
and eth6 came back DOWN (the live LAN interface was eth4,
192.168.1.103/24, holding the default route). Every start therefore died
with:

    tcpdump: eth6: That device is not up
    fatal error in <params>, line 1: problem with trace file -
      (truncated dump file; tried to read 4 file header bytes, only got 0)

Two compounding effects kept that invisible for five days:

  1. `Restart=always` + `StartLimitIntervalSec=0` (both deliberate — the
     unit header explains the limiter must never give up while waiting for
     the Docker Desktop engine after boot) turned a PERMANENT config error
     into an unbounded crash loop; `systemctl is-active` reported `active`
     throughout, because systemd re-enters the active state between
     failures.
  2. Then it WEDGED. At restart #123 the dead tcpdump leg left `docker
     run` attached to a container whose Zeek had already exited, and that
     client never returns — so systemd parked the unit at `active
     (running)` indefinitely while capturing nothing. `set -o pipefail`
     cannot catch this; it only decides an exit status once the pipeline
     actually exits.

`StartLimitIntervalSec=0` is deliberate and must STAY, so the fix cannot
be "let the rate limiter fail the unit" — that would reintroduce the
boot race this repo already fixed. Instead the two failure classes are
separated by EXIT CODE:

  * Docker not reachable yet, transient errors -> ordinary non-zero exit
    -> `Restart=always` keeps retrying forever, exactly as today.
  * Pinned interface is not usable -> exit 78 (EX_CONFIG, sysexits.h)
    -> `RestartPreventExitStatus=78` parks the unit in `failed`, where
    `systemctl is-active` finally reports the truth.

The preflight lives in its own script (`capture_iface_preflight.sh`)
rather than inline in `host_capture.sh`, for the same reason #320 moved
the capture pipeline out of the unit's `ExecStart=` into a script: it
makes the logic runnable — and therefore testable — in isolation. Testing
the POSITIVE path by running `host_capture.sh` itself is not safe, because
past the preflight it invokes `docker run --name zeek-host-capture` and
would race the real service on this very host.

Interface-parsing cases run the real script against a fake `ip` on PATH,
the same technique tests/setup/test_setup_branch_protection.py uses for
`gh` and test_provision_error_handling.py uses for `curl` — deterministic
on any host, no root, no namespaces, no live NICs required.

Run:  python tests/pipeline/test_zeek_capture_iface_validation.py
      (or: pytest tests/pipeline)
"""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT_SH = ROOT / "scripts" / "setup" / "capture_iface_preflight.sh"
HOST_CAPTURE_SH_PATH = ROOT / "scripts" / "setup" / "host_capture.sh"
SERVICE_UNIT_PATH = ROOT / "configs" / "systemd" / "zeek-host-capture.service"
SERVICE_UNIT = SERVICE_UNIT_PATH.read_text(encoding="utf-8")

# sysexits.h EX_CONFIG — "configuration error". Chosen over a bespoke code
# so the meaning is legible to anyone reading the journal without this file
# in front of them.
EX_CONFIG = 78

# An interface name that cannot exist: it contains characters the kernel
# rejects in an interface name. Using an impossible name (rather than, say,
# "eth99") keeps the test deterministic on any host, including one that
# really does have a high-numbered NIC.
IMPOSSIBLE_IFACE = "soc-test-no-such-iface!"

# `lo` is up on every host this could ever run on, CI included, and needs
# no privileges to inspect.
ALWAYS_UP_IFACE = "lo"


def _fake_ip_script(diag_fails=False):
    """A fake `ip` serving one canned `link show dev` line.

    `diag_fails=True` additionally makes the two commands used only by the
    failure DIAGNOSTIC (`link show up`, `route show default`) exit non-zero,
    which is how a missing/erroring `ip` behaves in production.

    Built by concatenation rather than f-strings on purpose: escape
    sequences inside f-string expressions are PEP 701 syntax, valid on
    Python 3.12 but a SyntaxError on the 3.11 that CI runs.
    """
    up_cmd = 'echo "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536"'
    route_cmd = 'echo "default via 192.168.1.1 dev eth4"'
    if diag_fails:
        up_cmd = route_cmd = "exit 7"
    return (
        '#!/bin/bash\n'
        'case "$*" in\n'
        '  *"link show dev"*) printf "%s\\n" "$FAKE_IP_LINE" ;;\n'
        '  *"link show up"*) ' + up_cmd + ' ;;\n'
        '  *"route show default"*) ' + route_cmd + ' ;;\n'
        '  *) exit 1 ;;\n'
        'esac\n')


def _run_preflight(iface, wait_secs="0", fake_ip_line=None, timeout=20,
                   diag_fails=False):
    """Run the real preflight script against `iface`.

    When `fake_ip_line` is given, a fake `ip` is placed first on PATH and
    serves that single line as the output of `ip -o link show dev ...`,
    so flag-parsing can be exercised against crafted kernel output that
    would otherwise need root and a synthetic netdev to reproduce.
    """
    env = dict(os.environ)
    if wait_secs is not None:
        env["SOC_IFACE_WAIT_SECS"] = wait_secs
    with tempfile.TemporaryDirectory() as shim_dir:
        if fake_ip_line is not None:
            fake_ip = Path(shim_dir) / "ip"
            fake_ip.write_text(_fake_ip_script(diag_fails), encoding="utf-8")
            fake_ip.chmod(fake_ip.stat().st_mode | stat.S_IXUSR)
            env["PATH"] = f"{shim_dir}{os.pathsep}{env.get('PATH', '')}"
            env["FAKE_IP_LINE"] = fake_ip_line
        return subprocess.run(
            ["/bin/bash", str(PREFLIGHT_SH), iface],
            capture_output=True, text=True, timeout=timeout, env=env)


def _first_executable_line(path, token):
    """Line number of the first NON-COMMENT line containing `token`.

    Ordering assertions must reflect EXECUTION order, not text order — the
    scripts here carry long explanatory headers that legitimately mention
    commands (`/usr/bin/tcpdump`, `PATH=`) well before the line that runs
    them, so a raw `str.find` would compare prose against code.
    """
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        if token in line:
            return n
    return None


class UnusableCaptureInterfaceFailsTerminallyTests(unittest.TestCase):
    def test_preflight_exits_with_ex_config_when_the_pinned_interface_cannot_exist(self):
        # The core property: an unusable pin is reported as a CONFIGURATION
        # error via a distinct exit code, so systemd can tell it apart from
        # the transient "Docker isn't up yet" case that must keep retrying.
        proc = _run_preflight(IMPOSSIBLE_IFACE)
        self.assertEqual(
            EX_CONFIG, proc.returncode,
            "preflight should exit 78 (EX_CONFIG) when the pinned capture "
            "interface is not usable, so RestartPreventExitStatus=78 can "
            "park the unit in `failed` instead of crash-looping it forever. "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}")

    def test_preflight_names_the_offending_interface_and_lists_live_candidates(self):
        # The 2026-09-05 outage took five days to notice and ~30 seconds to
        # diagnose once someone ran `ip -br link`. The failure message must
        # carry that diagnosis itself: which interface was pinned, and which
        # interfaces are actually up right now to pin instead.
        proc = _run_preflight(IMPOSSIBLE_IFACE)
        combined = proc.stdout + proc.stderr
        self.assertIn(IMPOSSIBLE_IFACE, combined,
                      "the failure message should quote the interface that "
                      f"was actually pinned. Got: {combined!r}")
        self.assertIn("/etc/default/zeek-host-capture", combined,
                      "the failure message should point at the file the "
                      f"operator has to edit. Got: {combined!r}")
        self.assertRegex(
            combined, r"(?i)(candidate|available|currently up|interfaces up)",
            "the failure message should list the interfaces that are "
            f"currently up, so the fix is obvious from the journal. Got: {combined!r}")


    def test_an_empty_interface_pin_is_also_a_terminal_config_error(self):
        # `CAPTURE_IFACE=` (a plausible env-file typo or truncation, and
        # equally a deliberate one-character sabotage) makes systemd pass a
        # single empty argv word. A bare `${1:?...}` would exit 1, not 78,
        # so Restart=always loops on it forever behind `active` — the same
        # permanent-config-error class the fix exists to make visible.
        proc = _run_preflight("")
        self.assertEqual(
            EX_CONFIG, proc.returncode,
            "an empty CAPTURE_IFACE must reach the same terminal exit 78 as "
            f"any other unusable pin. stdout={proc.stdout!r} stderr={proc.stderr!r}")


class UsableCaptureInterfacePassesTests(unittest.TestCase):
    """The other half of the property — without these, an `iface_is_up`
    that simply always returned false would satisfy every test above while
    parking a PERFECTLY HEALTHY unit in `failed` forever (worse than the
    original bug, because RestartPreventExitStatus makes it permanent)."""

    def test_preflight_accepts_an_interface_that_is_really_up(self):
        proc = _run_preflight(ALWAYS_UP_IFACE)
        self.assertEqual(
            0, proc.returncode,
            f"preflight rejected {ALWAYS_UP_IFACE!r}, which is up on every "
            "host — the check is failing closed on healthy configuration. "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}")
        self.assertNotIn("FATAL", proc.stdout + proc.stderr)

    def test_preflight_accepts_a_normal_up_interface_from_kernel_output(self):
        # Pinned against real `ip -o link show dev` output shape, so the
        # parser is exercised independently of whatever NICs this host has.
        proc = _run_preflight(
            "eth4",
            fake_ip_line=("2: eth4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 "
                          "qdisc mq state UP mode DEFAULT group default qlen 1000"
                          "\\    link/ether f8:cf:52:ff:9f:06 brd ff:ff:ff:ff:ff:ff"))
        self.assertEqual(0, proc.returncode,
                         f"stdout={proc.stdout!r} stderr={proc.stderr!r}")


class InterfaceFlagParsingTests(unittest.TestCase):
    def test_a_down_interface_is_rejected(self):
        # The exact shape of the interface that caused the outage.
        proc = _run_preflight(
            "eth6",
            fake_ip_line=("9: eth6: <BROADCAST,MULTICAST> mtu 1500 qdisc noop "
                          "state DOWN mode DEFAULT group default qlen 1000"
                          "\\    link/ether fa:cf:52:ff:9f:06 brd ff:ff:ff:ff:ff:ff"))
        self.assertEqual(EX_CONFIG, proc.returncode,
                         "a DOWN interface must be rejected — this is the "
                         "literal 2026-09-05 outage condition. "
                         f"stdout={proc.stdout!r} stderr={proc.stderr!r}")

    def test_an_interface_alias_containing_angle_brackets_cannot_fake_the_up_flag(self):
        # `ip -o link show` inlines the interface ALIAS onto the same line.
        # A greedy `.*<` in the flag extraction captures the LAST <...>
        # group on the line rather than the kernel flags field, so an alias
        # like "rack<A,UP>" makes a genuinely DOWN interface parse as up —
        # silently defeating the entire fix (no exit 78, no diagnostic, no
        # crash loop, just a false pass straight into a dead capture).
        # Bracketed asset-tag/rack aliases are a real convention, so this
        # is a live hazard, not a theoretical one.
        proc = _run_preflight(
            "eth6",
            fake_ip_line=("9: eth6: <BROADCAST,MULTICAST> mtu 1500 qdisc noop "
                          "state DOWN mode DEFAULT group default qlen 1000"
                          "\\    link/ether fa:cf:52:ff:9f:06 brd ff:ff:ff:ff:ff:ff"
                          "\\    alias rack<A,UP>note"))
        self.assertEqual(
            EX_CONFIG, proc.returncode,
            "a DOWN interface whose ALIAS contains '<...,UP>' was accepted — "
            "the flag extraction is matching the alias instead of the kernel "
            "flags field. Anchor it to the FIRST <...> group. "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}")

    def test_lower_up_alone_does_not_satisfy_the_up_flag_check(self):
        # Guards the comma-padding in the `,${flags},` / `*,UP,*` match:
        # without it, the substring "UP" inside "LOWER_UP" would match.
        proc = _run_preflight(
            "eth7",
            fake_ip_line="3: eth7: <BROADCAST,MULTICAST,LOWER_UP> mtu 1500")
        self.assertEqual(EX_CONFIG, proc.returncode,
                         "LOWER_UP without UP must not count as up. "
                         f"stdout={proc.stdout!r} stderr={proc.stderr!r}")

    def test_an_up_interface_without_carrier_is_accepted_but_warned_about(self):
        # Deliberate design call, documented in the script: carrier can drop
        # at ANY time after the preflight passes, so no start-time check can
        # own it — sustained-zero-packets is the capture-loss monitor's job.
        # Making NO-CARRIER terminal would also risk permanently parking
        # device types that never report carrier. So: accept, but say so.
        proc = _run_preflight(
            "eth4",
            fake_ip_line=("2: eth4: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 "
                          "qdisc mq state LOWERLAYERDOWN mode DEFAULT"))
        self.assertEqual(0, proc.returncode,
                         "an administratively-up interface should still be "
                         "accepted even without carrier. "
                         f"stdout={proc.stdout!r} stderr={proc.stderr!r}")
        self.assertRegex(
            proc.stdout + proc.stderr, r"(?i)(carrier|no-carrier)",
            "the preflight should WARN that the interface has no carrier — "
            "it will capture zero packets until the link comes up, and that "
            "is exactly the silent-failure shape this fix exists to surface")


class WaitValueHandlingTests(unittest.TestCase):
    """`SOC_IFACE_WAIT_SECS` is NOT a trusted knob.

    `zeek-host-capture.service` loads `EnvironmentFile=-/etc/default/
    zeek-host-capture`, which injects ARBITRARY variables into the unit's
    environment — not just `CAPTURE_IFACE`. So this value is reachable by
    anyone who can write that file, and two payloads both recreate the very
    outage this changeset exists to close:

      * `SOC_IFACE_WAIT_SECS=999999999` — the preflight sleeps for ~31
        years while `Type=simple` reports `active (running)`. The original
        invisible outage, restored with a one-line edit and no crash loop
        at all.
      * `SOC_IFACE_WAIT_SECS=abc` — `[ "$waited" -ge "abc" ]` makes bash's
        `test` print "integer expression expected" and return 2. As an
        `if` CONDITION that is exempt from `set -e`, so the comparison is
        simply always false and the loop spins forever, one journal line
        per second, rolling the journal and destroying prior evidence.

    Deliberate design call, and NOT what a first review suggested: a
    malformed value must NOT itself exit 78. Doing so would hand anyone
    with write access to that env file a one-character permanent sensor
    kill — strictly worse than the bug being fixed. Instead a bad value
    loses its grace period (falls to 0: check once, fail fast) and a large
    one is clamped, both with a loud warning. A garbage value can then
    never buy silence, and never parks a healthy sensor.
    """

    def test_a_non_numeric_wait_value_fails_fast_instead_of_spinning_forever(self):
        try:
            proc = _run_preflight(IMPOSSIBLE_IFACE, wait_secs="30s", timeout=25)
        except subprocess.TimeoutExpired:
            self.fail("preflight hung on a non-numeric SOC_IFACE_WAIT_SECS "
                      "instead of failing fast — this is the infinite-spin "
                      "wedge the fix is supposed to prevent")
        self.assertEqual(
            EX_CONFIG, proc.returncode,
            "with a garbage wait value and an unusable interface the "
            "preflight should still reach its terminal exit 78 promptly. "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}")

    def test_a_non_numeric_wait_value_does_not_park_an_otherwise_healthy_sensor(self):
        # The anti-DoS half: a typo in an unrelated tuning knob must not
        # take the capture lane down when the interface is perfectly fine.
        proc = _run_preflight(ALWAYS_UP_IFACE, wait_secs="30s", timeout=25)
        self.assertEqual(
            0, proc.returncode,
            "a malformed SOC_IFACE_WAIT_SECS must not fail a healthy "
            "interface — that would turn a one-character env-file edit into "
            f"a permanent sensor kill. stdout={proc.stdout!r} stderr={proc.stderr!r}")
        self.assertRegex(proc.stdout + proc.stderr, r"(?i)(warn|invalid|ignor)",
                         "a malformed wait value should be warned about, not "
                         "silently accepted")

    def test_an_absurdly_large_wait_value_is_clamped(self):
        # Without a clamp this sleeps for ~31 years behind `active (running)`.
        proc = _run_preflight(ALWAYS_UP_IFACE, wait_secs="999999999", timeout=25)
        self.assertEqual(0, proc.returncode,
                         f"stdout={proc.stdout!r} stderr={proc.stderr!r}")
        self.assertRegex(
            proc.stdout + proc.stderr, r"(?i)(clamp|capped|maximum|too large)",
            "an out-of-range wait value should be clamped with a warning, so "
            "it cannot hold the unit at `active (running)` indefinitely. "
            f"Got: {(proc.stdout + proc.stderr)!r}")

    def test_the_wait_value_is_never_arithmetic_evaluated(self):
        # `[ x -ge y ]` parses operands with legal_number() and ERRORS on
        # garbage — safe. But `[[ x -ge y ]]` and `(( x >= y ))` perform
        # ARITHMETIC EVALUATION on their operands, under which a value like
        # `a[$(id)]` executes the substitution AS ROOT. The current form is
        # the correct one; pin it so a future "cleanup" to the more modern
        # -looking `[[ ]]` / `(( ))` cannot silently open that door.
        text = PREFLIGHT_SH.read_text(encoding="utf-8")
        self.assertNotRegex(
            text, r"\[\[[^\]]*-ge[^\]]*IFACE_WAIT_SECS",
            "the wait value must not be compared inside [[ ... ]] — that is "
            "an arithmetic context and would evaluate attacker-supplied "
            "text as code")
        self.assertNotRegex(
            text, r"\(\([^)]*IFACE_WAIT_SECS",
            "the wait value must not appear inside (( ... )) — arithmetic "
            "evaluation of an env-file-supplied value runs code as root")


class DiagnosticCannotPreemptTheTerminalExitTests(unittest.TestCase):
    def test_a_failing_ip_during_the_diagnostic_still_yields_exit_78(self):
        # A bare `var="$(cmd | ...)"` assignment takes the substitution's
        # exit status, and under `set -euo pipefail` a non-zero one exits
        # the script IMMEDIATELY with that status — before `exit 78` is
        # reached. So if `ip` is missing from PATH (127) or errors, the
        # diagnostic block itself would preempt the terminal exit, making
        # RestartPreventExitStatus=78 inert and restoring the unbounded
        # crash loop behind `active`. shellcheck does NOT catch this:
        # SC2155 only fires for local/export/declare.
        proc = _run_preflight(
            "eth6",
            fake_ip_line="9: eth6: <BROADCAST,MULTICAST> mtu 1500",
            diag_fails=True)
        self.assertEqual(
            EX_CONFIG, proc.returncode,
            "the failure diagnostic swallowed the terminal exit code — a "
            "command failing inside the diagnostic must never preempt "
            f"exit 78. stdout={proc.stdout!r} stderr={proc.stderr!r}")


class HostCaptureRunsThePreflightFirstTests(unittest.TestCase):
    def test_host_capture_invokes_the_preflight_before_the_capture_pipeline(self):
        # A bad pin must be rejected before any capture machinery starts,
        # otherwise a wrong interface still leaves a half-built container
        # behind on every restart — which is precisely how the wedged
        # container ba3b492f9bfb came to exist during the outage.
        preflight_at = _first_executable_line(HOST_CAPTURE_SH_PATH,
                                              "capture_iface_preflight.sh")
        tcpdump_at = _first_executable_line(HOST_CAPTURE_SH_PATH, "/usr/bin/tcpdump")
        self.assertIsNotNone(preflight_at,
                             "host_capture.sh no longer invokes "
                             "capture_iface_preflight.sh at all")
        self.assertIsNotNone(tcpdump_at, "host_capture.sh no longer runs tcpdump")
        self.assertLess(preflight_at, tcpdump_at,
                        "the interface preflight must run BEFORE the "
                        "tcpdump|docker capture pipeline")

    def test_the_preflight_is_invoked_through_an_explicit_interpreter(self):
        # This repo sets core.fileMode=false and tracks every scripts/setup/
        # script as mode 100644, so the executable bit is not carried by git.
        # Invoking the preflight as `"${SCRIPT_DIR}/capture_iface_preflight.sh"`
        # therefore works only on a host that happened to chmod it locally;
        # a fresh clone gets "Permission denied" and the capture lane refuses
        # to start. The unit's own ExecStart= avoids this the same way, with
        # an explicit `/bin/bash`.
        line_no = _first_executable_line(HOST_CAPTURE_SH_PATH,
                                         "capture_iface_preflight.sh")
        self.assertIsNotNone(line_no, "host_capture.sh no longer invokes the preflight")
        line = HOST_CAPTURE_SH_PATH.read_text(encoding="utf-8").splitlines()[line_no - 1]
        self.assertRegex(
            line.strip(), r"^(/bin/)?bash\s",
            "the preflight must be run through an explicit bash interpreter, "
            "not relied on to be executable — git does not carry the exec bit "
            f"for this repo's scripts. Got: {line.strip()!r}")

    def test_host_capture_pins_path_before_invoking_anything(self):
        # The unit's EnvironmentFile can set PATH= for the whole service,
        # and systemd honours it — so a bare `ip`/`sed`/`awk`/`head`/`sleep`
        # would resolve through an operator-supplied PATH while running as
        # root with CAP_NET_RAW/CAP_NET_ADMIN/CAP_SETUID in the bounding
        # set (T1574.007). Root->root rather than a privilege escalation,
        # but it regresses this file's own convention of absolute paths
        # (/usr/bin/tcpdump, /usr/bin/docker) and widens the exposure.
        # Pinning PATH once at the systemd entry point covers every command
        # downstream, including the preflight it invokes.
        path_at = _first_executable_line(HOST_CAPTURE_SH_PATH, "PATH=")
        preflight_at = _first_executable_line(HOST_CAPTURE_SH_PATH,
                                              "capture_iface_preflight.sh")
        self.assertIsNotNone(path_at,
                             "host_capture.sh should pin PATH so the unit's "
                             "EnvironmentFile cannot redirect root-executed "
                             "helper binaries")
        self.assertIsNotNone(preflight_at, "host_capture.sh no longer invokes the preflight")
        self.assertLess(path_at, preflight_at,
                        "PATH must be pinned BEFORE the preflight runs")

    def test_the_capture_pipeline_can_never_mint_the_terminal_exit_code(self):
        # `set -o pipefail` makes the pipeline's status the script's status,
        # and `docker run` returns the CONTAINER's exit code verbatim
        # (Docker reserves only 125/126/127 for itself). Zeek's status comes
        # from the policy chain in /data/intel/config.zeek, which the unit
        # re-copies from a repo checkout on every restart. So a Zeek-side 78
        # would convert a self-healing crash loop into a permanently
        # `failed` unit that never restarts on its own — strictly better for
        # an attacker than the pre-change behaviour (T1562.001). 78 must be
        # reserved to the preflight and unforgeable from downstream.
        text = HOST_CAPTURE_SH_PATH.read_text(encoding="utf-8")
        self.assertRegex(
            text, r"EX_CONFIG.*\n?.*rc=1|rc=1.*EX_CONFIG",
            "host_capture.sh must remap a downstream exit 78 (from tcpdump, "
            "docker or the Zeek container) to an ordinary failure, so only "
            "the preflight can trigger RestartPreventExitStatus=78")


class SystemdTreatsAConfigErrorAsTerminalTests(unittest.TestCase):
    def _directive(self, name):
        return [ln.strip() for ln in SERVICE_UNIT.splitlines()
                if ln.strip().startswith(f"{name}=")]

    def test_unit_marks_the_config_exit_code_as_restart_preventing(self):
        # Without this, the preflight's exit 78 is just another non-zero
        # exit and Restart=always loops on it forever — i.e. the whole fix
        # would be inert.
        self.assertIn(
            f"RestartPreventExitStatus={EX_CONFIG}",
            self._directive("RestartPreventExitStatus"),
            "zeek-host-capture.service must set "
            f"RestartPreventExitStatus={EX_CONFIG} so an unusable "
            "CAPTURE_IFACE parks the unit in `failed` instead of "
            "crash-looping behind an `active` status")

    def test_unit_retries_long_enough_to_outlast_the_docker_boot_race(self):
        # Guards the other half of the tension: the Docker-Desktop boot race
        # this unit's header documents must survive. This originally required
        # StartLimitIntervalSec=0 (retry forever). Changed by owner decision
        # 2026-09-07 after the unit spent ~26h in an unbounded loop (1181+
        # restarts, no capture, nothing resting in `failed` to notice): the
        # limiter is now bounded generously rather than disabled, so the boot
        # race is still covered but the "retry forever" tail is not.
        #
        # The boot-race protection is now asserted by ARITHMETIC rather than by
        # the absence of a limiter — burst x RestartSec must still exceed a
        # slow engine start — so this keeps testing the property that mattered
        # instead of the specific mechanism that used to provide it.
        self.assertIn("Restart=always", self._directive("Restart"),
                      "Restart=always must stay — the unit waits out the "
                      "Docker Desktop engine with it")
        intervals = self._directive("StartLimitIntervalSec")
        self.assertTrue(intervals, "the unit must declare StartLimitIntervalSec")
        self.assertNotIn("StartLimitIntervalSec=0", intervals,
                         "StartLimitIntervalSec=0 disables the limiter, so a "
                         "permanently failing ExecStartPre retries forever — it "
                         "can neither park via RestartPreventExitStatus (which "
                         "covers only the MAIN process) nor exhaust a limiter")
        window = int(intervals[0].split("=", 1)[1])
        burst = int(self._directive("StartLimitBurst")[0].split("=", 1)[1])
        restart_sec = int(self._directive("RestartSec")[0].split("=", 1)[1])
        self.assertGreaterEqual(
            burst * restart_sec, 600,
            f"{burst} restarts x {restart_sec}s = {burst * restart_sec}s is too "
            "short to ride out a Docker Desktop cold start — the boot race this "
            "test exists to protect")
        self.assertLessEqual(
            burst * restart_sec, window,
            "the burst must be exhaustible inside its own StartLimitIntervalSec "
            "window, or the limiter can never trip and nothing is bounded")


if __name__ == "__main__":
    unittest.main(verbosity=2)
