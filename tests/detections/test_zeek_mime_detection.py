#!/usr/bin/env python3
"""
test_zeek_mime_detection.py — issue #411: a permanent, re-runnable regression
owner for Zeek's own MIME-detection behavior.

#365 (HTTP) and #382 (SMTP) each live-verified Zeek's real content-magic
mime_type output against the pinned zeek/zeek image ONCE, by hand, and baked
the findings into net_zeek_executable_download.yml/
net_zeek_smtp_attachment_executable.yml's mime_type lists and descriptions.
Neither pass left anything that re-derives ground truth from Zeek itself: a
future image bump that silently changes what Zeek types a real payload as
(the exact class of bug #293/test_zeek_image_pin.py's own header describes
happening once already, for a different Zeek-generated string) would pass
every existing test unchanged, because tests/detections/test_sigma_detections.py
and tests/detections/test_live_fire.py both pin RULE CONTENT and FIXTURE DATA,
never Zeek's own live behavior.

This module closes that gap the same way test_live_fire.py (#221/#387) closed
the analogous "does the real backend actually behave the way we assumed" gap
for Elasticsearch: a real client and a real server exchange real payload
bytes over a real loopback TCP connection, tcpdump captures the real wire
traffic, and the pinned zeek/zeek image (same EXPECTED_TAG/EXPECTED_DIGEST as
tests/pipeline/test_zeek_image_pin.py — bump both together) replays it for
real, exactly as production's offline-PCAP path
(scripts/setup/zeek_run_pcap.sh) does. No hand-crafted packet bytes: the OS
TCP/IP stack builds every header, tcpdump captures exactly what really went
on the wire, and Zeek's own file-analysis framework does the typing — the
same three-real-processes-one-capture shape findings/20260817-384-mime-type-
coverage.md used, just with the server+client+capture on the test runner
instead of nested inside one container (avoids depending on whatever tools
happen to ship inside the minimal zeek/zeek image itself).

Two logsource-specific scenarios, matching the two rules' assumptions:
  - HTTP:  a real `http.server` serves a real shell-script payload; a real
    `curl` fetches it. Asserts files.log types it `text/x-shellscript`
    (net_zeek_executable_download.yml's mime_type list depends on this).
  - SMTP:  a real stdlib `smtpd.SMTPServer` accepts a real `smtplib` session
    carrying the same payload as a base64 MIME attachment. Asserts BOTH
    `mime_type: text/x-shellscript` (content-magic is transport-agnostic,
    #382's own finding) AND `source: SMTP` (#382's specific, independently-
    verified claim that Zeek tags every extracted file with the protocol
    that carried it — net_zeek_smtp_attachment_executable.yml's
    selection_transport depends on this exact field/value).

Python-version note: smtpd/asyncore are deprecated and removed in Python
3.12 — fine while pyproject.toml pins requires-python "<3.12", but a future
bump to 3.12+ needs the SMTP scenario rewritten onto aiosmtpd (the module's
own documented replacement) alongside every other 3.12-blocking change that
bump would need repo-wide.

SKIPPED (not failed) — mirroring test_live_fire.py's own convention — if:
  - the `docker` or `tcpdump` binaries aren't on PATH,
  - the Docker daemon isn't reachable,
  - the pinned zeek/zeek image can't be run (not pulled, no network to pull
    it, wrong architecture, etc.)
so `pytest tests/` stays runnable with no Docker daemon and no raw-capture
privileges. Wired into the same non-required CI `live-fire` job as
test_live_fire.py (.github/workflows/detections.yml), NOT the required,
no-path-filter `detections` job's `tests/pipeline -q` glob — a Docker
image-pull or tcpdump-permission flake here must never block an unrelated
PR, the identical reasoning that job split already documents for
Elasticsearch container-pull flakiness.

Run:  pytest tests/detections/test_zeek_mime_detection.py -v
"""
import json
import shutil
import smtpd
import smtplib
import socket
import subprocess
import sys
import threading
import time
import unittest
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional

# Same pin tests/pipeline/test_zeek_image_pin.py enforces across the 4 real
# production capture paths — duplicated here with this cross-reference
# rather than imported, matching this repo's existing pattern of
# duplicating this exact pin per invocation site (each one documents the
# cross-check in its own comment; test_zeek_image_pin.py is what actually
# catches drift between them). Bump both together.
EXPECTED_TAG = "8.2.1"
EXPECTED_DIGEST = "sha256:eca2b3915d3e067cbb4a904f23f4c4f461ea2b60613ab30f7ee77bbc707c87c7"
ZEEK_IMAGE = f"zeek/zeek:{EXPECTED_TAG}@{EXPECTED_DIGEST}"

# A real shell-script payload — the exact content-shape #365 was filed over
# (Zeek's `text/x-shellscript` signature is `^#!.*bin/(env )?(sh|bash|...)`
# on the FIRST bytes of the file). Reused for both scenarios: the HTTP one
# tests basic content-magic; the SMTP one tests source-tagging on top of the
# identical content-magic engine (#382's finding: transport-agnostic).
SHELL_PAYLOAD = b"#!/bin/bash\necho hi\n"
EXPECTED_MIME = "text/x-shellscript"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _docker_daemon_reachable() -> bool:
    try:
        r = subprocess.run(["docker", "version"], capture_output=True, timeout=10)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _pinned_zeek_image_runnable() -> bool:
    try:
        r = subprocess.run(
            ["docker", "run", "--rm", ZEEK_IMAGE, "zeek", "--version"],
            capture_output=True, timeout=120)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _skip_reason() -> Optional[str]:
    """None if the environment can run this suite; otherwise why not —
    checked once in setUpClass so a missing prerequisite skips instantly
    instead of failing partway through a capture."""
    if shutil.which("docker") is None:
        return "docker binary not on PATH"
    if shutil.which("tcpdump") is None:
        return "tcpdump binary not on PATH (needed for real packet capture)"
    if not _docker_daemon_reachable():
        return "Docker daemon not reachable (docker version failed)"
    if not _pinned_zeek_image_runnable():
        return (f"pinned image {ZEEK_IMAGE} could not be run (not pulled locally "
                f"and no/failed network access to pull it)")
    return None


class _EchoSMTPServer(smtpd.SMTPServer):
    """Accepts one real SMTP session and does nothing with the message —
    this test only cares about the WIRE BYTES tcpdump captures, not about
    actually relaying mail. process_message must exist (smtpd.SMTPServer is
    abstract without it) but its body is intentionally a no-op."""

    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        return None


def _run_zeek_over_pcap(tmpdir: Path, pcap_name: str, out_subdir: str,
                         extra_zeek_args: tuple = ()) -> list:
    """Replays a captured pcap through the pinned image exactly like
    scripts/setup/zeek_run_pcap.sh's real invocation (-C, LogAscii::use_json=T,
    docker -w for the output dir) minus the intel/config.zeek loading that
    script also does — irrelevant here, since files.log/mime_type is part of
    Zeek's base (not policy/) file-analysis framework, loaded by default with
    no extra scripts. Returns the parsed files.log records (possibly empty).

    extra_zeek_args: appended verbatim after the pcap path — used by the SMTP
    scenario to register its ephemeral port with Zeek's SMTP analyzer (see
    that test's own comment for why DPD alone isn't enough here)."""
    out_dir = tmpdir / out_subdir
    out_dir.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["docker", "run", "--rm",
         "-v", f"{tmpdir}:/data",
         "-w", f"/data/{out_subdir}",
         ZEEK_IMAGE,
         "zeek", "-C", "-r", f"/data/{pcap_name}", "LogAscii::use_json=T",
         *extra_zeek_args],
        capture_output=True, timeout=120)
    assert r.returncode == 0, (
        f"zeek replay of {pcap_name} failed (exit {r.returncode}): "
        f"{r.stderr.decode(errors='replace')[:2000]}")
    files_log = out_dir / "files.log"
    records = []
    if files_log.exists():
        for line in files_log.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
    if not records:
        # Diagnostic-rich failure (caught live: files.log came back empty
        # on the SMTP pcap with no other error) — lists every log Zeek DID
        # produce (e.g. conn.log present but no smtp.log at all would mean
        # Zeek never recognized the session as SMTP; smtp.log present but
        # no files.log would mean the session was recognized but no MIME
        # entity was extracted) plus zeek's own stdout, so an empty result
        # is diagnosable from the CI log directly instead of needing a
        # second blind guess. Caller still decides pass/fail (some callers
        # may legitimately expect zero records); this only enriches what
        # gets shown when they don't.
        produced = sorted(p.name for p in out_dir.iterdir())
        print(f"NOTE: zeek replay of {pcap_name} produced zero files.log records. "
              f"Logs actually produced in {out_dir}: {produced}. "
              f"zeek stdout: {r.stdout.decode(errors='replace')[:2000]!r}")
    return records


class _Capture:
    """tcpdump on loopback, scoped to one TCP port — started before the real
    exchange and stopped after it. A short settle sleep on the start side
    lets tcpdump arm before traffic flows; on the stop side stop() polls the
    save file until it has settled (see that method) rather than guessing a
    fixed delay, so neither the classic capture-not-yet-armed race nor the
    ring-not-yet-drained race this pattern is prone to can truncate the pcap.

    Opening a live capture device needs CAP_NET_RAW/CAP_NET_ADMIN (or root)
    that a plain, unprivileged `tcpdump` invocation does not have on a
    default CI runner user — `sudo -n` (non-interactive: fails fast rather
    than hanging on a password prompt if passwordless sudo isn't configured,
    which GitHub-hosted runners' default user has) covers that regardless of
    the exact capability/group setup a given host uses. First caught live:
    an unprivileged tcpdump here silently produced NO pcap file at all (not
    an empty one — Zeek's own replay step failed with 'unable to open ...:
    No such file or directory'), and neither __init__ nor stop() noticed —
    the Popen process had already exited (permission denied) long before
    stop() ever ran, its failure never surfaced. Both ends now check the
    process actually stayed alive/produced real output, so a future
    regression of this exact class fails loudly at the capture step itself
    instead of a confusing downstream Zeek error two steps later."""

    # pcap global header (24 bytes) that tcpdump writes when it opens the save
    # file, before any packet — a capture that recorded nothing sits at exactly
    # this size.
    _PCAP_HEADER_BYTES = 24

    def __init__(self, tmpdir: Path, pcap_name: str, port: int):
        self.pcap_path = tmpdir / pcap_name
        # --immediate-mode: deliver each packet to tcpdump the instant it is
        # captured, instead of through the kernel's default TPACKET_V3 ring,
        # which only hands a block of packets up to userspace once that block
        # fills or its per-block retirement timer expires. A sub-100ms
        # loopback exchange never fills a block, so every block waits out its
        # timer, and across the several retirement cycles the exchange spans
        # (compounded by scheduler wakeups) the tail packets were observed
        # here (#411 follow-up) landing in the save file in bursts up to ~1s
        # AFTER the exchange already finished — so any bounded wait before
        # stopping tcpdump could catch a truncated prefix (handshake + SMTP banner +
        # EHLO only) and Zeek's files.log came back empty. -U still forces a
        # per-packet write to the file once delivered; the two together make
        # the save file track the wire in real time so stop()'s
        # size-has-settled check below is trustworthy.
        self._proc = subprocess.Popen(
            ["sudo", "-n", "tcpdump", "-i", "lo", "-w", str(self.pcap_path),
             "-U", "--immediate-mode", f"tcp port {port}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(1.0)  # let tcpdump actually attach before traffic starts
        if self._proc.poll() is not None:
            stderr = self._proc.stderr.read().decode(errors="replace") if self._proc.stderr else ""
            raise RuntimeError(
                f"tcpdump exited immediately (code {self._proc.returncode}) instead of "
                f"staying attached to the capture — likely a privilege problem (needs "
                f"passwordless sudo or CAP_NET_RAW/CAP_NET_ADMIN on tcpdump itself). "
                f"stderr: {stderr!r}")

    def stop(self):
        # Wait for tcpdump to finish flushing the captured exchange to disk
        # BEFORE terminating it, instead of a fixed sleep. Caught live (#411
        # follow-up): a fixed `time.sleep(0.5)` here raced tcpdump's
        # kernel-ring -> save-file drain — the exchange always reached the
        # wire (tcpdump's own "received by filter" counted every packet,
        # "dropped by kernel" was 0) but "packets captured" (what actually got
        # written) was nondeterministically truncated when SIGTERM arrived
        # before the ring was drained, so the pcap held only the TCP handshake
        # + SMTP banner + EHLO and Zeek's files.log came back empty. This is
        # the flaky-capture cause the SMTP test's own assertion message warned
        # about ("or the capture/replay plumbing itself broke"). `-U` writes
        # each packet as it is read, so the save file grows monotonically:
        # poll its size until it has grown past the bare header AND then held
        # steady, which means tcpdump has caught up with the (already-finished)
        # exchange. Same condition-based-waiting fix, and same defensive
        # spirit, as this class's tcpdump-not-yet-attached guard above.
        deadline = time.time() + 15.0
        last_size = -1
        stable_since = None
        while time.time() < deadline:
            try:
                size = self.pcap_path.stat().st_size
            except FileNotFoundError:
                size = 0
            if size != last_size:
                last_size = size
                stable_since = None
            elif size > self._PCAP_HEADER_BYTES:
                if stable_since is None:
                    stable_since = time.time()
                elif time.time() - stable_since >= 0.6:
                    break
            time.sleep(0.05)
        still_running = self._proc.poll() is None
        self._proc.terminate()
        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=10)
        if not still_running:
            stderr = self._proc.stderr.read().decode(errors="replace") if self._proc.stderr else ""
            raise RuntimeError(
                f"tcpdump had already exited (code {self._proc.returncode}) before the "
                f"capture was stopped — no pcap was actually being written during the "
                f"real exchange. stderr: {stderr!r}")
        # Reject a header-only pcap (tcpdump attached and wrote the global
        # header but captured zero packets), not just a missing/zero-byte one
        # — the same distinction the stop() poll above relies on — so a
        # capture that recorded nothing fails loudly here at the capture step
        # instead of surfacing only as the vaguer "zero files.log records"
        # diagnostic two steps later in the Zeek replay.
        try:
            size = self.pcap_path.stat().st_size
        except FileNotFoundError:
            size = -1
        if size <= self._PCAP_HEADER_BYTES:
            stderr = self._proc.stderr.read().decode(errors="replace") if self._proc.stderr else ""
            raise RuntimeError(
                f"tcpdump ran but {self.pcap_path} captured no packets after the exchange "
                f"(size {size} bytes, at or below the {self._PCAP_HEADER_BYTES}-byte pcap "
                f"header) — stderr: {stderr!r}")


class ZeekMimeDetectionLiveFireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Checked once here, not at import/collection time (unittest.skipIf
        # would call _skip_reason() while pytest is merely discovering
        # tests) — mirrors test_live_fire.py's LiveFireTestCase.setUpClass
        # pattern exactly, including the up-to-120s pinned-image-runnable
        # probe only running when this suite is actually about to execute.
        reason = _skip_reason()
        if reason:
            raise unittest.SkipTest(reason)

    def test_http_shell_script_download_types_as_text_x_shellscript(self):
        with TemporaryDirectory() as td:
            tmpdir = Path(td)
            (tmpdir / "dropper.sh").write_bytes(SHELL_PAYLOAD)
            port = _free_port()
            server = subprocess.Popen(
                [sys.executable, "-m", "http.server", str(port),
                 "--bind", "127.0.0.1", "--directory", str(tmpdir)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                time.sleep(1.0)  # let the server bind before capturing/fetching
                cap = _Capture(tmpdir, "capture_http.pcap", port)
                try:
                    r = subprocess.run(
                        ["curl", "-s", "-o", "/dev/null",
                         f"http://127.0.0.1:{port}/dropper.sh"],
                        timeout=10)
                    self.assertEqual(0, r.returncode, "curl fetch of the test payload failed")
                finally:
                    cap.stop()
            finally:
                server.terminate()
                server.wait(timeout=10)

            records = _run_zeek_over_pcap(tmpdir, "capture_http.pcap", "out_http")
            matches = [rec for rec in records if rec.get("mime_type") == EXPECTED_MIME]
            self.assertTrue(
                matches,
                f"no files.log record typed {EXPECTED_MIME!r} for a real shell-script "
                f"HTTP download against the pinned {ZEEK_IMAGE} — either this image "
                f"changed its content-magic behavior for this signature, or the "
                f"capture/replay plumbing itself broke. All files.log records: {records}")

    def test_smtp_attachment_types_as_text_x_shellscript_and_tags_source_smtp(self):
        with TemporaryDirectory() as td:
            tmpdir = Path(td)
            port = _free_port()
            smtp_server = _EchoSMTPServer(("127.0.0.1", port), None, decode_data=False)
            loop_thread = threading.Thread(
                target=smtpd.asyncore.loop, kwargs={"timeout": 0.2}, daemon=True)
            loop_thread.start()
            try:
                time.sleep(1.0)  # let the server bind/start looping before capturing/sending
                cap = _Capture(tmpdir, "capture_smtp.pcap", port)
                try:
                    msg = MIMEMultipart()
                    msg["From"] = "attacker@example.com"
                    msg["To"] = "victim@example.com"
                    msg["Subject"] = "test attachment"
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(SHELL_PAYLOAD)
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition", "attachment", filename="dropper.sh")
                    msg.attach(part)

                    with smtplib.SMTP("127.0.0.1", port, timeout=10) as client:
                        client.sendmail(msg["From"], [msg["To"]], msg.as_string())
                finally:
                    cap.stop()
            finally:
                smtp_server.close()
                smtpd.asyncore.close_all()
                loop_thread.join(timeout=10)

            # #411 live-fire finding: Zeek's SMTP DPD signature matches on the
            # SERVER's initial "220 ..." banner, but only confirms the session
            # as SMTP once it also sees the CLIENT's own EHLO/HELO as the
            # connection's very first bytes — the normal case on the
            # well-known ports (25/587/465) Zeek's default SMTP::ports
            # registers. On an OS-assigned ephemeral port with no DPD
            # confirmation, Zeek analyzed the connection (conn.log exists)
            # but never attached the SMTP analyzer at all (no smtp.log, so
            # files.log's MIME extraction never had a chance to run either)
            # — caught live via _run_zeek_over_pcap's own diagnostic printing
            # the produced-log list. Explicitly registering this run's port
            # with SMTP::ports (the same mechanism a real deployment uses for
            # SMTP on a nonstandard port) sidesteps the DPD-ordering
            # dependency entirely, matching how a real client would need to
            # be configured for a nonstandard mail port too.
            records = _run_zeek_over_pcap(
                tmpdir, "capture_smtp.pcap", "out_smtp",
                extra_zeek_args=("-e", f"redef SMTP::ports += {{ {port}/tcp }};"))
            matches = [rec for rec in records
                       if rec.get("mime_type") == EXPECTED_MIME and rec.get("source") == "SMTP"]
            self.assertTrue(
                matches,
                f"no files.log record typed {EXPECTED_MIME!r} with source=SMTP for a real "
                f"MIME attachment against the pinned {ZEEK_IMAGE} — either this image "
                f"changed its content-magic or SMTP source-tagging behavior, or the "
                f"capture/replay plumbing itself broke. All files.log records: {records}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
