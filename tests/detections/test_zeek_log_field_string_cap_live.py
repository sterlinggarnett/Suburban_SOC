#!/usr/bin/env python3
"""
#389 live half: replays hand-built DNS TXT responses through the PINNED
zeek/zeek image (the exact tag+digest every real capture path runs) and
asserts the facts this pipeline's #389 fix rests on:

  1. Upstream behavior pin — with no repo config loaded, the image cuts a
     long TXT answer at exactly Log::default_max_field_string_bytes' 4096-
     byte upstream default and marks it ONLY in weird.log
     (name=log_string_field_truncated, addl=DNS::LOG, no uid). This is the
     golden-output check configs/systemd/zeek-host-capture.service's
     image-bump checklist demands: if a future image moves this cap or the
     weird's name, this test says so before the pipeline goes quietly
     blind or noisy.
  2. Fix — with configs/intel/config.zeek loaded (the real production
     config, intel feed staged from the tracked seed), an answer longer
     than the old 4096 default but under the raised cap is logged in full
     with no truncation weird.
  3. Lockstep — an answer longer than the raised cap is cut at EXACTLY the
     value config.zeek redefs, which equals dns.answers' ignore_above in
     the shipped template (so the cut answer is still indexed and rule-
     matchable) and is the value configs/logstash.conf's exact-length
     pipeline.dns_answer_truncated_by_zeek check keys on (pinned statically
     by tests/pipeline/test_zeek_log_field_string_cap.py).
  4. Bounds pin — the image's Log::default_max_field_string_bytes (4096)
     and Log::default_max_total_string_bytes (256000) defaults, read from
     the running image, so the per-record volume bound config.zeek's
     rationale rests on is a checked fact, not prose (security-auditor).
  5. Observational — a multi-byte payload cut mid-character: asserts only
     that the truncation weird fires; records whether the dns.log record
     is still valid JSON and the parsed byte length, for the CI log. The
     pipeline's exact-length tag claims exactness for ASCII (base64 TXT-C2)
     only, and this is the evidence behind that hedge.

Pure-stdlib packet construction (struct-built Ethernet/IPv4/UDP/DNS, no
scapy): the TXT RDATA is a list of individually-valid <=255-byte character-
strings, the layout #389's own reproduction found necessary (a raw blob
re-chunks differently). Zeek renders each character-string as
"TXT <len> <content>" and space-joins them into ONE answers[] element.

SKIPS (not fails) if docker or the pinned image aren't usable — same
posture and helper shape as test_zeek_mime_detection.py — UNLESS
SOC_REQUIRE_LIVE_ZEEK=1 is set, in which case an unusable environment is
an error: the non-required `live-fire` CI job sets it so a run that could
not exercise the image shows red there instead of a silent green skip
(security-auditor: this file is the only evidence about the image itself).

Run:  pytest tests/detections/test_zeek_log_field_string_cap_live.py -v
"""
import json
import os
import re
import shutil
import struct
import subprocess
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional

ROOT = Path(__file__).resolve().parents[2]
CONFIG_ZEEK_PATH = ROOT / "configs" / "intel" / "config.zeek"
INTEL_SEED_PATH = ROOT / "configs" / "intel" / "intel.seed.dat"
TEMPLATE_PATH = ROOT / "configs" / "elasticsearch" / "logstash-security-template.json"

# Deliberately duplicated (not imported) — this repo's established pattern
# for the pin: each invocation site carries it with a cross-reference, and
# tests/pipeline/test_zeek_image_pin.py is what catches drift between them.
# Bump together with the 4 real capture paths + test_zeek_mime_detection.py.
EXPECTED_TAG = "8.2.1"
EXPECTED_DIGEST = "sha256:eca2b3915d3e067cbb4a904f23f4c4f461ea2b60613ab30f7ee77bbc707c87c7"
ZEEK_IMAGE = f"zeek/zeek:{EXPECTED_TAG}@{EXPECTED_DIGEST}"

# Zeek 8.1.0+'s upstream defaults (scripts/base/init-bare.zeek). Tests 1 and
# 4 pin them.
UPSTREAM_DEFAULT_CAP = 4096
UPSTREAM_DEFAULT_TOTAL = 256000
TRUNCATION_WEIRD = "log_string_field_truncated"
REDEF_RE = re.compile(r"^redef Log::default_max_field_string_bytes = (\d+);", re.M)
REQUIRE_ENV = "SOC_REQUIRE_LIVE_ZEEK"


def _repo_cap() -> int:
    m = REDEF_RE.search(CONFIG_ZEEK_PATH.read_text(encoding="utf-8"))
    assert m, "configs/intel/config.zeek has no Log::default_max_field_string_bytes redef"
    return int(m.group(1))


def _dns_answers_ignore_above() -> int:
    """dns.answers' real ignore_above from the shipped template — read, not
    hardcoded, so the ceiling this test compares against tracks the
    template (code-reviewer follow-up; same source tests/pipeline/
    test_zeek_log_field_string_cap.py reads)."""
    props = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))["template"]["mappings"]["properties"]
    return int(props["dns"]["properties"]["answers"]["ignore_above"])


# --- packet construction ---------------------------------------------------

def _csum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def _udp_frame(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x1234, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    return bytes.fromhex("aabbccddeeff112233445566") + b"\x08\x00" + ip + udp


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def _txt_chunks(chunk_bytes: int, chunks: int) -> list:
    # Distinct ASCII letter per chunk so a truncation point is attributable.
    return [bytes([65 + i % 26]) * chunk_bytes for i in range(chunks)]


def _multibyte_txt_chunks(chunks: int) -> list:
    # 83 x U+20AC (3 bytes each) = 249 bytes per character-string, all
    # multi-byte, so wherever the byte cap lands it is overwhelmingly
    # likely to fall mid-character.
    return ["€".encode("utf-8") * 83 for _ in range(chunks)]


def write_txt_pcap(path: Path, chunks: list) -> None:
    """One DNS TXT query + one response carrying every chunk as its own
    character-string inside a single TXT RR."""
    question = _dns_name("c2.example.com") + struct.pack("!HH", 16, 1)
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    rdata = b"".join(bytes([len(c)]) + c for c in chunks)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(rdata)) + rdata
    response = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question + answer
    client, server = bytes([10, 0, 0, 5]), bytes([10, 0, 0, 53])
    frames = [_udp_frame(client, server, 40000, 53, query),
              _udp_frame(server, client, 53, 40000, response)]
    with path.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        t = int(time.time())
        for i, frame in enumerate(frames):
            f.write(struct.pack("<IIII", t, i * 1000, len(frame), len(frame)) + frame)


# --- environment gating -----------------------------------------------------

def _docker_daemon_reachable() -> bool:
    try:
        return subprocess.run(["docker", "version"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _pinned_zeek_image_runnable() -> bool:
    try:
        return subprocess.run(["docker", "run", "--rm", ZEEK_IMAGE, "zeek", "--version"],
                              capture_output=True, timeout=180).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _skip_reason() -> Optional[str]:
    if shutil.which("docker") is None:
        return "docker binary not on PATH"
    if not _docker_daemon_reachable():
        return "Docker daemon not reachable (docker version failed)"
    if not _pinned_zeek_image_runnable():
        return (f"pinned image {ZEEK_IMAGE} could not be run (not pulled locally "
                f"and no/failed network access to pull it)")
    return None


# --- replay -----------------------------------------------------------------

def _run_zeek(tmpdir: Path, pcap_name: str, out_subdir: str, load_repo_config: bool) -> dict:
    """Replays the pcap through the pinned image the way zeek_run_pcap.sh
    does (-C, LogAscii::use_json=T, docker -w for the output dir), with the
    real configs/intel/config.zeek loaded from the same /data/intel mount
    path the production capture uses when load_repo_config is set. Returns
    {"dns": [...], "dns_raw": [...lines...], "weird": [...]}; a dns.log line
    that is not valid JSON is kept in dns_raw only (see test 5)."""
    out_dir = tmpdir / out_subdir
    out_dir.mkdir(parents=True, exist_ok=True)
    args = ["docker", "run", "--rm", "-v", f"{tmpdir}:/data", "-w", f"/data/{out_subdir}",
            ZEEK_IMAGE, "zeek", "-C", "-r", f"/data/{pcap_name}", "LogAscii::use_json=T"]
    if load_repo_config:
        args.append("/data/intel/config.zeek")
    # 180s: config.zeek suspends packet processing until the intel feed is
    # read (#222); a hang here must fail with a message, not stall CI.
    r = subprocess.run(args, capture_output=True, timeout=180)
    assert r.returncode == 0, (
        f"zeek replay of {pcap_name} failed (exit {r.returncode}): "
        f"{r.stderr.decode(errors='replace')[:2000]}")
    logs: dict = {"dns": [], "dns_raw": [], "weird": []}
    dns_path = out_dir / "dns.log"
    if dns_path.exists():
        for line in dns_path.read_bytes().decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            logs["dns_raw"].append(line)
            try:
                logs["dns"].append(json.loads(line))
            except json.JSONDecodeError:
                pass
    weird_path = out_dir / "weird.log"
    if weird_path.exists():
        logs["weird"] = [json.loads(line) for line in weird_path.read_text(encoding="utf-8").splitlines()
                         if line.strip()]
    return logs


def _zeek_print(expr: str) -> str:
    r = subprocess.run(["docker", "run", "--rm", ZEEK_IMAGE, "zeek", "-e", f"print {expr};"],
                       capture_output=True, timeout=120)
    assert r.returncode == 0, f"zeek -e 'print {expr}' failed: {r.stderr.decode(errors='replace')[:500]}"
    return r.stdout.decode().strip()


def _single_txt_answer(dns_records: list) -> str:
    txt = [r for r in dns_records if r.get("qtype_name") == "TXT" and r.get("answers")]
    assert len(txt) == 1, f"expected exactly one TXT dns.log record with answers, got {txt!r}"
    assert len(txt[0]["answers"]) == 1, f"expected ONE joined answers[] element, got {txt[0]['answers']!r}"
    return txt[0]["answers"][0]


def _truncation_weirds(weird_records: list) -> list:
    return [w for w in weird_records if w.get("name") == TRUNCATION_WEIRD]


class ZeekLogFieldStringCapLiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reason = _skip_reason()
        if reason:
            if os.environ.get(REQUIRE_ENV) == "1":
                raise AssertionError(
                    f"{REQUIRE_ENV}=1 but the live Zeek environment is unusable: {reason}")
            raise unittest.SkipTest(reason)
        cls._tmp = TemporaryDirectory()
        cls.tmpdir = Path(cls._tmp.name)
        # Stage the production config at the path it expects its intel feed
        # under (/data/intel/intel.dat); the tracked seed stands in for the
        # refresh_intel.sh output that is gitignored.
        intel = cls.tmpdir / "intel"
        intel.mkdir()
        shutil.copy(CONFIG_ZEEK_PATH, intel / "config.zeek")
        shutil.copy(INTEL_SEED_PATH, intel / "intel.dat")
        cls.cap = _repo_cap()
        # 24 x 250 B = 6,000 content bytes (~6,215 logged): over the upstream
        # 4096 default, under the raised cap.
        cls.chunks_6k = _txt_chunks(250, 24)
        write_txt_pcap(cls.tmpdir / "txt_6k.pcap", cls.chunks_6k)
        # 40 x 250 B = 10,000 content bytes (~10,359 logged): over the cap.
        cls.chunks_10k = _txt_chunks(250, 40)
        write_txt_pcap(cls.tmpdir / "txt_10k.pcap", cls.chunks_10k)
        # 40 x 249 B of 3-byte characters: over the cap, cut mid-character.
        write_txt_pcap(cls.tmpdir / "txt_mb.pcap", _multibyte_txt_chunks(40))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_1_pinned_image_truncates_at_the_upstream_default_and_marks_it_only_in_weird_log(self):
        logs = _run_zeek(self.tmpdir, "txt_10k.pcap", "out_upstream", load_repo_config=False)
        answer = _single_txt_answer(logs["dns"])
        self.assertEqual(len(answer.encode("utf-8")), UPSTREAM_DEFAULT_CAP,
                         "the pinned image no longer cuts at 4096 bytes — Zeek's upstream "
                         "Log::default_max_field_string_bytes default moved; re-check #389's "
                         "config.zeek/logstash.conf assumptions")
        weirds = _truncation_weirds(logs["weird"])
        self.assertEqual(len(weirds), 1, f"expected one {TRUNCATION_WEIRD} weird, got {logs['weird']!r}")
        self.assertEqual(weirds[0].get("addl"), "DNS::LOG")
        # Connection-less weird: Zeek raises it from the log writer, not a
        # connection, so it carries no uid to correlate on — which is why
        # logstash.conf's exact-length tag is still needed as the per-
        # record pointer.
        self.assertNotIn("uid", weirds[0])

    def test_2_repo_config_zeek_logs_an_answer_above_the_old_default_in_full(self):
        logs = _run_zeek(self.tmpdir, "txt_6k.pcap", "out_fixed_6k", load_repo_config=True)
        answer = _single_txt_answer(logs["dns"])
        self.assertTrue(answer.startswith("TXT "), f"unexpected TXT render: {answer[:40]!r}")
        self.assertTrue(answer.endswith(self.chunks_6k[-1].decode()),
                        "last character-string missing — the answer was still cut")
        size = len(answer.encode("utf-8"))
        self.assertGreater(size, UPSTREAM_DEFAULT_CAP, "the raise did not take effect")
        self.assertLessEqual(size, _dns_answers_ignore_above(),
                             "a full answer under the cap must also be under the indexing ceiling")
        self.assertEqual(_truncation_weirds(logs["weird"]), [])

    def test_3_repo_config_zeek_cuts_an_oversized_answer_at_exactly_the_redef_value(self):
        logs = _run_zeek(self.tmpdir, "txt_10k.pcap", "out_fixed_10k", load_repo_config=True)
        answer = _single_txt_answer(logs["dns"])
        self.assertEqual(len(answer.encode("utf-8")), self.cap,
                         "a Zeek-truncated answer must land at exactly config.zeek's redef "
                         "value — that is the number logstash.conf's exact-length tag keys on")
        self.assertEqual(self.cap, _dns_answers_ignore_above(),
                         "the cut answer must still be indexable (cap == ignore_above)")
        weirds = _truncation_weirds(logs["weird"])
        self.assertEqual(len(weirds), 1, f"expected one {TRUNCATION_WEIRD} weird, got {logs['weird']!r}")
        self.assertEqual(weirds[0].get("addl"), "DNS::LOG")

    def test_4_image_upstream_field_and_total_string_defaults_are_the_documented_ones(self):
        self.assertEqual(_zeek_print("Log::default_max_field_string_bytes"), str(UPSTREAM_DEFAULT_CAP))
        self.assertEqual(_zeek_print("Log::default_max_total_string_bytes"), str(UPSTREAM_DEFAULT_TOTAL),
                         "the per-record string budget config.zeek's volume rationale rests on moved")

    def test_5_multibyte_cut_still_raises_the_truncation_weird(self):
        logs = _run_zeek(self.tmpdir, "txt_mb.pcap", "out_fixed_mb", load_repo_config=True)
        weirds = _truncation_weirds(logs["weird"])
        self.assertEqual(len(weirds), 1, f"expected one {TRUNCATION_WEIRD} weird, got {logs['weird']!r}")
        # Observational half (recorded, not asserted — see module docstring):
        # is the record still valid JSON after Zeek's writer handled the
        # partial trailing character, and how long is the parsed answer?
        txt = [r for r in logs["dns"] if r.get("qtype_name") == "TXT" and r.get("answers")]
        if txt:
            size = len(txt[0]["answers"][0].encode("utf-8"))
            print(f"NOTE(#389 multibyte cut): dns.log record parsed as JSON; answers[0] is {size} "
                  f"UTF-8 bytes vs cap {self.cap} (exact-length tag {'fires' if size == self.cap else 'MISSES'})")
        else:
            print(f"NOTE(#389 multibyte cut): dns.log TXT record did NOT parse as JSON "
                  f"({len(logs['dns_raw'])} raw line(s)) — the pipeline's ndjson decode would fail "
                  f"this record too; exact-length tag cannot fire for it")
        self.assertTrue(logs["dns_raw"], "dns.log was empty for the multibyte pcap")


if __name__ == "__main__":
    unittest.main()
