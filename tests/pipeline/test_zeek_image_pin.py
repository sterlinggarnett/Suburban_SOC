#!/usr/bin/env python3
"""
Static check that zeek/zeek is pinned to a specific, digest-verified image
across all 4 real Zeek capture invocations (#293).

THE BUG CLASS: an unpinned `zeek/zeek` (bare, or `:latest`) lets an
upstream image rebuild silently change any Zeek/OpenSSL-generated string
value a Sigma rule's logic depends on, with no corresponding repo change to
review. Already happened once, live, during #228's review:
net_zeek_ssl_self_signed_c2.yml's first draft assumed OpenSSL's older
"self signed certificate" (space) wording; the real image's OpenSSL 3.0.13
emitted "self-signed certificate" (hyphenated) — a silent, value-level no-op
that would have shipped undetected if a human hadn't happened to diff the
exact string by hand.

A tag alone is not enough: a Docker Hub tag is a mutable pointer the
publisher can re-push at any time (the exact "upstream rebuild changed a
generated string" event class above), and a host with Docker socket access
can `docker tag <anything> zeek/zeek:8.1.1` locally regardless of what the
real registry serves (security-auditor review). Pinning tag+digest closes
both: the digest is content-addressed, so neither a registry re-push nor a
local retag can make `docker run` resolve to different bytes without the
line itself changing.

The 4 real capture paths (grep-confirmed, no other executable invocation —
docs/plans mentioning `zeek/zeek` are excluded from this check, tracked
separately since they aren't something a systemd unit or SOP script runs):
  - scripts/setup/host_capture.sh (#320: the always-on production sensor's
    tcpdump|docker pipeline — factored out of
    configs/systemd/zeek-host-capture.service's own ExecStart= line to close
    a CAPTURE_IFACE shell-interpolation gap; that unit now just invokes this
    script with the interface as a positional argument, and no longer
    contains a real zeek/zeek invocation of its own)
  - scripts/setup/stream_capture.sh (SOP-001-A/B/C: mesh/LAN/raw live streaming)
  - scripts/setup/zeek_connect_host.sh (SOP-001-E: interactive host monitor)
  - scripts/setup/zeek_run_pcap.sh (offline PCAP replay)

Pinning only 3 of the 4, pinning them to different values, or pinning to a
value nobody reviewed is just as silent a failure mode as pinning none —
this test enforces that every real capture path is pinned, and that all 4
match the exact tag+digest this repo's rules were verified against
(EXPECTED_TAG/EXPECTED_DIGEST below), not merely "some tag, not latest".

Run:  python tests/pipeline/test_zeek_image_pin.py  (or: pytest tests/pipeline)
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

REAL_CAPTURE_PATHS = [
    ROOT / "scripts" / "setup" / "host_capture.sh",
    ROOT / "scripts" / "setup" / "stream_capture.sh",
    ROOT / "scripts" / "setup" / "zeek_connect_host.sh",
    ROOT / "scripts" / "setup" / "zeek_run_pcap.sh",
]

# The exact version this repo's Zeek-string-dependent rules (e.g.
# net_zeek_ssl_self_signed_c2.yml) were verified against — see
# configs/systemd/zeek-host-capture.service's #293 header comment for the
# bump process. A deliberate bump means editing these two constants, which
# is the review signal this whole module exists to force.
# #364: bumped 8.1.1 -> 8.2.1 to close 7 real CRITICAL CVEs #355's Trivy
# job found on 8.1.1 — 8.2.1 scans clean. Both validation_status-dependent
# rules re-verified against the new OpenSSL (3.5.6): byte-identical exact
# strings, no rule change needed.
EXPECTED_TAG = "8.2.1"
EXPECTED_DIGEST = "sha256:eca2b3915d3e067cbb4a904f23f4c4f461ea2b60613ab30f7ee77bbc707c87c7"

# Anchored on both sides against [\w./-] so a registry/namespace prefix
# ("evil.example.com/zeek/zeek", "notzeek/zeek") or a suffix
# ("zeek/zeek-dev") is never misread as a bare "zeek/zeek" reference
# (security-auditor review) — those must NOT match here, so a real swap of
# the image reference fails this module's exactly-once check loudly
# instead of a stale positive.
IMAGE_REF_RE = re.compile(
    r"(?<![\w./-])zeek/zeek"
    r"(?::(?P<tag>[\w][\w.\-]*))?"
    r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?"
    r"(?![\w./-])"
)

# A reference only counts if it's on the line that actually invokes the
# container (or the multi-line `docker run \`-continued statement it's
# part of) — never a comment mentioning the image in prose. Both markers
# are required to be real, non-comment code in this repo's 4 files, so
# this alone would already exclude prose; comments are additionally
# stripped below so a comment that happens to contain one of these marker
# strings ("bump the docker run image") still can't be misread as a real
# invocation (security-auditor review).
INVOCATION_MARKERS = ("docker run", "ExecStart=")


def _strip_full_line_comments(text: str) -> str:
    return "\n".join("" if line.strip().startswith("#") else line for line in text.splitlines())


def _join_backslash_continuations(text: str) -> list:
    """Collapse a `cmd \\\\\\n  arg \\\\\\n  image \\\\\\n  ...` shell statement
    into one logical line, so the image reference — which sits on its own
    line, separate from the `docker run` token — is recognized as part of
    the same real invocation rather than requiring both on one line (only
    true for the systemd unit's single-line ExecStart form)."""
    logical_lines = []
    buf = ""
    for line in text.splitlines():
        buf = f"{buf} {line.strip()}" if buf else line
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1]
        else:
            logical_lines.append(buf)
            buf = ""
    if buf:
        logical_lines.append(buf)
    return logical_lines


def extract_image_refs(text: str) -> list:
    """[(tag_or_None, digest_or_None), ...] for every real (non-comment)
    zeek/zeek invocation in text."""
    refs = []
    for logical_line in _join_backslash_continuations(_strip_full_line_comments(text)):
        if not any(marker in logical_line for marker in INVOCATION_MARKERS):
            continue
        for m in IMAGE_REF_RE.finditer(logical_line):
            refs.append((m.group("tag"), m.group("digest")))
    return refs


class RealCapturePathsArePinnedAndInLockstep(unittest.TestCase):
    def test_every_real_capture_path_has_exactly_one_real_invocation(self):
        # Guards the test itself against silently checking nothing if a
        # file is ever renamed/moved, checking a stale duplicate if a 5th
        # invocation is ever added without updating REAL_CAPTURE_PATHS, or
        # a swapped/typosquatted image reference passing by simply not
        # matching (and thus not counting) at all.
        for path in REAL_CAPTURE_PATHS:
            self.assertTrue(path.is_file(), f"expected real capture path missing: {path}")
            refs = extract_image_refs(path.read_text(encoding="utf-8"))
            self.assertEqual(
                1, len(refs),
                f"{path}: expected exactly 1 real zeek/zeek invocation, found {len(refs)}")

    def test_every_real_capture_path_pins_the_expected_tag_and_digest(self):
        for path in REAL_CAPTURE_PATHS:
            tag, digest = extract_image_refs(path.read_text(encoding="utf-8"))[0]
            self.assertEqual(
                EXPECTED_TAG, tag,
                f"{path}: tag is {tag!r}, expected the reviewed pin {EXPECTED_TAG!r} "
                f"(a bare/None tag is unpinned; any other value hasn't been reviewed)")
            self.assertEqual(
                EXPECTED_DIGEST, digest,
                f"{path}: digest is {digest!r}, expected {EXPECTED_DIGEST!r} — a tag alone "
                f"is a mutable pointer (registry re-push or local `docker tag` can both "
                f"repoint it silently); the digest is what actually pins the bytes")


class ExtractImageRefsSelfTests(unittest.TestCase):
    """Mutation check on the checker itself, not just the current real
    files — confirms extract_image_refs actually fails closed on each bug
    shape this module exists to catch, rather than happening to pass today
    only because the real files are already correct."""

    def test_detects_bare_unpinned_reference(self):
        self.assertEqual([(None, None)], extract_image_refs("docker run --rm zeek/zeek zeek --version"))

    def test_detects_latest_as_a_real_tag_not_unpinned(self):
        # `:latest` must be caught by the tag != EXPECTED_TAG assertion
        # above, not misparsed as "unpinned" here — two different failure
        # modes, deliberately covered by two different tests.
        self.assertEqual([("latest", None)], extract_image_refs("docker run zeek/zeek:latest"))

    def test_extracts_pinned_tag_without_digest(self):
        self.assertEqual([("8.1.1", None)], extract_image_refs("docker run zeek/zeek:8.1.1"))

    def test_extracts_pinned_tag_and_digest(self):
        text = f"docker run zeek/zeek:8.1.1@{EXPECTED_DIGEST}"
        self.assertEqual([("8.1.1", EXPECTED_DIGEST)], extract_image_refs(text))

    def test_rejects_registry_prefixed_lookalike(self):
        # The real reference was swapped for a different registry/mirror —
        # must NOT be misread as a bare, matching "zeek/zeek".
        self.assertEqual([], extract_image_refs("docker run evil.example.com/zeek/zeek:8.1.1"))

    def test_rejects_typosquat_prefix(self):
        self.assertEqual([], extract_image_refs("docker run notzeek/zeek:8.1.1"))

    def test_rejects_suffixed_lookalike(self):
        self.assertEqual([], extract_image_refs("docker run zeek/zeek-dev:8.1.1"))

    def test_ignores_comment_only_mentions(self):
        # The exact shape caught by hand while authoring this file: an
        # explanatory comment describing the image in prose is a second,
        # unpinned-looking match in the same text as the real invocation
        # below it, if comments aren't excluded first.
        text = (
            "# zeek/zeek is pinned to a specific version below\n"
            f"docker run zeek/zeek:8.1.1@{EXPECTED_DIGEST}"
        )
        self.assertEqual([("8.1.1", EXPECTED_DIGEST)], extract_image_refs(text))

    def test_ignores_a_comment_that_contains_an_invocation_marker(self):
        # A bump note like "migrated the docker run invocation off
        # zeek/zeek:8.1.1" contains the "docker run" marker string itself
        # — must still be excluded as a comment, not read as a second real
        # invocation.
        text = (
            "# migrated the docker run invocation off zeek/zeek:8.1.1\n"
            f"docker run zeek/zeek:8.1.1@{EXPECTED_DIGEST}"
        )
        self.assertEqual([("8.1.1", EXPECTED_DIGEST)], extract_image_refs(text))

    def test_detects_two_real_invocations_in_one_file(self):
        # A genuine drift risk this module must still catch: a second real
        # (non-comment) invocation added to a file, whether or not it
        # agrees with the first.
        text = (
            f"docker run zeek/zeek:8.1.1@{EXPECTED_DIGEST}\n"
            "docker run zeek/zeek:8.0.0"
        )
        self.assertEqual([("8.1.1", EXPECTED_DIGEST), ("8.0.0", None)], extract_image_refs(text))

    def test_joins_a_backslash_continued_multi_line_invocation(self):
        # The 3 shell scripts' real shape: `docker run` and the image
        # reference are on different lines of the same continued statement.
        text = (
            "docker run --rm \\\n"
            "  -v /data:/data \\\n"
            f"  zeek/zeek:8.1.1@{EXPECTED_DIGEST} \\\n"
            "  zeek -C -r /input.pcap"
        )
        self.assertEqual([("8.1.1", EXPECTED_DIGEST)], extract_image_refs(text))


if __name__ == "__main__":
    unittest.main(verbosity=2)
