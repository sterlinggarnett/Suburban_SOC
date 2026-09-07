#!/usr/bin/env python3
"""
#557 — .gitattributes must cover systemd unit files.

`git config core.autocrlf` is `true` on the capture host, so an extension with
no `text eol=lf` rule checks out CRLF while HEAD stores LF. Every file in
`configs/systemd/` was in that state: unit files carrying absolute paths and
argument lists, `sudo cp`-ed verbatim into /etc/systemd/system, in exactly the
shape the existing `*.conf`/`*.cron` entries were written to protect.

Nothing was broken by it, and that is worth stating precisely rather than
overselling the fix: verified empirically on this host with a throwaway `--user`
unit written with explicit `\\r\\n` terminators, systemd strips the `\\r`
(`Environment=SOC_PROBE=value` came back with no trailing carriage return and
`ExecStart` printed the unedited value). The argument for the fix is that
relying on a parser's leniency is a weaker guarantee than not producing the
problem, and that this file already made that call for five other extensions.

These tests ask git itself what the attributes resolve to, rather than
pattern-matching the .gitattributes text — a rule can be present and still be
overridden by a later one, and only `git check-attr` sees the real precedence.

Run:  python tests/pipeline/test_gitattributes_line_endings.py
      (or: pytest tests/pipeline)
"""

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Extensions this repo has deliberately declared LF, each with a comment in
# .gitattributes saying what CRLF would corrupt. A rule silently disappearing
# from that file is the regression these guard.
LF_EXTENSIONS = [
    "sh", "conf", "cron", "dat", "yml", "yaml", "json", "md", "py", "ndjson",
    "service", "timer",
]


def _git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=True, timeout=60)


def _git_available():
    try:
        return _git("rev-parse", "--is-inside-work-tree").returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _eol_attr(path):
    """What `eol` git actually resolves for a path, honouring rule precedence."""
    out = _git("check-attr", "eol", "--", path).stdout.strip()
    # "<path>: eol: lf"
    return out.rsplit(":", 1)[-1].strip() if out else "unspecified"


@unittest.skipUnless(_git_available(), "not inside a git work tree")
class UnitFilesAreDeclaredLfTests(unittest.TestCase):
    """The actual #557 fix."""

    def test_service_and_timer_extensions_resolve_to_lf(self):
        for ext in ("service", "timer"):
            with self.subTest(ext=ext):
                self.assertEqual("lf", _eol_attr(f"configs/systemd/example.{ext}"),
                                 f"*.{ext} has no `text eol=lf` rule — on a host with "
                                 "core.autocrlf=true these check out CRLF while HEAD "
                                 "stores LF (#557)")

    def test_every_tracked_unit_file_resolves_to_lf(self):
        """Extension-level rules, not path-level ones — a unit moved out of
        configs/systemd/ must stay covered."""
        tracked = [ln for ln in _git("ls-files").stdout.splitlines()
                   if ln.endswith((".service", ".timer"))]
        self.assertTrue(tracked, "no tracked systemd unit files found at all")
        for path in tracked:
            with self.subTest(path=path):
                self.assertEqual("lf", _eol_attr(path))

    def test_unit_working_copies_are_actually_lf(self):
        """The rule alone does not rewrite files that were already checked out
        CRLF — #557's "done when" also required renormalising the working
        copies. Reads bytes rather than trusting the attribute."""
        tracked = [ln for ln in _git("ls-files").stdout.splitlines()
                   if ln.endswith((".service", ".timer"))]
        offenders = []
        for path in tracked:
            data = (ROOT / path).read_bytes()
            if b"\r\n" in data:
                offenders.append(path)
        self.assertEqual([], offenders,
                         f"unit files still checked out with CRLF: {offenders}. "
                         "Renormalise: rm them and `git checkout -- configs/systemd/`")


@unittest.skipUnless(_git_available(), "not inside a git work tree")
class ExtensionlessGovernanceFilesAreDeclaredLfTests(unittest.TestCase):
    """#562 — the file governing every other file's line endings never
    governed itself. Extension globs can't match a file with no extension, so
    `.gitattributes`, `.gitignore`, `.dockerignore` and `LICENSE` need
    literal-basename rules instead."""

    EXTENSIONLESS_LF_FILES = [".gitattributes", ".gitignore", ".dockerignore", "LICENSE"]

    def test_extensionless_files_resolve_to_lf(self):
        for name in self.EXTENSIONLESS_LF_FILES:
            with self.subTest(name=name):
                self.assertEqual("lf", _eol_attr(name),
                                 f"{name} has no `text eol=lf` rule — on a host with "
                                 "core.autocrlf=true it checks out CRLF while HEAD "
                                 "stores LF (#562)")

    def test_tracked_extensionless_working_copies_are_actually_lf(self):
        """Same renormalisation check #557 required, for the files that are
        actually tracked today (.dockerignore doesn't exist in this repo)."""
        offenders = []
        for name in self.EXTENSIONLESS_LF_FILES:
            path = ROOT / name
            if not path.is_file():
                continue
            if b"\r\n" in path.read_bytes():
                offenders.append(name)
        self.assertEqual([], offenders,
                         f"still checked out with CRLF: {offenders}. "
                         "Renormalise: rm them and `git checkout -- <path>`")


@unittest.skipUnless(_git_available(), "not inside a git work tree")
class DeclaredLineEndingsHoldTests(unittest.TestCase):
    def test_every_declared_lf_family_still_resolves_to_lf(self):
        """Each of these has a comment in .gitattributes explaining what CRLF
        would corrupt — a deleted line should fail here, not in production."""
        for ext in LF_EXTENSIONS:
            with self.subTest(ext=ext):
                self.assertEqual("lf", _eol_attr(f"some/path/example.{ext}"),
                                 f"*.{ext} lost its `text eol=lf` rule")

    def test_powershell_stays_crlf(self):
        """The one deliberate exception: CRLF is correct for *.ps1 on Windows.
        Asserted so a future blanket-LF edit cannot quietly break it."""
        self.assertEqual("crlf", _eol_attr("scripts/endpoint/example.ps1"))

    def test_no_tracked_blob_is_stored_with_crlf(self):
        """The invariant the per-extension rules exist to produce. `git
        ls-files --eol` reports the INDEX encoding: `text eol=` normalises to LF
        on the way in, so an i/crlf blob means some file was committed from a
        CRLF working tree with no rule covering it — which is exactly how
        configs/systemd/ drifted."""
        offenders = []
        for line in _git("ls-files", "--eol").stdout.splitlines():
            fields = line.split("\t", 1)
            if len(fields) != 2:
                continue
            if fields[0].split()[0] == "i/crlf":
                offenders.append(fields[1].strip())
        self.assertEqual([], offenders,
                         f"CRLF stored in the index for: {offenders}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
