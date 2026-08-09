#!/usr/bin/env python3
"""
env_loader.py — .env inline-comment parsing tests (#259).

slo_metrics.py's hand-rolled .env loader (needed because it's invoked
directly via `python3 slo_metrics.py` per configs/systemd/slo-metrics.service,
unlike most scripts here which bash-source .env first) used to take the whole
line remainder as the value, breaking float()/int() conversion on a real
"KEY=10   # comment" style .env line — reproduced live against this
environment's local .env. run_hunts.py had the byte-for-byte identical bug;
both now share this one parser/loader.

Run:  pytest tests/setup/test_env_loader.py
"""

import io
import contextlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import env_loader


class ParseEnvLineTests(unittest.TestCase):
    def test_strips_trailing_inline_comment(self):
        self.assertEqual(
            env_loader.parse_env_line(
                "SLO_MTTD_MAX_MIN=10         # Max Mean Time to Detect (in minutes)"),
            ("SLO_MTTD_MAX_MIN", "10"))

    def test_plain_line_without_comment_unaffected(self):
        self.assertEqual(env_loader.parse_env_line("ELASTIC_PASSWORD=hunter2"),
                          ("ELASTIC_PASSWORD", "hunter2"))

    def test_value_containing_hash_with_no_preceding_space_untouched(self):
        # Only a `#` preceded by whitespace is a comment (matching bash's own
        # word-splitting) — a value that legitimately contains "#" (a
        # password, a URL fragment) must not be truncated.
        self.assertEqual(env_loader.parse_env_line("SOME_SECRET=abc#def"),
                          ("SOME_SECRET", "abc#def"))

    def test_spaceless_hash_followed_by_a_real_trailing_comment(self):
        # Stresses both halves of the inline-comment regex at once: the
        # first `#` has no preceding space (part of the value) and must
        # survive, the second `#` does have preceding space (a real
        # comment) and must not. SOME_OTHER_VALUE deliberately doesn't match
        # the credential-key pattern (unlike an earlier draft's
        # "NOT_A_SECRET_KEY", which actually DID match via its own "SECRET"/
        # "KEY" substrings), so this test isn't also exercising the
        # truncation-warning path (see TruncationWarningTests for that).
        self.assertEqual(env_loader.parse_env_line("SOME_OTHER_VALUE=10#nospace  # real comment"),
                          ("SOME_OTHER_VALUE", "10#nospace"))

    def test_comment_only_line_returns_none(self):
        self.assertIsNone(env_loader.parse_env_line("# just a comment"))

    def test_blank_line_returns_none(self):
        self.assertIsNone(env_loader.parse_env_line("   "))

    def test_line_without_equals_returns_none(self):
        self.assertIsNone(env_loader.parse_env_line("not a valid line"))

    def test_inline_comment_value_is_actually_usable_as_a_float(self):
        # The regression this issue exists to prevent: this must not raise.
        _, v = env_loader.parse_env_line(
            "SLO_MTTD_MAX_MIN=10         # Max Mean Time to Detect (in minutes)")
        self.assertEqual(float(v), 10.0)

    def test_non_ascii_whitespace_before_hash_is_not_treated_as_a_comment(self):
        # security-auditor review: \s is Unicode-aware and would match e.g.
        # U+00A0 (no-break space) — bash's real $IFS-based word-splitting
        # does not treat that as a separator, so neither should this parser.
        line = "KEY=value\u00a0#notacomment"  # explicit escape, not a literal invisible byte
        self.assertEqual(env_loader.parse_env_line(line), ("KEY", "value\u00a0#notacomment"))

    # --- security-auditor review: malformed-key rejection ---------------------
    def test_empty_key_returns_none(self):
        # Would otherwise reach os.environ.setdefault("", v), which raises.
        self.assertIsNone(env_loader.parse_env_line("=novalue"))

    def test_key_with_embedded_space_returns_none(self):
        self.assertIsNone(env_loader.parse_env_line("KEY WORD=value"))

    def test_key_with_leading_or_trailing_space_is_stripped_and_accepted(self):
        # "KEY = value" — a plain key/value with incidental spacing around
        # "=" (unlike a genuinely malformed key) should still resolve, with
        # the value's own incidental whitespace stripped too (security-
        # auditor review: bash itself would reject "KEY = value" outright as
        # a command rather than an assignment — a leading space silently
        # surviving into the returned value would be a worse divergence
        # than stripping it).
        self.assertEqual(env_loader.parse_env_line("KEY = value"), ("KEY", "value"))

    def test_key_starting_with_digit_returns_none(self):
        self.assertIsNone(env_loader.parse_env_line("1KEY=value"))

    def test_malformed_key_warns_on_stderr(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            result = env_loader.parse_env_line("KEY WORD=value")
        self.assertIsNone(result)
        self.assertIn("KEY WORD", buf.getvalue())
        # security-auditor review: the warning must name the offending key
        # only — never the value, which for a genuinely malformed line
        # (unlike a comment-truncation warning) it never even has.
        self.assertNotIn("value", buf.getvalue())

    def test_malformed_key_warning_truncates_a_very_long_key(self):
        # security-auditor review: "key" is arbitrary operator-supplied text
        # up to the first "=" — a value pasted with no "=" of its own (a
        # stray base64/PEM fragment) must not land in the journal in full.
        long_key = "A" * 100
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            env_loader.parse_env_line(f"{long_key} B=value")
        self.assertNotIn(long_key, buf.getvalue())
        self.assertIn("A" * 32, buf.getvalue())

    def test_well_formed_key_is_silent(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            env_loader.parse_env_line("ELASTIC_PASSWORD=hunter2")
        self.assertEqual(buf.getvalue(), "")


class TruncationWarningTests(unittest.TestCase):
    """security-auditor review: silently truncating a credential-shaped
    value at an inline comment is worse than truncating an ordinary
    override — must be loud (stderr), even though no credential in
    .env.example's documented openssl-generated format could ever trigger
    this in practice."""

    def test_credential_key_truncation_warns_on_stderr(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            result = env_loader.parse_env_line("SOME_PASSWORD=abc123  # oops")
        self.assertEqual(result, ("SOME_PASSWORD", "abc123"))
        self.assertIn("SOME_PASSWORD", buf.getvalue())

    def test_non_credential_key_truncation_is_silent(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            result = env_loader.parse_env_line("SLO_MTTD_MAX_MIN=10  # comment")
        self.assertEqual(result, ("SLO_MTTD_MAX_MIN", "10"))
        self.assertEqual(buf.getvalue(), "")

    def test_credential_key_without_truncation_is_silent(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            result = env_loader.parse_env_line("SOME_PASSWORD=abc123")
        self.assertEqual(result, ("SOME_PASSWORD", "abc123"))
        self.assertEqual(buf.getvalue(), "")

    def test_credential_pattern_covers_access_relevant_key_shapes(self):
        # security-auditor review: the pattern originally missed several
        # access-relevant shapes actually used by this repo's own secrets
        # (NTFY_TOPIC is a bearer capability — anyone who knows it can
        # publish/subscribe) or plausible future ones (*_CRED, *_AUTH).
        # code-reviewer catch: SOME_API_KEY/SOME_SECRET_VALUE/SOME_TOKEN
        # cover the original SECRET/KEY/TOKEN alternation terms directly —
        # TruncationWarningTests' other cases stopped exercising them
        # positively once NOT_A_SECRET_KEY (which accidentally DID match)
        # was renamed to SOME_OTHER_VALUE elsewhere in this file.
        for key in ("SOME_PWD", "SOME_CRED", "SOME_AUTH", "SOME_SALT",
                    "SOME_SIGNING", "SOME_PRIVATE", "NTFY_TOPIC",
                    "SOME_API_KEY", "SOME_SECRET_VALUE", "SOME_TOKEN"):
            with self.subTest(key=key):
                buf = io.StringIO()
                with contextlib.redirect_stderr(buf):
                    result = env_loader.parse_env_line(f"{key}=abc123  # oops")
                self.assertEqual(result, (key, "abc123"))
                self.assertIn(key, buf.getvalue())


class LoadEnvFileTests(unittest.TestCase):
    def test_missing_file_is_a_no_op(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            env_loader.load_env_file(Path("/nonexistent-path-for-test/.env"))
        # No exception is the assertion here.

    def test_sets_a_var_not_already_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_text("SOME_NEW_TEST_VAR=fromfile\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SOME_NEW_TEST_VAR", None)
                env_loader.load_env_file(env_path)
                self.assertEqual(os.environ["SOME_NEW_TEST_VAR"], "fromfile")

    def test_process_env_wins_over_file(self):
        # security-auditor review: the security-relevant property — a value
        # already in the process environment (e.g. a hardened systemd
        # Environment=ES_CA=... set after a unit's own EnvironmentFile=)
        # must never be downgraded by a stale/tampered .env.
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_text("ES_CA=/tmp/evil-ca.crt\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"ES_CA": "/trusted/ca.crt"}):
                env_loader.load_env_file(env_path)
                self.assertEqual(os.environ["ES_CA"], "/trusted/ca.crt")

    def test_duplicate_key_within_file_resolves_to_last_occurrence(self):
        # security-auditor review: bash `set -a; . .env` and systemd's own
        # EnvironmentFile= both take the LAST duplicate-key line, not the
        # first — a rotation workflow that appends a new value below an old
        # one (e.g. .env.bak.preRotate-style) must resolve identically here,
        # not silently keep the stale first value.
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_text(
                "SOME_ROTATING_VAR=old_value\nSOME_ROTATING_VAR=new_value\n",
                encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SOME_ROTATING_VAR", None)
                env_loader.load_env_file(env_path)
                self.assertEqual(os.environ["SOME_ROTATING_VAR"], "new_value")

    def test_inline_comment_line_in_a_real_file_loads_cleanly(self):
        # End-to-end: the actual regression this issue exists to prevent,
        # exercised through the real file-reading path (not just the parser).
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_text(
                "SLO_MTTD_MAX_MIN=10         # Max Mean Time to Detect (in minutes)\n",
                encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SLO_MTTD_MAX_MIN", None)
                env_loader.load_env_file(env_path)
                self.assertEqual(float(os.environ["SLO_MTTD_MAX_MIN"]), 10.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
