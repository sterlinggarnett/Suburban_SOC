#!/usr/bin/env python3
"""
Grok/JSON parse-failure golden-file tests (audit #169).

SCOPE (matches tests/detections/sigma_eval.py's documented scope exactly):
this is a re-implementation of the sshd auth.log grok pattern and the Zeek
ndjson parsing behavior from configs/logstash.conf, for fast fixture tests
without a live Logstash. It validates parsing LOGIC/intent, NOT the actual
compiled grok engine that runs in the container — a syntax drift between
this regex and the real pattern would not be caught here. The sshd regex
below is a direct manual translation of the exact grok pattern at
configs/logstash.conf's auth.log block; keep them in sync by hand.

Covers both parse-failure classes the pipeline tags:
  * _grokparsefailure — sshd auth.log lines that don't match the anchored
    grok pattern (configs/logstash.conf, auth.log block)
  * _jsonparsefailure  — malformed Zeek ndjson lines (Filebeat's json codec)

Run:  python tests/pipeline/test_grok_parse_failures.py  (or: pytest tests/pipeline)
"""

import json
import re
import unittest

# Direct translation of configs/logstash.conf's sshd grok pattern:
#   ^%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:[host][name]} sshd\[%{POSINT:[process][pid]}\]:
#   %{WORD:[event][outcome]} %{NOTSPACE:[system][auth][method]} for (?:invalid user )?
#   %{GREEDYDATA:[user][name]} from %{IP:[source][ip]} port %{POSINT:[source][port]}
#   (?:\s+ssh2)?(?:\:.*)?\s*$
# M13 US7 (#230/#243) security review: modern OpenSSH (~6.8+) appends a key-
# fingerprint suffix to publickey lines ("... port 22 ssh2: RSA SHA256:...")
# that the pre-fix pattern's `\s*$` right after " ssh2" could never match,
# grokparsefailure-ing every publickey auth line - see
# test_valid_accepted_publickey_with_fingerprint below, which is a real
# regression test against a real modern OpenSSH log line, not a synthetic
# example the old pattern happened to already handle.
SSHD_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<host_name>[a-zA-Z0-9._-]+)\ssshd\[(?P<pid>[1-9][0-9]*)\]:\s"
    r"(?P<outcome>\w+)\s(?P<auth_method>\S+)\sfor\s(?:invalid user )?"
    r"(?P<user_name>.+)\sfrom\s(?P<source_ip>[0-9a-fA-F.:]+)\sport\s"
    r"(?P<source_port>[1-9][0-9]*)(?:\s+ssh2)?(?:\:.*)?\s*$"
)

# The pipeline's cheap literal pre-filter (configs/logstash.conf:283) — grok
# never even runs unless this matches, regardless of the rest of the line.
AUTH_LOG_PATH = "auth.log"


def sshd_grok_match(message: str, log_path: str = AUTH_LOG_PATH):
    """Mirrors the pipeline's two-stage gate: literal pre-filter, then grok.

    Returns "skipped" (pre-filter excluded it — never reaches grok, matches
    a non-sshd auth.log line like sudo/cron/PAM), "match" (grok succeeded),
    or "grokparsefailure" (reached grok, didn't match — what the pipeline
    tags _grokparsefailure)."""
    if AUTH_LOG_PATH not in log_path or "sshd[" not in message:
        return "skipped"
    return "match" if SSHD_PATTERN.match(message) else "grokparsefailure"


def zeek_json_parse(line: str):
    """Mirrors Filebeat's ndjson codec feeding a JSON line to the json filter —
    returns "match" or "jsonparsefailure" (what the pipeline tags)."""
    try:
        json.loads(line)
        return "match"
    except (json.JSONDecodeError, ValueError):
        return "jsonparsefailure"


class SshdGrokTests(unittest.TestCase):
    def test_valid_failed_password(self):
        msg = "Jul  8 10:15:23 dragon-zord sshd[12345]: Failed password for admin from 203.0.113.7 port 51422 ssh2"
        self.assertEqual(sshd_grok_match(msg), "match")

    def test_valid_accepted_publickey(self):
        msg = "Jul  8 10:16:01 dragon-zord sshd[12346]: Accepted publickey for tjlam from 198.51.100.4 port 22 ssh2"
        self.assertEqual(sshd_grok_match(msg), "match")

    def test_valid_accepted_publickey_with_fingerprint(self):
        # M13 US7 (#230/#243) security review: modern OpenSSH (~6.8+) appends
        # a key-fingerprint suffix to publickey accept/fail lines that the
        # sibling test_valid_accepted_publickey above doesn't have - before
        # the (?:\:.*)? fix, this line failed the grok (the trailing
        # ": RSA SHA256:..." isn't whitespace, so `\s*$` never matched),
        # silently suppressing auth_linux_ssh_root_login.yml for every
        # modern OpenSSH publickey login, root or otherwise.
        msg = ("Jul  8 10:16:01 dragon-zord sshd[12346]: Accepted publickey for root "
               "from 198.51.100.4 port 22 ssh2: RSA SHA256:AbCdEf1234567890abcdefABCDEF1234")
        m = SSHD_PATTERN.match(msg)
        self.assertIsNotNone(m, "publickey line with a fingerprint suffix must still match")
        self.assertEqual(m.group("user_name"), "root")
        self.assertEqual(m.group("source_ip"), "198.51.100.4")

    def test_valid_failed_password_invalid_user(self):
        # "invalid user" phrasing INSIDE the verb+for structure — the (?:invalid
        # user )? optional group the #161 fix added to capture brute-force
        # attempts against non-existent accounts.
        msg = "Jul  8 10:17:45 dragon-zord sshd[12347]: Failed password for invalid user root from 203.0.113.9 port 51500 ssh2"
        self.assertEqual(sshd_grok_match(msg), "match")

    def test_valid_ipv6_source(self):
        msg = "Jul  8 10:18:02 dragon-zord sshd[12348]: Failed password for admin from 2001:db8::dead:beef port 51501 ssh2"
        self.assertEqual(sshd_grok_match(msg), "match")

    def test_standalone_invalid_user_line_not_parsed(self):
        # audit #161 DEFERRED follow-up, now covered here: sshd's OTHER "Invalid
        # user X from Y port Z" log line has no verb ("Failed"/"Accepted") and no
        # auth method — a structurally different message the pattern was never
        # written to match. This is a REAL, currently-unhandled grok parse
        # failure, not a hypothetical.
        msg = "Jul  8 10:19:10 dragon-zord sshd[12349]: Invalid user backup from 203.0.113.11 port 51600"
        self.assertEqual(sshd_grok_match(msg), "grokparsefailure")

    def test_truncated_line_missing_port(self):
        msg = "Jul  8 10:20:00 dragon-zord sshd[12350]: Failed password for admin from 203.0.113.12"
        self.assertEqual(sshd_grok_match(msg), "grokparsefailure")

    def test_empty_message_is_skipped_not_failed(self):
        # No "sshd[" substring -> excluded by the pre-filter before grok ever runs.
        self.assertEqual(sshd_grok_match(""), "skipped")

    def test_garbage_after_sshd_marker(self):
        msg = "Jul  8 10:21:00 dragon-zord sshd[12351]: this is not a real auth line at all"
        self.assertEqual(sshd_grok_match(msg), "grokparsefailure")

    def test_non_sshd_auth_log_line_is_skipped_not_failed(self):
        # sudo/cron/PAM lines never reach grok at all (the literal pre-filter at
        # configs/logstash.conf:283) — this must NOT be tagged _grokparsefailure,
        # it's simply out of scope for this grok block.
        msg = "Jul  8 10:22:00 dragon-zord sudo: tjlam : TTY=pts/0 ; PWD=/home/tjlam ; USER=root ; COMMAND=/bin/ls"
        self.assertEqual(sshd_grok_match(msg), "skipped")

    def test_non_auth_log_path_is_skipped(self):
        msg = "Jul  8 10:15:23 dragon-zord sshd[12345]: Failed password for admin from 203.0.113.7 port 51422 ssh2"
        self.assertEqual(sshd_grok_match(msg, log_path="/var/log/syslog"), "skipped")

    def test_injection_style_username_does_not_hijack_source_ip(self):
        # Regression guard for the #161 HIGH source.ip-spoof fix: an
        # attacker-controlled username containing a fake "from <ip> port <n>"
        # must not let the greedy capture bind to the INJECTED ip/port instead
        # of the real, sshd-appended trailing one.
        msg = ("Jul  8 10:23:00 dragon-zord sshd[12352]: Failed password for "
               "victim from 8.8.8.8 port 22 from 203.0.113.13 port 51700 ssh2")
        result = sshd_grok_match(msg)
        self.assertEqual(result, "match")
        m = SSHD_PATTERN.match(msg)
        self.assertEqual(m.group("source_ip"), "203.0.113.13")
        self.assertEqual(m.group("source_port"), "51700")


class ZeekJsonTests(unittest.TestCase):
    def test_valid_zeek_conn_json(self):
        line = '{"ts":1751234567.123,"id.orig_h":"10.0.0.5","id.resp_h":"93.184.216.34","proto":"tcp"}'
        self.assertEqual(zeek_json_parse(line), "match")

    def test_truncated_json_line(self):
        line = '{"ts":1751234567.123,"id.orig_h":"10.0.0.5","id.resp_h":'
        self.assertEqual(zeek_json_parse(line), "jsonparsefailure")

    def test_non_json_garbage_line(self):
        line = "this is not json at all {{{"
        self.assertEqual(zeek_json_parse(line), "jsonparsefailure")


if __name__ == "__main__":
    unittest.main(verbosity=2)
