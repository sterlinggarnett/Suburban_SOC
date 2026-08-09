#!/usr/bin/env python3
# =============================================================================
# env_loader.py — shared .env line parser + loader for scripts invoked
# directly (python3 slo_metrics.py / run_hunts.py, per their systemd/cron
# entrypoints) rather than via bash's `set -a; . .env; set +a` sourcing,
# which every OTHER script in this repo gets comment-stripping from for
# free (#259).
#
# Usage:
#   import env_loader
#   env_loader.load_env_file(ENV)   # ENV = REPO / "scripts" / "setup" / ".env"
#
# security-auditor review (#259 round 2): os.environ.setdefault() is THE
# security-relevant property here — a value already present in the process
# environment (e.g. a hardened systemd Environment=ES_CA=... set AFTER a
# unit's own EnvironmentFile=) always wins over whatever this file says, so
# a stale/tampered .env can never downgrade it. See load_env_file()'s own
# docstring for the one place this invariant does NOT hold (systemd's
# EnvironmentFile= itself, if pointed at the raw .env — configs/systemd/
# slo-metrics.service used to do exactly that; fixed there, not here) and
# for the file's OWN duplicate-key semantics (last line wins, matching bash
# and systemd — that's a separate, non-conflicting axis from the
# process-env-wins-over-file rule above).
# =============================================================================
import os
import re
import sys

# security-auditor review: [ \t] (not \s) — \s is Unicode-aware and matches
# things like U+00A0 (no-break space), which bash's actual $IFS-based word
# splitting does not treat as a separator. [ \t] mirrors bash's real
# comment-boundary behavior exactly instead of only approximating it.
_INLINE_COMMENT_RE = re.compile(r"[ \t]+#")
# Key must be a plausible shell/environment identifier — rejects an empty
# key (=value), a key with an embedded space (KEY WORD=value, which would
# otherwise silently os.environ.setdefault() an unusable variable name), and
# any other shape nothing in this repo's .env.example ever produces.
_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Case-insensitive: flags a warning only for keys that plausibly hold a
# secret or other access-relevant value, so an ordinary SLO_* override
# doesn't print anything for the routine, expected case.
_CREDENTIAL_KEY_RE = re.compile(
    r"(PASS|PWD|SECRET|KEY|TOKEN|CRED|AUTH|SALT|SIGNING|PRIVATE|TOPIC)",
    re.IGNORECASE)


def parse_env_line(line):
    """Parses one scripts/setup/.env line into (key, value), or None for a
    blank/comment/malformed line.

    #259: this hand-rolled parser used to take the whole line remainder as
    the value — a real "KEY=10   # comment" style .env line broke
    float()/int() conversion downstream, at import time, before main() ever
    ran, in whichever script read it. The inline-comment regex only matches
    a `#` preceded by whitespace, so a value that legitimately contains "#"
    with no space before it (a password, a URL fragment) is left untouched
    — same distinction bash's own word-splitting makes for scripts that
    source .env via `set -a; . .env; set +a` instead of this hand-rolled
    loader.

    security-auditor review (#259 round 2): a line whose key doesn't match
    _KEY_RE is dropped with a stderr warning (key name only, never the
    value) rather than silently — a rejection nothing tells the operator
    about is exactly the class of bug #259 itself was. If stripping an
    inline comment actually changes a credential-shaped key's value, that
    also warns — a secret containing " #" (unlikely; every credential in
    .env.example is openssl-generated and cannot produce one) would
    otherwise be silently truncated with no error anywhere.
    """
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    k, v = line.split("=", 1)
    k = k.strip()
    if not _KEY_RE.fullmatch(k):
        # security-auditor review: "key" here is arbitrary operator-supplied
        # text (everything before the first "="), not a validated identifier
        # — truncate what reaches the journal so a value pasted into .env
        # with no "=" of its own (e.g. a stray base64/PEM fragment) can't
        # land there in full via this path.
        print(f"env_loader: WARNING - ignoring a .env line with a malformed "
              f"key ({k[:32]!r}{'...' if len(k) > 32 else ''}) - keys must "
              f"match [A-Za-z_][A-Za-z0-9_]*.", file=sys.stderr)
        return None
    comment_stripped_v = _INLINE_COMMENT_RE.split(v, maxsplit=1)[0]
    if comment_stripped_v != v and _CREDENTIAL_KEY_RE.search(k):
        print(f"env_loader: WARNING - {k}'s value contained \" #\" and was "
              f"truncated there (treated as an inline comment). If that "
              f"was meant to be part of the value, remove the space before "
              f"the \"#\".", file=sys.stderr)
    return k, comment_stripped_v.strip()


def load_env_file(path):
    """Reads a scripts/setup/.env-style file, calling os.environ.setdefault()
    for every parsed KEY=value line. No-op if path doesn't exist.

    setdefault() (never direct assignment) is deliberate: anything already
    present in the process environment — including a value a systemd unit's
    own hardened Environment= directive set — always wins over whatever this
    file says, so a stale or tampered .env can never downgrade it.

    Within the file itself, a repeated key resolves to its LAST occurrence
    (matching bash `set -a; . .env` and systemd's own EnvironmentFile=
    duplicate-key handling — both take the last, not the first) — parsed
    fully into a dict before any os.environ.setdefault() call, rather than
    setdefault()-ing line by line, which would have made the FIRST
    occurrence win instead and silently diverged from every other consumer
    of this same file (security-auditor review).
    """
    if not path.exists():
        return
    parsed_vars = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parsed = parse_env_line(line)
        if parsed:
            k, v = parsed
            parsed_vars[k] = v
    for k, v in parsed_vars.items():
        os.environ.setdefault(k, v)
