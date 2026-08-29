#!/usr/bin/env python3
"""
#304: docker-compose.yml's `provision` service bootstraps several ES roles
inline (a hand-maintained JSON PUT body per role) as a stopgap before the
`roles` service re-applies every configs/elasticsearch/roles/*.json file as
the real source of truth (see that service's own "audit P1-11" comment).
Before #257/#275, only `slo_metrics_reader` had any automated check that its
inline bootstrap copy stayed in sync with its role file -- `logstash_writer`'s
had already drifted once for real (missing `asset-inventory-*`/
`soc-agent-health-*`, fixed by #257). This generalizes that single-role guard
to EVERY role the `provision` service bootstraps inline (9 as of this
writing, up from the 6 this issue was originally filed against -- 3 more
roles gained inline bootstrap copies since), discovered directly from
docker-compose.yml rather than a hardcoded list, so a role added to
`provision` in the future is covered automatically without editing this
file.

Comparison is order-insensitive (a privileges/names array reordering is not
a real drift), and anchored to the actual executing `curl ... -d "..."`
command text via regex, not a whole-file substring search -- a copy that
only appeared in a comment would not satisfy this test.

Live-checked as of this writing: all 9 roles' inline copies already match
their role files byte-for-byte (logstash_writer's #257 fix already covers
the specific drift #304 was filed against) -- this file exists to catch the
NEXT drift, not to fix a currently-live one.

Pure stdlib, static text/regex + JSON-equality assertions against the real
files -- no live Elasticsearch, matching this directory's existing
convention (see test_docker_compose_ports.py, tests/pipeline/
test_mac_correlation.py).

Run:  python tests/setup/test_role_compose_sync.py  (or: pytest tests/setup)
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLES_DIR = ROOT / "configs" / "elasticsearch" / "roles"
COMPOSE_PATH = ROOT / "scripts" / "setup" / "docker-compose.yml"
COMPOSE_TEXT = COMPOSE_PATH.read_text(encoding="utf-8")

# Anchored to the actual executing curl PUT line's -d payload, not a bare
# substring search anywhere in the file (a stray comment containing the same
# JSON would not match this).
_INLINE_ROLE_PUT = re.compile(
    r'/_security/role/(?P<role>\w+)\s+-d\s+"(?P<body>(?:[^"\\]|\\.)*)"'
)


def _canonicalize(value):
    """Recursively normalize dict/list ordering so two structurally-equal
    role definitions compare equal regardless of key or array order."""
    if isinstance(value, dict):
        return {k: _canonicalize(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return sorted(
            (_canonicalize(v) for v in value),
            key=lambda v: json.dumps(v, sort_keys=True),
        )
    return value


def _discover_inline_role_puts():
    """role name -> parsed JSON body, for every _security/role/<name> PUT
    in docker-compose.yml's `provision` service."""
    roles = {}
    for match in _INLINE_ROLE_PUT.finditer(COMPOSE_TEXT):
        name = match.group("role")
        body = match.group("body").replace('\\"', '"')
        roles[name] = json.loads(body)
    return roles


class RoleComposeSyncTests(unittest.TestCase):
    """Every role docker-compose.yml's `provision` service bootstraps inline
    must stay in sync (structurally, not necessarily byte-for-byte) with its
    authoritative configs/elasticsearch/roles/*.json file -- the JSON file
    is what the `roles` service re-applies and therefore what actually wins
    on a full bring-up, but the inline copy is what governs the bootstrap
    window before `roles` runs, so drift between the two is a real, live
    bug, not just cosmetic duplication."""

    def test_at_least_the_known_roles_are_discovered(self):
        # Self-check: if docker-compose.yml's PUT command syntax ever
        # changes shape, this regex could silently stop matching anything,
        # and every test below would vacuously pass on zero roles. Pin a
        # floor so that failure is loud instead of silent.
        discovered = _discover_inline_role_puts()
        self.assertGreaterEqual(
            len(discovered),
            9,
            "expected at least the 9 roles known to be bootstrapped inline "
            "by docker-compose.yml's provision service; found fewer -- the "
            "_INLINE_ROLE_PUT regex may no longer match this file's syntax",
        )

    def test_every_inline_role_put_has_a_role_file(self):
        for role in _discover_inline_role_puts():
            self.assertTrue(
                (ROLES_DIR / f"{role}.json").exists(),
                f"docker-compose.yml bootstraps role '{role}' inline but "
                f"configs/elasticsearch/roles/{role}.json does not exist",
            )

    def test_inline_role_puts_match_their_role_files(self):
        mismatches = []
        for role, inline_body in _discover_inline_role_puts().items():
            role_file = ROLES_DIR / f"{role}.json"
            if not role_file.exists():
                continue  # covered by test_every_inline_role_put_has_a_role_file
            file_body = json.loads(role_file.read_text(encoding="utf-8"))
            if _canonicalize(inline_body) != _canonicalize(file_body):
                mismatches.append(role)
        self.assertEqual(
            mismatches,
            [],
            f"docker-compose.yml's inline bootstrap copy has drifted from "
            f"configs/elasticsearch/roles/*.json for: {mismatches} -- keep "
            f"them in sync (#304)",
        )


if __name__ == "__main__":
    unittest.main()
