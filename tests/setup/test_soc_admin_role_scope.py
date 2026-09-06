#!/usr/bin/env python3
"""
#374: `soc_admin` (configs/elasticsearch/roles/soc_admin.json) held `"all"`
on a bare `soc-*` wildcard -- a separation-of-duties gap where the one role
that administers the SOC platform could also silently rewrite or delete
`soc-slo-metrics` (the SOC's own SLO/self-measurement history) or
`soc-agent-health-*` (the audit-write-failure marker index #275/#361 depend
on), with no independent record left to show that kind of tampering
happened.

Fixed by excluding both from the `soc-*` grant using Elasticsearch's
negated-pattern index privilege syntax (a `-`-prefixed entry in the same
`names` array as the wildcard it narrows) -- the same carve-out mechanism
narrower roles in this repo already rely on implicitly by never granting
the broader pattern in the first place; `soc_admin` needed it explicitly
because it holds the wildcard.

Deliberately scoped to exactly what #374 named (`soc-slo-metrics`,
`soc-agent-health-*`) -- NOT `soc-audit-*` or any other `soc-*` index,
which the issue did not raise and which may be a legitimate admin
capability (e.g. retention/ILM management on the audit trail).

#453 extended the same carve-out to `soc-audit-*` -- the append-only,
tamper-evident audit trail (`soc_audit_appender.json` grants only
`create_index`/`create` for exactly this reason) is the single most
sensitive index in this set, and `soc_admin` retaining `all` (including
delete) on it left the platform-admin role able to silently rewrite or
erase the SOC's own record of what an admin identity did -- the identical
exposure class #374 fixed for the other two indices. Confirmed this does
not regress any automated erasure workflow: `scripts/setup/erase_tenant.sh`
(the only code path that legitimately deletes `soc-audit-<tenant>`, for
GDPR/CCPA right-to-erasure) authenticates as the `elastic` superuser via
`ES_USER`/`ES_PASS`, not as `soc_admin` -- no service account is bound to
`soc_admin` in `docker-compose.yml`'s inline role bootstrap; it is a
human-operator role per `docs/SOP-009-rbac.md`.

Pure stdlib, static JSON-structure assertions against the real role file --
no live Elasticsearch, matching this directory's existing convention (see
test_role_compose_sync.py, test_docker_compose_ports.py). Whether
Elasticsearch's negated-pattern privilege model actually enforces this the
way expected should be confirmed against a real cluster before this is
relied on in production -- not exercised here.

Run:  python tests/setup/test_soc_admin_role_scope.py  (or: pytest tests/setup)
"""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLE_PATH = ROOT / "configs" / "elasticsearch" / "roles" / "soc_admin.json"


def _soc_wildcard_entries(role):
    """Every index-privilege entry whose names list grants the soc-*
    wildcard (there should be exactly one -- setUp() fails loudly via a
    real unittest assertion, not a bare `assert`, if that ever breaks, so
    the check survives running under `python -O`)."""
    return [entry for entry in role["indices"] if "soc-*" in entry["names"]]


class SocAdminWildcardCarveOutTests(unittest.TestCase):
    def setUp(self):
        self.role = json.loads(ROLE_PATH.read_text(encoding="utf-8"))
        matches = _soc_wildcard_entries(self.role)
        self.assertEqual(
            len(matches),
            1,
            f"expected exactly one indices entry granting soc-*, found "
            f"{len(matches)} -- soc_admin.json's structure has changed in a "
            f"way this test doesn't understand",
        )
        self.entry = matches[0]

    def test_still_grants_the_soc_wildcard(self):
        # The fix must narrow the grant, not remove SOC-platform admin
        # capability outright.
        self.assertIn("soc-*", self.entry["names"])
        self.assertIn("all", self.entry["privileges"])

    def test_excludes_soc_slo_metrics(self):
        self.assertIn(
            "-soc-slo-metrics",
            self.entry["names"],
            "soc_admin must not hold 'all' on soc-slo-metrics -- it would "
            "let the admin role silently rewrite/erase the SOC's own SLO "
            "measurement history (#374)",
        )

    def test_excludes_soc_agent_health(self):
        self.assertIn(
            "-soc-agent-health-*",
            self.entry["names"],
            "soc_admin must not hold 'all' on soc-agent-health-* -- it "
            "would let the admin role silently rewrite/erase the audit-"
            "write-failure marker index #275/#361 depend on (#374)",
        )

    def test_excludes_soc_audit(self):
        self.assertIn(
            "-soc-audit-*",
            self.entry["names"],
            "soc_admin must not hold 'all' on soc-audit-* -- it would let "
            "the admin role silently rewrite/erase the SOC's own "
            "tamper-evident audit trail, including the record of what an "
            "admin identity did (#453)",
        )

    def test_excludes_soc_health(self):
        self.assertIn(
            "-soc-health",
            self.entry["names"],
            "soc_admin must not hold 'all' on soc-health -- #555 promoted that "
            "index from ordinary dashboard data to a monitoring-integrity "
            "signal (metric_soc_health_stale_seconds() is the only thing that "
            "notices the health lane dying), so an analyst-tier role able to "
            "POST one document with a current @timestamp could stop the timer "
            "and keep the SLO lane reporting the health lane as alive "
            "indefinitely. Index DELETION was already caught via BREACH_IF_NA; "
            "forgery was not caught at all (security-auditor, #555 HIGH 2)",
        )

    def test_does_not_exclude_anything_beyond_374_453_and_555(self):
        # Deliberately scoped: every other soc-* index is untouched --
        # expanding this carve-out further is a separate decision, not a
        # side effect of a fix. -soc-health joined in #555 as its own
        # deliberate decision, for the reason on the test directly above:
        # the two self-monitoring OUTPUT indices (soc-slo-metrics, soc-health)
        # are now both here, which is the invariant to preserve -- if a third
        # lane is ever added, its output index belongs in this set too.
        excluded = {name for name in self.entry["names"] if name.startswith("-")}
        self.assertEqual(
            excluded,
            {"-soc-slo-metrics", "-soc-health", "-soc-agent-health-*", "-soc-audit-*"},
        )


if __name__ == "__main__":
    unittest.main()
