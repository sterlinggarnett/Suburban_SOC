#!/usr/bin/env python3
"""
Audit-write failure visibility tests (issue #184).

write_audit()'s ES write failures must never propagate (auditing must not break
alert handling) — but a failure now also writes a best-effort marker doc to
soc-agent-health-<tenant> so a SUSTAINED run of failures is dashboard-visible
(via slo_metrics.py's metric_audit_write_failures()), not just a log line.

Run:  pytest tests/ai_agent/test_audit_write_health.py
"""

import json
import os
import sys
import types
import unittest
from unittest import mock

os.environ["SOC_AGENT_HMAC_SECRET"] = "unit_test_secret"

_stub = types.ModuleType("weekly_ciso_report")
_stub.run_reporting_pipeline = lambda *a, **k: {"status": "stub"}  # type: ignore[attr-defined]
sys.modules["weekly_ciso_report"] = _stub

import agent_app  # noqa: E402,F401 -- imported to smoke-test its own module-level init
import agent  # noqa: E402


class WriteAuditHealthMarkerTests(unittest.TestCase):
    def test_health_marker_written_on_audit_write_failure(self):
        with mock.patch.object(agent.requests, "post",
                               side_effect=ConnectionError("refused")) as m:
            agent.write_audit("quarantine_mac", "system", "acme-corp",
                                   outcome="success", target="AA:BB:CC:DD:EE:FF")
        # Two POST attempts: the original audit write, then the health marker.
        self.assertEqual(m.call_count, 2)
        marker_args, marker_kwargs = m.call_args_list[1]
        self.assertEqual(marker_args[0],
                         f"{agent.ES_HOST}/soc-agent-health-acme-corp/_bulk")
        self.assertIn('"event.action": "audit_write_failed"', marker_kwargs["data"])
        self.assertIn('"target_action": "quarantine_mac"', marker_kwargs["data"])
        self.assertIn('"tenant.id": "acme-corp"', marker_kwargs["data"])

    def test_write_audit_never_raises_even_if_health_marker_also_fails(self):
        # Core acceptance criterion: BOTH writes failing must not raise.
        with mock.patch.object(agent.requests, "post",
                               side_effect=ConnectionError("refused")):
            try:
                agent.write_audit("quarantine_mac", "system", "acme-corp")
            except Exception as e:
                self.fail(f"write_audit() raised unexpectedly: {e}")

    def test_health_marker_not_written_on_audit_write_success(self):
        success = mock.Mock(status_code=200)
        success.json.return_value = {"errors": False, "items": [{"create": {"status": 201}}]}
        with mock.patch.object(agent.requests, "post", return_value=success) as m:
            agent.write_audit("quarantine_mac", "system", "acme-corp")
        # Only the original audit write — no marker needed when it succeeds.
        self.assertEqual(m.call_count, 1)

    def test_health_marker_written_on_embedded_bulk_rejection(self):
        # ES's _bulk endpoint can return HTTP 200 with an embedded per-item
        # error (e.g. a 403 from a missing role privilege) — requests.post
        # never raises for that. write_audit() must still detect it and fall
        # into the same health-marker path as a connection-level failure.
        rejected = mock.Mock(status_code=200)
        rejected.json.return_value = {
            "errors": True,
            "items": [{"create": {"status": 403, "error": {
                "type": "security_exception", "reason": "action denied"}}}],
        }
        rejected.text = json.dumps(rejected.json.return_value)

        accepted = mock.Mock(status_code=200)
        accepted.json.return_value = {"errors": False, "items": [{"create": {"status": 201}}]}
        accepted.text = json.dumps(accepted.json.return_value)

        with mock.patch.object(agent.requests, "post",
                               side_effect=[rejected, accepted]) as m:
            try:
                agent.write_audit("quarantine_mac", "system", "acme-corp",
                                       outcome="success", target="AA:BB:CC:DD:EE:FF")
            except Exception as e:
                self.fail(f"write_audit() raised unexpectedly: {e}")

        # Two POST attempts: the (rejected) original audit write, then the
        # health marker — proving the embedded-error case is detected, not
        # just connection-level exceptions.
        self.assertEqual(m.call_count, 2)
        marker_args, marker_kwargs = m.call_args_list[1]
        self.assertEqual(marker_args[0],
                         f"{agent.ES_HOST}/soc-agent-health-acme-corp/_bulk")
        self.assertIn('"event.action": "audit_write_failed"', marker_kwargs["data"])
        self.assertIn('"target_action": "quarantine_mac"', marker_kwargs["data"])
        self.assertIn('"tenant.id": "acme-corp"', marker_kwargs["data"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
