#!/usr/bin/env python3
"""
ntfy/Discord notification IOC masking tests (issue #177 / NIST AC-4).

ntfy.sh and Discord are public third-party services. By default, the source
IP/MAC in a notification's text must be masked (last IPv4 octet / MAC
OUI-only) — the case, audit trail, and broker dispatch always see the
unmasked value regardless. NOTIFY_INCLUDE_RAW_IOCS=true opts back into raw
IOCs in the notification text.

Run:  pytest tests/ai_agent/test_notify_masking.py
"""

import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

SECRET = "unit_test_secret"
os.environ["SOC_AGENT_HMAC_SECRET"] = SECRET
# #246: separate /approve + /pending credential, same collection-order
# reasoning as above (agent.py reads both at import time).
os.environ.setdefault("SOC_APPROVER_HMAC_SECRET", "unit_test_approver_secret")

_stub = types.ModuleType("weekly_ciso_report")
_stub.run_reporting_pipeline = lambda *a, **k: {"status": "stub"}  # type: ignore[attr-defined]  # dynamic stub module, mypy can't see the assignment
sys.modules["weekly_ciso_report"] = _stub

import agent_app  # noqa: E402
import agent  # noqa: E402

GOOD_MAC = "AA:BB:CC:DD:EE:FF"


class MaskHelperTests(unittest.TestCase):
    """Pure unit tests for the masking helpers — no Flask involved."""

    def test_mask_ip_v4_zeroes_last_octet(self):
        self.assertEqual(agent._mask_ip("203.0.113.42"), "203.0.113.0")

    def test_mask_ip_v6_fully_expanded_truncates_to_slash64(self):
        self.assertEqual(
            agent._mask_ip("2001:db8:1234:5678:9abc:def0:1234:5678"),
            "2001:db8:1234:5678::",
        )

    def test_mask_ip_v6_compressed_form_is_still_masked(self):
        # audit #177: a naive colon-split heuristic treats a "::"-compressed
        # address (the common real-world form) as having too few segments and
        # passes it through completely unmasked. Must go through `ipaddress`,
        # not string splitting.
        self.assertEqual(agent._mask_ip("2001:db8::1"), "2001:db8::")
        self.assertEqual(agent._mask_ip("fe80::1"), "fe80::")
        self.assertEqual(agent._mask_ip("::1"), "::")

    def test_mask_ip_passes_through_non_ip(self):
        # "unknown" (the safe_ip fallback) and malformed input are not validators'
        # business — masking is a display courtesy, so pass through unchanged.
        self.assertEqual(agent._mask_ip("unknown"), "unknown")

    def test_mask_mac_keeps_oui_only(self):
        self.assertEqual(agent._mask_mac(GOOD_MAC), "AA:BB:CC:xx:xx:xx")
        self.assertEqual(agent._mask_mac("aa-bb-cc-dd-ee-ff"), "aa-bb-cc-xx-xx-xx")

    def test_mask_mac_mixed_separators_still_masks_last_three_octets(self):
        # audit #177 follow-up: _MAC_RE allows ':'/'-' independently per position, so
        # a single guessed separator used to leave every octet past that guess
        # unmasked — e.g. splitting "AA:BB-CC:DD-EE:FF" on ':' (the first separator
        # found) yielded "AA:BB-CC:DD-EE:FF-xx-xx-xx", leaking the whole MAC.
        self.assertEqual(agent._mask_mac("AA:BB-CC:DD-EE:FF"), "AA:BB-CC:xx-xx:xx")

    def test_mask_mac_passes_through_invalid(self):
        self.assertEqual(agent._mask_mac(""), "")
        self.assertEqual(agent._mask_mac("not-a-mac"), "not-a-mac")

    def test_mask_notify_ioc_dispatches_by_shape(self):
        self.assertEqual(agent._mask_notify_ioc(GOOD_MAC), "AA:BB:CC:xx:xx:xx")
        self.assertEqual(agent._mask_notify_ioc("203.0.113.42"), "203.0.113.0")
        self.assertEqual(agent._mask_notify_ioc(""), "")
        self.assertEqual(agent._mask_notify_ioc(agent.EXCLUSION_UNVERIFIABLE),
                         agent.EXCLUSION_UNVERIFIABLE)

    def test_is_valid_mac_rejects_trailing_garbage(self):
        # audit #177 follow-up: a second module-level `_MAC_RE` (the unanchored
        # LLM-sanitizer token regex) used to shadow this anchored validator regex,
        # since both were bound to the same name and the sanitizer's definition ran
        # second at import time. is_valid_mac() then accepted anything merely
        # *starting* with a MAC (word-boundary match, not a full-string match),
        # letting trailing injected content ride along into the case/audit/broker
        # dispatch as if it were a validated MAC. Renamed to _MAC_TOKEN_RE so this
        # validator regex is unambiguously the one in effect.
        self.assertTrue(agent.is_valid_mac(GOOD_MAC))
        self.assertFalse(agent.is_valid_mac(GOOD_MAC + "\n# injected"))
        self.assertFalse(agent.is_valid_mac(GOOD_MAC + " extra"))

    def test_sanitize_for_llm_still_redacts_macs(self):
        # Guards the rename (_MAC_RE -> _MAC_TOKEN_RE) didn't leave the sanitizer's
        # own regex reference dangling.
        self.assertEqual(
            agent.sanitize_for_llm(f"device {GOOD_MAC} flagged"),
            "device [REDACTED_MAC] flagged",
        )


def _sign(body: bytes, ts=None):
    ts = ts or str(int(time.time()))
    sig = "sha256=" + hmac.new(SECRET.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return ts, sig


class NotifyWiringTests(unittest.TestCase):
    """Confirms /alert actually substitutes the masked (or raw) IOC into every
    send_soc_alert/send_discord_alert call site, not just that the helpers work
    in isolation."""

    def setUp(self):
        agent_app.app.testing = True
        self.client = agent_app.app.test_client()
        agent._seen_sigs.clear()

        self._qfile = tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8")
        self._qfile.close()
        mock.patch.object(agent, "APPROVAL_QUEUE", self._qfile.name).start()

        # This suite only drives /alert intake (no multi-request approval flow
        # to verify), so the checkpoint store just needs to not hit real ES —
        # a no-op write and "not a duplicate" read are enough (#214).
        mock.patch.object(agent, "write_checkpoint", return_value=None).start()
        mock.patch.object(agent, "is_duplicate", return_value=False).start()

        # Matches the real broker's response shape (hive-mind-broker/app.py) — it
        # embeds the raw attacker IP verbatim in `message`/`detail`, which is
        # exactly what let a raw-IP leak through the ntfy `detail` field slip past
        # notify_ip's masking (audit #177) until the message fixture reflected it.
        mock.patch.object(agent, "dispatch_block_via_broker",
                           return_value=(True, "IP 203.0.113.42 blocked on 1/1 router(s)")).start()
        mock.patch.object(agent, "analyze_alert_with_ai", return_value="stub").start()
        mock.patch.object(agent, "log_soar_action").start()
        mock.patch.object(agent, "create_case", return_value="case-abc123").start()
        mock.patch.object(agent, "add_case_comment").start()
        mock.patch.object(agent, "close_case").start()
        mock.patch.object(agent, "write_audit").start()

        self.mock_soc_alert = mock.patch.object(
            agent, "send_soc_alert", return_value=None).start()
        self.mock_discord = mock.patch.object(
            agent, "send_discord_alert", return_value=None).start()

        self.addCleanup(mock.patch.stopall)
        self.addCleanup(lambda: os.unlink(self._qfile.name))

    def _post(self, payload, path="/alert"):
        body = json.dumps(payload).encode()
        ts, sig = _sign(body)
        headers = {
            "Content-Type": "application/json",
            "x-elastic-signature": sig,
            "x-elastic-timestamp": ts,
        }
        return self.client.post(path, data=body, headers=headers)

    def test_drafted_alert_masks_ip_by_default(self):
        with mock.patch.object(agent, "NOTIFY_INCLUDE_RAW_IOCS", False):
            r = self._post({"severity": "medium", "source_ip": "203.0.113.42",
                            "source_mac": GOOD_MAC})
        self.assertEqual(r.status_code, 200)
        message = self.mock_soc_alert.call_args.kwargs["message"]
        self.assertNotIn("203.0.113.42", message)
        self.assertNotIn(GOOD_MAC, message)

    def test_drafted_alert_includes_raw_ioc_when_opted_in(self):
        # The drafted-action message displays a single target (IP, falling back to
        # MAC) — assert that one value is the raw IP, not the masked ".0" form.
        with mock.patch.object(agent, "NOTIFY_INCLUDE_RAW_IOCS", True):
            r = self._post({"severity": "medium", "source_ip": "203.0.113.42",
                            "source_mac": GOOD_MAC})
        self.assertEqual(r.status_code, 200)
        message = self.mock_soc_alert.call_args.kwargs["message"]
        self.assertIn("203.0.113.42", message)
        self.assertNotIn("203.0.113.0", message)

    def test_autonomous_isolation_masks_ntfy_and_discord_by_default(self):
        with mock.patch.object(agent, "AUTONOMOUS_ISOLATION", True), \
             mock.patch.object(agent, "NOTIFY_INCLUDE_RAW_IOCS", False):
            r = self._post({"severity": "critical", "source_ip": "203.0.113.42",
                            "source_mac": GOOD_MAC})
        self.assertEqual(r.get_json()["status"], "auto_isolated")

        soc_message = self.mock_soc_alert.call_args.kwargs["message"]
        self.assertNotIn("203.0.113.42", soc_message)
        self.assertNotIn(GOOD_MAC, soc_message)

        self.mock_discord.assert_called_once()
        discord_kwargs = self.mock_discord.call_args.kwargs
        self.assertEqual(discord_kwargs["device_ip"], "203.0.113.0")
        self.assertEqual(discord_kwargs["device_mac"], "AA:BB:CC:xx:xx:xx")

    def test_autonomous_isolation_case_and_audit_keep_raw_ioc(self):
        # Masking is presentation-only for the two public egress points — the
        # authenticated Kibana case and audit trail must retain full fidelity.
        with mock.patch.object(agent, "AUTONOMOUS_ISOLATION", True), \
             mock.patch.object(agent, "NOTIFY_INCLUDE_RAW_IOCS", False):
            self._post({"severity": "critical", "source_ip": "203.0.113.42",
                       "source_mac": GOOD_MAC})
        create_case_args = agent.create_case.call_args[0]
        self.assertIn("203.0.113.42", create_case_args)
        self.assertIn(GOOD_MAC, create_case_args)

    def test_excluded_asset_alert_masks_by_default(self):
        # governance/exclusion_list.txt contains 192.168.1.1 (see test_alert_auth.py).
        with mock.patch.object(agent, "NOTIFY_INCLUDE_RAW_IOCS", False):
            r = self._post({"severity": "critical", "source_ip": "192.168.1.1",
                            "source_mac": GOOD_MAC})
        self.assertEqual(r.get_json()["status"], "no_action_protected_asset")
        message = self.mock_soc_alert.call_args.kwargs["message"]
        self.assertNotIn("192.168.1.1", message)
        self.assertIn("192.168.1.0", message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
