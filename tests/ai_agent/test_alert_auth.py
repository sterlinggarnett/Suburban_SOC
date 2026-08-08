#!/usr/bin/env python3
"""
SOC AI agent — webhook auth, input validation, and SOAR response-model tests.

Covers WS0.2 (HMAC auth + MAC validation) and the CDP §12.3/§12.4 response model:

  * /alert rejects missing/invalid HMAC signatures (401) and never executes;
  * autonomous containment is OFF by default — a critical alert with a valid MAC
    is DRAFTED for human approval, NOT auto-executed (the industry-standard
    human-in-the-loop posture for a destructive, irreversible action);
  * autonomous execution happens ONLY when an operator opts in
    (AUTONOMOUS_ISOLATION=true);
  * a malicious/invalid MAC never reaches the response path;
  * §12.4 protected assets are never isolated and never even drafted;
  * a drafted action can be listed (/pending) and executed by a human (/approve);
  * execution routes containment to the hive-mind-broker over HMAC (#109) — the
    slim agent never shells out to isolate.sh.

Run:  pytest tests/ai_agent/test_alert_auth.py
"""

import os
import sys
import json
import time
import types
import hmac
import uuid
import hashlib
import tempfile
import threading
import unittest
from unittest import mock

# The shared secret must be set BEFORE importing agent_app (it is read at import).
# setdefault, not "=": agent.py's module-level constants are only computed on the
# FIRST import within the pytest process — other test files in this dir may
# collect first and already have set (and locked in) the same literal values.
SECRET = "unit_test_secret"
os.environ.setdefault("SOC_AGENT_HMAC_SECRET", SECRET)

# #246: /approve and /pending are gated on a SEPARATE secret from /alert's — a
# credential that signs /alert (Logstash's) must not also authorize/view
# containment actions. Also set before import.
APPROVER_SECRET = "unit_test_approver_secret"
os.environ.setdefault("SOC_APPROVER_HMAC_SECRET", APPROVER_SECRET)

# agent_app imports its sibling reporting module at load time; stub it so this
# unit test doesn't pull in PDF/LLM dependencies.
_stub = types.ModuleType("weekly_ciso_report")
_stub.run_reporting_pipeline = lambda *a, **k: {"status": "stub"}  # type: ignore[attr-defined]  # dynamic stub module, mypy can't see the assignment
sys.modules["weekly_ciso_report"] = _stub

import agent_app  # noqa: E402
import agent  # noqa: E402

# An IP guaranteed to be on the permanent exclusion list (governance/exclusion_list.txt).
EXCLUDED_IP = "192.168.1.1"
GOOD_MAC = "AA:BB:CC:DD:EE:FF"


class FakeCheckpointStore:
    """In-memory stand-in for checkpoints.py's ES-backed functions.

    Phase H (#214) made the agent's request flow genuinely ES-dependent
    (checkpoint read/write, the atomic approval claim) — these integration
    tests drive real multi-request state transitions (draft -> approve ->
    re-approve), so a fixed-return mock isn't enough; they need something
    that actually behaves like the store. Thread-safe: the concurrency test
    races two real threads against claim().
    """
    def __init__(self):
        self._docs = {}
        self._claims = set()
        self._lock = threading.Lock()

    def write_checkpoint(self, tenant_id, alert_id, phase, context=None):
        # Mirrors real write_checkpoint()'s ES semantics: PUT _doc/{id} REPLACES
        # the whole document. A call that omits context wipes any previously
        # stored context — this fake must reproduce that, not paper over it,
        # or callers that rely on context surviving would pass here and fail
        # for real.
        with self._lock:
            doc = {"phase": phase}
            if context is not None:
                doc["context"] = context
            self._docs[(tenant_id, alert_id)] = doc

    def read_checkpoint(self, tenant_id, alert_id):
        with self._lock:
            doc = self._docs.get((tenant_id, alert_id))
            return dict(doc) if doc else None

    def is_duplicate(self, tenant_id, alert_id):
        with self._lock:
            return (tenant_id, alert_id) in self._docs

    def is_awaiting_approval(self, tenant_id, alert_id):
        with self._lock:
            doc = self._docs.get((tenant_id, alert_id))
            return bool(doc) and doc.get("phase") == "PENDING_APPROVAL"

    def claim_approval(self, tenant_id, alert_id, approver):
        key = (tenant_id, alert_id)
        with self._lock:
            if key in self._claims:
                return False
            self._claims.add(key)
            return True

    def release_claim(self, tenant_id, alert_id):
        # The real checkpoints.release_claim() marks the claim doc RELEASED
        # (never deletes — agent_checkpoints's ES role has no delete
        # privilege by design, #245/#247) so claim_approval() can re-win it.
        # Freeing an already-free (or never-claimed) key is still success,
        # not an error, matching the real idempotent-on-404 behavior.
        with self._lock:
            self._claims.discard((tenant_id, alert_id))
            return True

    def resolve_claim(self, tenant_id, alert_id):
        # The real checkpoints.resolve_claim() marks the claim doc RESOLVED
        # after a confirmed success — never re-winnable. This fake models
        # that the same way it models release: just no longer a live claim.
        with self._lock:
            self._claims.discard((tenant_id, alert_id))
            return True


def _sign(body: bytes, ts=None, secret=None):
    """Return (timestamp, 'sha256=<hmac>') for the replay-protected scheme: the HMAC
    is over '<timestamp>.' + body (audit P1-1). `secret` defaults to SECRET
    (/alert's); pass APPROVER_SECRET to sign as the /approve + /pending credential."""
    ts = ts or str(int(time.time()))
    key = (secret if secret is not None else SECRET).encode()
    sig = "sha256=" + hmac.new(key, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return ts, sig


class AlertResponseTests(unittest.TestCase):
    def setUp(self):
        agent_app.app.testing = True
        self.client = agent_app.app.test_client()
        # The replay/nonce cache is module-level (audit P1-1); isolate it per test so
        # identical signed requests across tests don't trip replay rejection.
        agent._seen_sigs.clear()

        # Isolate the approval queue to a throwaway file per test.
        self._qfile = tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8")
        self._qfile.close()
        self._qpatch = mock.patch.object(agent, "APPROVAL_QUEUE", self._qfile.name)
        self._qpatch.start()

        # Phase H (#214): /alert and /approve are now genuinely ES-checkpoint-
        # backed. Route them through an in-memory fake so the real
        # draft -> approve -> re-approve state machine (and the atomic claim)
        # is exercised, without a live Elasticsearch.
        self._store = FakeCheckpointStore()
        mock.patch.object(agent, "write_checkpoint", side_effect=self._store.write_checkpoint).start()
        mock.patch.object(agent, "read_checkpoint", side_effect=self._store.read_checkpoint).start()
        mock.patch.object(agent, "is_duplicate", side_effect=self._store.is_duplicate).start()
        mock.patch.object(agent, "is_awaiting_approval", side_effect=self._store.is_awaiting_approval).start()
        mock.patch.object(agent, "claim_approval", side_effect=self._store.claim_approval).start()
        mock.patch.object(agent, "release_claim", side_effect=self._store.release_claim).start()
        mock.patch.object(agent, "resolve_claim", side_effect=self._store.resolve_claim).start()

        # Neutralize outbound side-effects. The broker dispatch is mocked to report
        # a successful block, so the autonomous/approve paths see containment succeed
        # without any real HTTP/SSH. Default return: (ok, detail).
        self.mock_dispatch = mock.patch.object(
            agent, "dispatch_block_via_broker",
            return_value=(True, "IP blocked on 1/1 router(s)")).start()
        for fn in ("analyze_alert_with_ai", "send_soc_alert",
                   "send_discord_alert", "log_soar_action"):
            mock.patch.object(agent, fn, return_value="stub").start()
        # WS2.3: stub Kibana Cases — create returns a fake id; comment/close are
        # tracked so tests can assert the case lifecycle without a live Kibana.
        self.mock_create_case = mock.patch.object(
            agent, "create_case", return_value="case-abc123").start()
        self.mock_case_comment = mock.patch.object(agent, "add_case_comment").start()
        self.mock_close_case = mock.patch.object(agent, "close_case").start()
        # WS3.3: audit writes go to ES — stub them out for unit tests.
        self.mock_audit = mock.patch.object(agent, "write_audit").start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(lambda: os.unlink(self._qfile.name))

    def _post(self, payload, sign=True, tamper=False, path="/alert", ts=None, secret=None):
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if sign:
            # #246: /approve is gated on APPROVER_SECRET, not /alert's SECRET —
            # mirrors what a real operator's client would sign with. An explicit
            # `secret` overrides this (used to prove cross-secret rejection).
            use_secret = secret if secret is not None else (APPROVER_SECRET if path == "/approve" else SECRET)
            tstamp, sig = _sign(body, ts, use_secret)
            if tamper:
                sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
            headers["x-elastic-signature"] = sig
            headers["x-elastic-timestamp"] = tstamp
        return self.client.post(path, data=body, headers=headers)

    def _get_pending(self, sign=True, secret=None):
        """GET /pending is HMAC-gated on APPROVER_SECRET; sign the (empty) body
        like an operator would."""
        headers = {}
        if sign:
            use_secret = secret if secret is not None else APPROVER_SECRET
            tstamp, sig = _sign(b"", secret=use_secret)
            headers["x-elastic-signature"] = sig
            headers["x-elastic-timestamp"] = tstamp
        return self.client.get("/pending", headers=headers)

    # --- WS0.2 authentication ------------------------------------------------
    def test_missing_signature_rejected(self):
        r = self._post({"severity": "critical", "source_mac": GOOD_MAC}, sign=False)
        self.assertEqual(r.status_code, 401)
        self.mock_dispatch.assert_not_called()

    def test_invalid_signature_rejected(self):
        r = self._post({"severity": "critical", "source_mac": GOOD_MAC}, tamper=True)
        self.assertEqual(r.status_code, 401)
        self.mock_dispatch.assert_not_called()

    # --- privileged-endpoint authentication (audit P0-2) ---------------------
    def test_approve_unsigned_rejected_and_never_executes(self):
        # First draft a real action (signed) so a valid target exists to approve.
        draft = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC}).get_json()
        # An UNSIGNED /approve for that action must be refused and never dispatch.
        r = self._post({"id": draft["action_id"], "approver": "attacker"},
                       sign=False, path="/approve")
        self.assertEqual(r.status_code, 401)
        self.mock_dispatch.assert_not_called()

    def test_approve_invalid_signature_rejected(self):
        draft = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC}).get_json()
        r = self._post({"id": draft["action_id"], "approver": "attacker"},
                       tamper=True, path="/approve")
        self.assertEqual(r.status_code, 401)
        self.mock_dispatch.assert_not_called()

    def test_pending_unsigned_rejected(self):
        r = self._get_pending(sign=False)
        self.assertEqual(r.status_code, 401)

    # --- #246: /approve's credential is independent of /alert's --------------
    def test_alert_secret_cannot_sign_approve(self):
        # A credential that signs /alert (Logstash's) must NOT also authorize
        # execution — the core property #246 exists to guarantee.
        draft = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC}).get_json()
        r = self._post({"id": draft["action_id"], "approver": "attacker"},
                       path="/approve", secret=SECRET)
        self.assertEqual(r.status_code, 401)
        self.mock_dispatch.assert_not_called()

    def test_alert_secret_cannot_sign_pending(self):
        r = self._get_pending(secret=SECRET)
        self.assertEqual(r.status_code, 401)

    def test_approver_secret_cannot_sign_alert(self):
        # And the reverse: holding the approval credential must not let a
        # caller forge /alert intake either.
        body = json.dumps({"severity": "critical", "source_mac": GOOD_MAC}).encode()
        ts, sig = _sign(body, secret=APPROVER_SECRET)
        r = self.client.post("/alert", data=body,
                             headers={"Content-Type": "application/json",
                                      "x-elastic-signature": sig,
                                      "x-elastic-timestamp": ts})
        self.assertEqual(r.status_code, 401)

    def test_approve_uses_configured_identity_not_body_field(self):
        # The "approver" field in the request body is unauthenticated,
        # caller-controlled input — the approver of record must come from the
        # trusted, operator-configured identity bound to APPROVER_SECRET instead.
        draft = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC}).get_json()
        r = self._post({"id": draft["action_id"], "approver": "attacker-supplied-name"},
                       path="/approve")
        self.assertEqual(r.status_code, 200)
        comment_text = self.mock_case_comment.call_args[0][-1]
        self.assertIn(agent.APPROVER_IDENTITY, comment_text)
        self.assertNotIn("attacker-supplied-name", comment_text)

    # --- replay protection (audit P1-1) --------------------------------------
    def test_replayed_alert_rejected(self):
        # A valid signed /alert is accepted once; replaying the EXACT same body +
        # timestamp + signature is refused (nonce already seen).
        payload = {"severity": "critical", "source_ip": "1.2.3.4", "source_mac": GOOD_MAC}
        ts = str(int(time.time()))
        first = self._post(payload, ts=ts)
        self.assertEqual(first.status_code, 200)
        replay = self._post(payload, ts=ts)              # identical -> identical signature
        self.assertEqual(replay.status_code, 401)

    def test_stale_timestamp_rejected(self):
        # A correctly-signed request with a timestamp outside the window is refused.
        old = str(int(time.time()) - (agent.HMAC_REPLAY_WINDOW + 60))
        r = self._post({"severity": "critical", "source_mac": GOOD_MAC}, ts=old)
        self.assertEqual(r.status_code, 401)
        self.mock_dispatch.assert_not_called()

    def test_missing_timestamp_rejected(self):
        # A valid signature with NO timestamp header is refused (can't prove freshness).
        body = json.dumps({"severity": "critical"}).encode()
        _, sig = _sign(body)
        r = self.client.post("/alert", data=body,
                             headers={"Content-Type": "application/json",
                                      "x-elastic-signature": sig})  # no timestamp
        self.assertEqual(r.status_code, 401)

    def test_weekly_report_unsigned_rejected(self):
        r = self._post({}, sign=False, path="/weekly-report")
        self.assertEqual(r.status_code, 401)

    # --- §12.3 draft-by-default (autonomous OFF) -----------------------------
    def test_critical_valid_mac_drafts_not_executes_by_default(self):
        r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                        "source_mac": GOOD_MAC})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "drafted")
        self.mock_dispatch.assert_not_called()     # NEVER auto-dispatches by default
        # The drafted action is queued for approval.
        pending = self._get_pending().get_json()["pending"]
        self.assertTrue(any(a["target_mac"] == GOOD_MAC for a in pending))

    def test_malicious_mac_never_dispatches(self):
        r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                        "source_mac": "x; rm -rf / #"})
        self.assertEqual(r.status_code, 200)
        self.mock_dispatch.assert_not_called()

    # --- §12.3 autonomous path (opt-in) --------------------------------------
    def test_autonomous_flag_dispatches_to_broker(self):
        with mock.patch.object(agent, "AUTONOMOUS_ISOLATION", True):
            r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "auto_isolated")
        self.mock_dispatch.assert_called_once()
        # The broker blocks by IP — the attacker IP is the first positional arg.
        self.assertEqual(self.mock_dispatch.call_args[0][0], "1.2.3.4")

    def test_autonomous_flag_still_blocks_invalid_mac(self):
        with mock.patch.object(agent, "AUTONOMOUS_ISOLATION", True):
            r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": "not-a-mac"})
        self.assertEqual(r.status_code, 200)
        self.mock_dispatch.assert_not_called()     # no valid MAC -> never dispatches

    # --- §12.4 exclusion list ------------------------------------------------
    def test_excluded_asset_never_acted_on(self):
        with mock.patch.object(agent, "AUTONOMOUS_ISOLATION", True):
            r = self._post({"severity": "critical", "source_ip": EXCLUDED_IP,
                            "source_mac": GOOD_MAC})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "no_action_protected_asset")
        self.mock_dispatch.assert_not_called()     # protected asset, even with flag on
        # And nothing was drafted for it either.
        pending = self._get_pending().get_json()["pending"]
        self.assertFalse(any(a["target_ip"] == EXCLUDED_IP for a in pending))

    # --- approval flow: human executes a drafted action ----------------------
    def test_pending_then_approve_dispatches(self):
        draft = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC}).get_json()
        action_id = draft["action_id"]
        self.mock_dispatch.assert_not_called()     # still not executed at draft time

        r = self._post({"id": action_id, "approver": "analyst1"}, path="/approve")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "executed")
        self.mock_dispatch.assert_called_once()    # the human approval dispatches it
        self.assertEqual(self.mock_dispatch.call_args[0][0], "1.2.3.4")

    def test_failed_execution_releases_claim_for_retry(self):
        # #247: a failed dispatch (broker down, no routers configured, etc.)
        # must not permanently strand the alert — the claim is released so a
        # retried /approve can win the claim race again once the underlying
        # problem clears, and the failure must be visibly distinct from a
        # real success rather than silently recorded as "approved".
        draft = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC}).get_json()
        action_id = draft["action_id"]

        self.mock_dispatch.return_value = (False, "no routers for tenant 'home-smith'")
        first = self._post({"id": action_id, "approver": "analyst1"}, path="/approve")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.get_json()["status"], "isolation_failed")
        self.mock_dispatch.assert_called_once()

        # Visible in /pending — not silently dropped the moment it was
        # claimed, and distinguishable from an actual success.
        pending = self._get_pending().get_json()["pending"]
        failed_entry = next((a for a in pending if a["id"] == action_id), None)
        self.assertIsNotNone(failed_entry)
        self.assertEqual(failed_entry["status"], "isolation_failed")

        # Retry once the underlying problem is fixed. Different approver
        # string (fresh signature) — avoids the replay/nonce guard rejecting
        # an otherwise byte-identical request signed within the same second.
        self.mock_dispatch.return_value = (True, "IP blocked on 1/1 router(s)")
        second = self._post({"id": action_id, "approver": "analyst2"}, path="/approve")
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.get_json()["status"], "executed")
        self.assertEqual(self.mock_dispatch.call_count, 2)

    def test_approve_twice_does_not_double_execute(self):
        # audit P2-9: re-approving an already-resolved id must NOT dispatch again.
        action_id = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                                "source_mac": GOOD_MAC}).get_json()["action_id"]
        self.assertEqual(self._post({"id": action_id, "approver": "a1"},
                                    path="/approve").status_code, 200)
        self.mock_dispatch.assert_called_once()
        # Second approval of the same id (different approver -> distinct signature, so
        # it passes replay/auth and reaches the dedup): now resolved -> 409 (#214:
        # the ES checkpoint phase is no longer PENDING_APPROVAL, so
        # is_awaiting_approval rejects it before claim_approval is even reached).
        second = self._post({"id": action_id, "approver": "a2"}, path="/approve")
        self.assertEqual(second.status_code, 409)
        self.mock_dispatch.assert_called_once()    # still exactly one dispatch

    def test_concurrent_approve_of_same_id_dispatches_only_once(self):
        # audit #172: under gunicorn's gthread workers, /approve requests are
        # genuinely concurrent (the old single-threaded dev server serialized them
        # implicitly). Two threads racing to approve the SAME action_id — each with
        # a distinct, validly-signed request — must still execute isolation exactly
        # once. A small delay in the mocked dispatch widens the race window so the
        # unlocked read-check-execute this test guards against would otherwise
        # reliably let both requests observe "pending" before either resolves it.
        action_id = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                                "source_mac": GOOD_MAC}).get_json()["action_id"]

        def _slow_dispatch(*a, **k):
            time.sleep(0.05)
            return (True, "IP blocked on 1/1 router(s)")
        self.mock_dispatch.side_effect = _slow_dispatch

        import threading
        results = {}

        def _approve(approver):
            results[approver] = self._post(
                {"id": action_id, "approver": approver}, path="/approve").status_code

        threads = [threading.Thread(target=_approve, args=(f"racer-{i}",)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.mock_dispatch.assert_called_once()
        self.assertEqual(sorted(results.values()), [200, 409])

    # --- WS0.3 tenant-scoped routing (the broker owns router resolution) ------
    def test_named_tenant_passed_to_broker_on_autonomous(self):
        # The agent forwards the tenant; the broker maps it to that tenant's routers.
        with mock.patch.object(agent, "AUTONOMOUS_ISOLATION", True):
            r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC, "tenant_id": "home-smith"})
        self.assertEqual(r.get_json()["status"], "auto_isolated")
        self.mock_dispatch.assert_called_once()
        # dispatch_block_via_broker(attacker_ip, tenant, source_mac=...)
        self.assertEqual(self.mock_dispatch.call_args[0][1], "home-smith")

    # --- WS2.3 alert triage & case tracking ----------------------------------
    def test_alert_opens_tracked_case(self):
        r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                        "source_mac": GOOD_MAC, "tenant_id": "home-smith"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["case_id"], "case-abc123")
        self.mock_create_case.assert_called_once()
        # the SOAR decision is appended to the case timeline
        self.assertTrue(self.mock_case_comment.called)

    def test_approve_closes_case_with_disposition(self):
        draft = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC}).get_json()
        r = self._post({"id": draft["action_id"], "approver": "analyst1"}, path="/approve")
        self.assertEqual(r.get_json()["status"], "executed")
        self.assertEqual(r.get_json()["case_id"], "case-abc123")
        # approval closes the case with a disposition
        self.mock_close_case.assert_called_with("unassigned", "case-abc123",
                                                "true_positive_contained")

    def test_broker_refusal_surfaces_as_isolation_failed(self):
        # When the broker reports no routers for the tenant (it owns inventory),
        # the agent reports isolation_failed — never a silent success.
        self.mock_dispatch.return_value = (False, "no routers for tenant 'neighbor-jones'")
        with mock.patch.object(agent, "AUTONOMOUS_ISOLATION", True):
            r = self._post({"severity": "critical", "source_ip": "1.2.3.4",
                            "source_mac": GOOD_MAC, "tenant_id": "neighbor-jones"})
        self.assertEqual(r.get_json()["status"], "isolation_failed")
        self.mock_dispatch.assert_called_once()


class TenantResolverTests(unittest.TestCase):
    """WS0.3 helper unit tests (no Flask client)."""

    def setUp(self):
        # #277: verify_signature() (now also used on dispatch_block_via_broker's
        # response side) consumes the SAME module-level nonce cache request-side
        # verification uses. Two tests in this class that happen to sign an
        # identical body within the same second would otherwise collide and
        # spuriously fail as a "replayed signature" — clear it per-test, same
        # as the other test class in this file that already does this.
        agent._seen_sigs.clear()

    def test_safe_tenant(self):
        self.assertEqual(agent.safe_tenant("Home-Smith"), "home-smith")
        self.assertEqual(agent.safe_tenant("bad slug!"), "unassigned")
        self.assertEqual(agent.safe_tenant(None), "unassigned")

    def test_ip_excluded_cidr_and_ipv6(self):
        # audit P2-7: exclusion entries may be CIDR or IPv6, not just exact IPv4.
        entries = {"10.0.0.0/24", "2001:db8::/32", "8.8.8.8"}
        self.assertTrue(agent._ip_excluded("10.0.0.5", entries))    # in /24
        self.assertFalse(agent._ip_excluded("10.0.1.5", entries))   # outside
        self.assertTrue(agent._ip_excluded("2001:db8::1", entries)) # IPv6 in /32
        self.assertTrue(agent._ip_excluded("8.8.8.8", entries))     # exact
        self.assertFalse(agent._ip_excluded("nonsense", entries))

    def test_dispatch_fails_closed_without_secret(self):
        # #109: no HIVE_MIND_SECRET => the agent never dispatches (fails closed).
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b""):
            ok, detail = agent.dispatch_block_via_broker("1.2.3.4", "home-smith")
        self.assertFalse(ok)
        self.assertIn("HIVE_MIND_SECRET", detail)

    # --- #247 security-auditor review: the broker's own outcome must not be
    # collapsed into a blanket confirmed-false — a genuinely ambiguous result
    # (the broker itself unsure, or a mid-dispatch failure) must raise
    # IsolationOutcomeUnknown, never return (False, ...) ---------------------
    # #277: matches the b"secret" every test in this class patches
    # agent.HIVE_MIND_SECRET to — _fake_response() signs its body with this
    # SAME secret (and the SAME domain tag agent.py's BROKER_RESPONSE_DOMAIN
    # uses) by default so existing classification tests keep representing a
    # legitimately-signed broker response, not an accidentally-unsigned one
    # now that dispatch_block_via_broker() checks for a signature. Tests
    # that specifically exercise forged/missing/tampered signatures pass
    # sign=False or tamper_signature=True.
    _FAKE_BROKER_SECRET = b"secret"
    _RESPONSE_DOMAIN = b"broker-response:"
    # Every dispatch_block_via_broker() call in this class dispatches this
    # exact IP — auto-injected into json_body so each test doesn't need to
    # repeat it, matching what the real broker now always echoes back.
    # NOT a security check as of round-3: request_id (see
    # _post_echoing_request_id() below) is the actual binding mechanism the
    # agent verifies; attacker_ip is echoed for observability only, same as
    # in the real broker response (app.py's _signed_json_response()
    # docstring). attacker_ip=None opts a test OUT of auto-injection, for a
    # test that wants full control over the mocked json_body's keys.
    _DEFAULT_DISPATCHED_IP = "1.2.3.4"

    def _fake_response(self, status_code, json_body=None, text="", sign=True,
                       tamper_signature=False, attacker_ip=_DEFAULT_DISPATCHED_IP):
        resp = mock.Mock()
        resp.status_code = status_code
        if json_body is not None and attacker_ip is not None and "attacker_ip" not in json_body:
            json_body = {**json_body, "attacker_ip": attacker_ip}
        resp.text = text or str(json_body or "")
        if json_body is not None:
            resp.json.return_value = json_body
            body = json.dumps(json_body).encode("utf-8")
        else:
            resp.json.side_effect = ValueError("no JSON")
            body = (text or "").encode("utf-8")
        resp.content = body
        if sign:
            ts = str(int(time.time()))
            sig = "sha256=" + hmac.new(
                self._FAKE_BROKER_SECRET, self._RESPONSE_DOMAIN + f"{ts}.".encode("utf-8") + body,
                hashlib.sha256).hexdigest()
            if tamper_signature:
                sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
            resp.headers = {"x-elastic-signature": sig, "x-elastic-timestamp": ts}
        else:
            resp.headers = {}
        return resp

    def _post_echoing_request_id(self, status_code, json_body=None, **fake_response_kwargs):
        """#277 round-3: dispatch_block_via_broker() generates a fresh random
        request_id per call (so it can bind the response to this exact call
        — see agent.py's own comment on that check) that a statically-built
        mock response can't know in advance. Returns a side_effect for
        mock.patch.object(agent.requests, "post", ...) that reads the REAL
        outbound request body and echoes back whatever request_id it finds,
        the same way the real broker does."""
        def _side_effect(*args, **kwargs):
            outbound = json.loads(kwargs["data"])
            body = {**(json_body or {}), "request_id": outbound.get("request_id")}
            return self._fake_response(status_code, body, **fake_response_kwargs)
        return _side_effect

    def test_dispatch_confirmed_success_when_broker_reports_it(self):
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", side_effect=self._post_echoing_request_id(
                 200, {"executed": True, "success_count": 1, "unknown_count": 0, "message": "blocked"})):
            ok, detail = agent.dispatch_block_via_broker("1.2.3.4", "home-smith")
        self.assertTrue(ok)

    def test_dispatch_confirmed_failure_on_4xx(self):
        # The broker rejected the request BEFORE ever attempting dispatch
        # (auth/validation) — confirmed non-dispatch, safe to release+retry.
        # Verbatim shape of a real /webhook/dispatch 4xx: FastAPI's
        # HTTPException(status_code=400, detail=...) body is {"detail": "..."},
        # not {"message": "..."} (round-3 security-auditor review).
        resp = self._fake_response(400, {"detail": "attacker_ip is not a valid IP address"})
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", return_value=resp):
            ok, detail = agent.dispatch_block_via_broker("1.2.3.4", "home-smith")
        self.assertFalse(ok)

    def test_dispatch_confirmed_failure_on_broker_502_or_503(self):
        # 502/503 mean the request never reached (or was refused before) the
        # broker's dispatch logic at all — e.g. the broker's own 503 for "HMAC
        # secret not configured" (app.py's _verify()) fires before any dispatch
        # attempt is even possible. Confirmed non-dispatch, unlike 500/504.
        for status in (502, 503):
            with self.subTest(status=status):
                resp = self._fake_response(status, {"detail": "Broker secret not configured"})
                with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
                     mock.patch.object(agent.requests, "post", return_value=resp):
                    ok, detail = agent.dispatch_block_via_broker("1.2.3.4", "home-smith")
                self.assertFalse(ok)

    def test_dispatch_confirmed_failure_on_real_no_routers_response_shape(self):
        # Verbatim shape of /webhook/dispatch's real "no routers configured"
        # response (app.py): 200 status, executed=False, no count keys at all
        # — not the {"executed": True, "success_count": 0, ...} shape the
        # all-routers-confirmed-failed test below uses (a different, also-real
        # scenario). Both must classify as confirmed non-dispatch.
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", side_effect=self._post_echoing_request_id(
                 200, {"status": "no_routers", "executed": False,
                      "message": "No routers configured for tenant 'home-smith' — nothing to block."})):
            ok, detail = agent.dispatch_block_via_broker("1.2.3.4", "home-smith")
        self.assertFalse(ok)

    def test_dispatch_unknown_on_broker_500_or_504(self):
        # 500: the broker's OWN handler code failed partway through (e.g. an
        # exception raised while recording the audit row, AFTER
        # dispatch_block_to_all() already ran). 504: an intermediary gave up
        # waiting while the broker may still have been mid-dispatch. Both
        # genuinely ambiguous — must raise, never return a confirmed False.
        for status in (500, 504):
            with self.subTest(status=status):
                resp = self._fake_response(status, {"detail": "internal error"})
                with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
                     mock.patch.object(agent.requests, "post", return_value=resp):
                    with self.assertRaises(agent.IsolationOutcomeUnknown):
                        agent.dispatch_block_via_broker("1.2.3.4", "home-smith")

    def test_dispatch_unknown_when_no_router_confirmed_but_some_unconfirmed(self):
        # success_count=0 AND unknown_count>0: at least one router's outcome
        # could not be confirmed — the block may already be live there.
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", side_effect=self._post_echoing_request_id(
                 200, {"executed": True, "success_count": 0,
                      "unknown_count": 1, "message": "1 unconfirmed"})):
            with self.assertRaises(agent.IsolationOutcomeUnknown):
                agent.dispatch_block_via_broker("1.2.3.4", "home-smith")

    def test_dispatch_confirmed_success_ignores_a_coexisting_unknown_router(self):
        # At least one router IS confirmed blocked — the overall containment
        # goal is met even if a different router's outcome is unconfirmed.
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", side_effect=self._post_echoing_request_id(
                 200, {"executed": True, "success_count": 1,
                      "unknown_count": 1, "message": "1 ok, 1 unconfirmed"})):
            ok, detail = agent.dispatch_block_via_broker("1.2.3.4", "home-smith")
        self.assertTrue(ok)

    def test_dispatch_confirmed_failure_when_all_routers_confirmed_failed(self):
        # Distinct from "no routers configured" (tested above): routers exist
        # and dispatch was attempted, but every one confirmed-failed (e.g. bad
        # SSH keys) with none unknown — still a safe, confirmed non-dispatch.
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", side_effect=self._post_echoing_request_id(
                 200, {"executed": True, "success_count": 0,
                      "unknown_count": 0, "message": "0/2 routers blocked"})):
            ok, detail = agent.dispatch_block_via_broker("1.2.3.4", "home-smith")
        self.assertFalse(ok)

    def test_dispatch_unknown_on_non_integer_counts(self):
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", side_effect=self._post_echoing_request_id(
                 200, {"executed": True, "success_count": "not-a-number",
                      "unknown_count": 0, "message": "malformed"})):
            with self.assertRaises(agent.IsolationOutcomeUnknown):
                agent.dispatch_block_via_broker("1.2.3.4", "home-smith")

    def test_dispatch_unknown_on_unparseable_200_body(self):
        resp = self._fake_response(200, json_body=None, text="not json")
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", return_value=resp):
            with self.assertRaises(agent.IsolationOutcomeUnknown):
                agent.dispatch_block_via_broker("1.2.3.4", "home-smith")

    def test_dispatch_unknown_on_connection_exception(self):
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post",
                               side_effect=ConnectionError("refused")):
            with self.assertRaises(agent.IsolationOutcomeUnknown):
                agent.dispatch_block_via_broker("1.2.3.4", "home-smith")

    # --- #277: an on-path attacker forging (or blocking/mangling) the broker's
    # response must never be trusted as a confirmed success or confirmed
    # failure — only as IsolationOutcomeUnknown, regardless of how convincing
    # the forged JSON body looks. --------------------------------------------
    def test_dispatch_unknown_on_forged_success_with_no_signature(self):
        # The exact attack #277 fixes: a forged {"executed": True, ...} body
        # with no signature at all must NOT be trusted as a confirmed success.
        resp = self._fake_response(200, {"executed": True, "success_count": 1,
                                          "unknown_count": 0, "message": "blocked"}, sign=False)
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", return_value=resp):
            with self.assertRaises(agent.IsolationOutcomeUnknown):
                agent.dispatch_block_via_broker("1.2.3.4", "home-smith")

    def test_dispatch_tampering_alerts_mask_the_ip_by_default(self):
        # #277 round-4: ntfy.sh is a public third-party service — the same
        # #177/AC-4 masking policy every OTHER send_soc_alert() call in this
        # file already honors must also apply to the two new alerts this
        # fix's own tampering-detection paths raise. A round-4 review found
        # these two call sites were pushing the raw attacker_ip unmasked.
        resp = self._fake_response(200, {"executed": True, "success_count": 1,
                                          "unknown_count": 0, "message": "blocked"}, sign=False)
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent, "NOTIFY_INCLUDE_RAW_IOCS", False), \
             mock.patch.object(agent.requests, "post", return_value=resp), \
             mock.patch.object(agent, "send_soc_alert") as mock_alert:
            with self.assertRaises(agent.IsolationOutcomeUnknown):
                agent.dispatch_block_via_broker("203.0.113.42", "home-smith")
        mock_alert.assert_called_once()
        alert_message = mock_alert.call_args[0][1]
        self.assertNotIn("203.0.113.42", alert_message)
        self.assertIn(agent._mask_ip("203.0.113.42"), alert_message)

    def test_dispatch_unknown_on_forged_failure_with_no_signature(self):
        # The other half of #277's threat model: a forged {"executed": False}
        # must not be trusted as a confirmed non-dispatch either — the real
        # dispatch may have already succeeded before the attacker interfered.
        resp = self._fake_response(200, {"status": "no_routers", "executed": False,
                                          "message": "No routers configured"}, sign=False)
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", return_value=resp):
            with self.assertRaises(agent.IsolationOutcomeUnknown):
                agent.dispatch_block_via_broker("1.2.3.4", "home-smith")

    def test_dispatch_unknown_on_tampered_signature(self):
        resp = self._fake_response(200, {"executed": True, "success_count": 1,
                                          "unknown_count": 0, "message": "blocked"},
                                   tamper_signature=True)
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", return_value=resp):
            with self.assertRaises(agent.IsolationOutcomeUnknown):
                agent.dispatch_block_via_broker("1.2.3.4", "home-smith")

    def test_dispatch_unknown_when_signed_with_wrong_secret(self):
        # A response signed with a DIFFERENT secret than the agent's own
        # HIVE_MIND_SECRET (e.g. a compromised/misconfigured broker, or an
        # attacker who somehow holds a different valid-looking secret) must
        # fail verification exactly like an unsigned response.
        payload = {"executed": True, "success_count": 1, "unknown_count": 0,
                  "message": "blocked", "attacker_ip": "1.2.3.4"}
        body = json.dumps(payload).encode("utf-8")
        ts = str(int(time.time()))
        wrong_sig = "sha256=" + hmac.new(
            b"not-the-real-secret", self._RESPONSE_DOMAIN + f"{ts}.".encode("utf-8") + body,
            hashlib.sha256).hexdigest()
        resp = mock.Mock()
        resp.status_code = 200
        resp.text = str(payload)
        resp.json.return_value = payload
        resp.content = body
        resp.headers = {"x-elastic-signature": wrong_sig, "x-elastic-timestamp": ts}
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", return_value=resp):
            with self.assertRaises(agent.IsolationOutcomeUnknown):
                agent.dispatch_block_via_broker("1.2.3.4", "home-smith")

    def test_dispatch_unknown_on_reflected_own_request_as_fake_response(self):
        # #277 round-2: the exact reflection attack domain separation exists
        # to prevent — an on-path attacker captures the agent's OWN genuine
        # signed REQUEST and returns those SAME bytes back as if they were
        # the broker's response. Without a domain tag this verifies
        # successfully (confirmed empirically during the fix) and resolves
        # to a CONFIRMED non-dispatch (data.get("executed") is absent on a
        # request body), enabling an unsafe retry. Must be IsolationOutcomeUnknown.
        request_body = json.dumps({
            "attacker_ip": "1.2.3.4", "tenant_id": "home-smith",
            "source_mac": "", "approver": "soc-ai-agent"}).encode("utf-8")
        ts, sig = agent.sign_request(b"secret", request_body)  # the REQUEST domain (empty)
        resp = mock.Mock()
        resp.status_code = 200
        resp.text = request_body.decode()
        resp.json.return_value = json.loads(request_body)
        resp.content = request_body
        resp.headers = {"x-elastic-signature": sig, "x-elastic-timestamp": ts}
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", return_value=resp):
            with self.assertRaises(agent.IsolationOutcomeUnknown):
                agent.dispatch_block_via_broker("1.2.3.4", "home-smith")

    def test_dispatch_unknown_on_replayed_response_for_a_different_request(self):
        # #277 round-3: a genuine, correctly-signed response for a DIFFERENT
        # dispatch call — captured earlier, never consumed by the agent so
        # its signature was never cached, then replayed against THIS call —
        # must not be accepted as confirming this one. request_id is a fresh
        # random value per call, so a response carrying any OTHER call's
        # request_id (even one that's a validly-formatted, genuinely-issued
        # id from a real earlier dispatch) can never legitimately match.
        # This is the general case #277 round-2's narrower "different IP
        # only" version missed: same IP different tenant, or same IP+tenant
        # replayed later, are both instances of "different request_id."
        resp = self._fake_response(200, {"executed": True, "success_count": 1,
                                          "unknown_count": 0, "message": "blocked",
                                          "request_id": uuid.uuid4().hex})  # a DIFFERENT call's id
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", return_value=resp):
            with self.assertRaises(agent.IsolationOutcomeUnknown):
                agent.dispatch_block_via_broker("1.2.3.4", "home-smith")

    def test_dispatch_unknown_on_genuinely_signed_response_missing_request_id(self):
        # #277 round-4: a correctly-signed 200 response that simply omits
        # request_id entirely (e.g. an older/mismatched broker deployment,
        # or a bug on the broker's own echo path) must degrade to UNKNOWN,
        # not be silently trusted just because the signature checks out —
        # data.get("request_id") is None here, which can never equal the
        # real uuid4 hex the agent generated for this call.
        resp = self._fake_response(200, {"executed": True, "success_count": 1,
                                          "unknown_count": 0, "message": "blocked"})
        # _fake_response() only auto-injects attacker_ip, not request_id —
        # so this body genuinely has no request_id key at all.
        self.assertNotIn("request_id", resp.json.return_value)
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", return_value=resp):
            with self.assertRaises(agent.IsolationOutcomeUnknown):
                agent.dispatch_block_via_broker("1.2.3.4", "home-smith")

    def test_dispatch_confirmed_success_with_genuinely_signed_response(self):
        # Positive control: a properly-signed response (the default
        # _fake_response() behavior) still classifies normally — #277's
        # acceptance criterion that existing signed round-trips are unaffected.
        with mock.patch.object(agent, "HIVE_MIND_SECRET", b"secret"), \
             mock.patch.object(agent.requests, "post", side_effect=self._post_echoing_request_id(
                 200, {"executed": True, "success_count": 1,
                      "unknown_count": 0, "message": "blocked"})):
            ok, detail = agent.dispatch_block_via_broker("1.2.3.4", "home-smith")
        self.assertTrue(ok)

    # --- #246: an operator misconfiguring the two secrets to be equal must not
    # silently revert the /alert-vs-/approve separation this issue introduced ---
    def test_resolve_approver_secret_rejects_equal_secrets(self):
        same = b"same_value_for_both"
        self.assertEqual(agent._resolve_approver_secret(same, same), b"")

    def test_resolve_approver_secret_keeps_distinct_secrets(self):
        approver, alert = b"approver_secret", b"alert_secret"
        self.assertEqual(agent._resolve_approver_secret(approver, alert), approver)

    def test_resolve_approver_secret_leaves_unset_secret_unset(self):
        # Empty approver secret is the ordinary "not configured" fail-closed case,
        # not the equal-secrets case — must not be compared/misreported as such.
        self.assertEqual(agent._resolve_approver_secret(b"", b"alert_secret"), b"")

    # --- #277 round-2: same misconfiguration class as #246's approver-secret
    # guard, for HIVE_MIND_SECRET vs the /alert-signing HMAC_SECRET -----------
    def test_resolve_hive_mind_secret_rejects_equal_secrets(self):
        same = b"same_value_for_both"
        self.assertEqual(agent._resolve_hive_mind_secret(same, ("SOC_AGENT_HMAC_SECRET", same)), b"")

    def test_resolve_hive_mind_secret_keeps_distinct_secrets(self):
        hive, alert = b"hive_secret", b"alert_secret"
        self.assertEqual(agent._resolve_hive_mind_secret(hive, ("SOC_AGENT_HMAC_SECRET", alert)), hive)

    def test_resolve_hive_mind_secret_leaves_unset_secret_unset(self):
        self.assertEqual(
            agent._resolve_hive_mind_secret(b"", ("SOC_AGENT_HMAC_SECRET", b"alert_secret")), b"")

    def test_resolve_hive_mind_secret_rejects_collision_with_approver_secret(self):
        # #277 round-4: the guard is variadic (checks against every OTHER
        # agent secret, not just HMAC_SECRET) — this exercises the SECOND
        # position specifically, the exact case a round-2.5 review flagged
        # as untested (a collision with APPROVER_HMAC_SECRET, not HMAC_SECRET).
        hive = b"same_value"
        self.assertEqual(agent._resolve_hive_mind_secret(
            hive, ("SOC_AGENT_HMAC_SECRET", b"alert_secret"), ("SOC_APPROVER_HMAC_SECRET", hive)), b"")

    def test_verify_signature_rejects_non_ascii_header_without_raising(self):
        # #277 round-2: hmac.compare_digest() raises TypeError on a non-ASCII
        # str signature header — requests/urllib3 decode response headers as
        # latin-1, so an attacker-controlled response can trigger this. Must
        # degrade to a clean rejection, never an uncaught exception out of
        # the isolation path.
        result = agent.verify_signature(b"body", "sha256=\xe9not-hex", str(int(time.time())),
                                        secret=b"secret")
        self.assertFalse(result)

    def test_hosted_llm_egress_disabled_degrades_gracefully(self):
        # WS1.1 regression: LLM_ALLOW_HOSTED was referenced but never defined, so
        # analyze_alert_with_ai raised NameError -> /alert 500 on every intel hit.
        # With hosted egress disabled it must return a string, never raise.
        with mock.patch.object(agent, "LLM_ALLOW_HOSTED", False), \
             mock.patch.object(agent, "LLM_API_URL",
                               "https://api.openai.com/v1/chat/completions"):
            out = agent.analyze_alert_with_ai("alert: conn to known-bad IP")
        self.assertIsInstance(out, str)
        self.assertIn("skipped", out.lower())

    def test_notify_resolution_prefers_tenant_then_global(self):
        with mock.patch.dict(os.environ, {"NTFY_TOPIC_HOME_SMITH": "tenant-topic"}):
            self.assertEqual(agent.ntfy_topic_for("home-smith"), "tenant-topic")


if __name__ == "__main__":
    unittest.main(verbosity=2)
