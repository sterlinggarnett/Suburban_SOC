import pytest
from fastapi.testclient import TestClient
from unittest import mock
from unittest.mock import AsyncMock
import asyncio
import hmac
import hashlib
import json
import os
import time

# Set the HMAC secret before importing app (read at import).
os.environ["HIVE_MIND_SECRET"] = "test_secret"

import app as broker_app
from app import app, HMAC_SECRET

client = TestClient(app)
# Captured before the autouse _mock_write_denial fixture below ever patches
# broker_app.write_denial, so the two low-level write_denial() unit tests can
# exercise the real implementation while every other test gets the safe stub.
_real_write_denial = broker_app.write_denial

# A tenant + its router count, per the local inventory.yaml.
TENANT = "home-smith"
EXCLUDED_IP = "192.168.1.1"


def _sign(body: bytes, ts=None):
    """Return (timestamp, 'sha256=<hmac>') for the replay-protected scheme: HMAC over
    '<timestamp>.' + body (audit P1-1)."""
    ts = ts or str(int(time.time()))
    sig = "sha256=" + hmac.new(HMAC_SECRET, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return ts, sig


def _signed_headers(body, sign=True, tamper=False, ts=None):
    headers = {}
    if sign:
        tstamp, sig = _sign(body, ts)
        if tamper:
            sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
        headers["x-elastic-signature"] = sig
        headers["x-elastic-timestamp"] = tstamp
    return headers


def _post(payload, sign=True, tamper=False, ts=None):
    body = json.dumps(payload).encode("utf-8")
    return client.post("/webhook/alert", data=body,
                       headers=_signed_headers(body, sign, tamper, ts))


def _get_pending(sign=True):
    """GET /pending is HMAC-gated; sign the (empty) body like an operator would."""
    return client.get("/pending", headers=_signed_headers(b"", sign))


def _approve(payload, sign=True, tamper=False):
    """POST /approve is HMAC-gated; sign the request body."""
    body = json.dumps(payload).encode("utf-8")
    return client.post("/approve", data=body, headers=_signed_headers(body, sign, tamper))


@pytest.fixture(autouse=True)
def _no_real_ssh():
    """Keep the dispatcher from making real SSH calls; reset the queue per test."""
    broker_app._append_action  # touch to ensure import
    broker_app._seen_sigs.clear()   # isolate the replay/nonce cache per test (P1-1)
    if os.path.exists(broker_app.APPROVAL_QUEUE):
        os.remove(broker_app.APPROVAL_QUEUE)
    # #247: dispatch_block_to_all() returns (success_count, unknown_count).
    with mock.patch.object(broker_app, "dispatch_block_to_all",
                           new=AsyncMock(return_value=(1, 0))) as m:
        yield m
    if os.path.exists(broker_app.APPROVAL_QUEUE):
        os.remove(broker_app.APPROVAL_QUEUE)


@pytest.fixture(autouse=True)
def _mock_write_denial():
    """Stub the ES write so denial-persistence tests don't need a real cluster;
    every other test gets a silent no-op instead of a real (and pointless)
    network attempt to 'elasticsearch' (#171)."""
    with mock.patch.object(broker_app, "write_denial", new=AsyncMock()) as m:
        yield m


def test_missing_signature():
    assert client.post("/webhook/alert", json={"attacker_ip": "1.2.3.4"}).status_code == 401


def test_invalid_signature():
    assert _post({"attacker_ip": "1.2.3.4"}, tamper=True).status_code == 401


def test_missing_ip():
    r = _post({"tenant_id": TENANT})
    assert r.status_code == 400


def test_alert_with_tenant_drafts_for_approval(_no_real_ssh):
    r = _post({"attacker_ip": "9.9.9.9", "tenant_id": TENANT})
    assert r.status_code == 200
    assert "approval" in r.json()["message"].lower()
    _no_real_ssh.assert_not_awaited()              # draft does NOT dispatch
    pending = _get_pending().json()["pending"]
    drafted = [a for a in pending if a["attacker_ip"] == "9.9.9.9"]
    assert drafted and drafted[0]["tenant"] == TENANT and drafted[0]["router_count"] >= 1


def test_unknown_tenant_is_no_op(_no_real_ssh):
    r = _post({"attacker_ip": "9.9.9.9", "tenant_id": "ghost-tenant"})
    assert r.status_code == 200
    assert "no routers" in r.json()["message"].lower()
    _no_real_ssh.assert_not_awaited()
    assert _get_pending().json()["count"] == 0   # nothing drafted


def test_missing_tenant_is_no_op(_no_real_ssh):
    # No tenant_id => 'unassigned', which owns no routers => no broadcast.
    r = _post({"attacker_ip": "9.9.9.9"})
    assert r.status_code == 200
    assert "no routers" in r.json()["message"].lower()
    _no_real_ssh.assert_not_awaited()


def test_excluded_ip_refused(_no_real_ssh):
    r = _post({"attacker_ip": EXCLUDED_IP, "tenant_id": TENANT})
    assert r.status_code == 200
    assert "exclusion list" in r.json()["message"].lower()
    assert _get_pending().json()["count"] == 0


# --- audit #164: attacker_ip must be a valid IP before it reaches nft/SSH ------
def test_alert_injection_string_rejected(_no_real_ssh):
    r = _post({"attacker_ip": "1.1.1.1 drop; reboot #", "tenant_id": TENANT})
    assert r.status_code == 400
    _no_real_ssh.assert_not_awaited()
    assert _get_pending().json()["count"] == 0


def test_alert_hostname_rejected(_no_real_ssh):
    r = _post({"attacker_ip": "not-an-ip.example.com", "tenant_id": TENANT})
    assert r.status_code == 400
    _no_real_ssh.assert_not_awaited()


def _post_dispatch(payload, sign=True, tamper=False, ts=None):
    body = json.dumps(payload).encode("utf-8")
    return client.post("/webhook/dispatch", data=body,
                       headers=_signed_headers(body, sign, tamper, ts))


# --- #109: /webhook/dispatch — immediate, pre-approved block -------------------
def test_dispatch_missing_signature():
    assert client.post("/webhook/dispatch", json={"attacker_ip": "9.9.9.9"}).status_code == 401


def test_dispatch_invalid_signature():
    assert _post_dispatch({"attacker_ip": "9.9.9.9"}, tamper=True).status_code == 401


def test_dispatch_missing_ip():
    assert _post_dispatch({"tenant_id": TENANT}).status_code == 400


def test_dispatch_executes_to_tenant_routers(_no_real_ssh):
    r = _post_dispatch({"attacker_ip": "9.9.9.9", "tenant_id": TENANT})
    assert r.status_code == 200
    body = r.json()
    assert body["executed"] is True and body["status"] == "executed"
    _no_real_ssh.assert_awaited_once()                 # actually dispatched, no draft
    routers_arg = _no_real_ssh.await_args[0][0]
    assert routers_arg and all(rt.get("tenant") == TENANT for rt in routers_arg)
    # Recorded as executed (not left pending).
    assert _get_pending().json()["count"] == 0


def test_dispatch_excluded_ip_refused(_no_real_ssh):
    r = _post_dispatch({"attacker_ip": EXCLUDED_IP, "tenant_id": TENANT})
    assert r.status_code == 200
    assert r.json()["executed"] is False
    assert "exclusion list" in r.json()["message"].lower()
    _no_real_ssh.assert_not_awaited()


# --- audit #164: attacker_ip must be a valid IP before it reaches nft/SSH ------
def test_dispatch_injection_string_rejected(_no_real_ssh):
    r = _post_dispatch({"attacker_ip": "1.1.1.1 drop; reboot #", "tenant_id": TENANT})
    assert r.status_code == 400
    _no_real_ssh.assert_not_awaited()


def test_dispatch_hostname_rejected(_no_real_ssh):
    r = _post_dispatch({"attacker_ip": "not-an-ip.example.com", "tenant_id": TENANT})
    assert r.status_code == 400
    _no_real_ssh.assert_not_awaited()


def test_dispatch_valid_ipv6_still_dispatches(_no_real_ssh):
    # Regression guard: the #164 validation must not break legitimate IPv6 input.
    r = _post_dispatch({"attacker_ip": "2001:db8::dead:beef", "tenant_id": TENANT})
    assert r.status_code == 200
    assert r.json()["executed"] is True
    _no_real_ssh.assert_awaited_once()


def test_dispatch_unknown_tenant_is_no_op(_no_real_ssh):
    r = _post_dispatch({"attacker_ip": "9.9.9.9", "tenant_id": "ghost-tenant"})
    assert r.status_code == 200
    assert r.json()["executed"] is False
    assert "no routers" in r.json()["message"].lower()
    _no_real_ssh.assert_not_awaited()


def test_approve_dispatches_only_to_tenant_routers(_no_real_ssh):
    _post({"attacker_ip": "9.9.9.9", "tenant_id": TENANT})
    # pull the drafted id
    action_id = [a for a in _get_pending().json()["pending"]
                 if a["attacker_ip"] == "9.9.9.9"][0]["id"]

    r = _approve({"id": action_id, "approver": "analyst1"})
    assert r.status_code == 200
    assert r.json()["status"] == "executed"
    _no_real_ssh.assert_awaited_once()
    routers_arg = _no_real_ssh.await_args[0][0]
    assert routers_arg and all(rt.get("tenant") == TENANT for rt in routers_arg)


# --- audit P0-2: /approve and /pending must be authenticated ------------------
def test_approve_unsigned_rejected_and_never_dispatches(_no_real_ssh):
    # Draft a real action (signed), then attempt to approve it UNSIGNED.
    _post({"attacker_ip": "9.9.9.9", "tenant_id": TENANT})
    action_id = [a for a in _get_pending().json()["pending"]
                 if a["attacker_ip"] == "9.9.9.9"][0]["id"]
    r = _approve({"id": action_id, "approver": "attacker"}, sign=False)
    assert r.status_code == 401
    _no_real_ssh.assert_not_awaited()          # never executed the block


def test_approve_invalid_signature_rejected(_no_real_ssh):
    _post({"attacker_ip": "9.9.9.9", "tenant_id": TENANT})
    action_id = [a for a in _get_pending().json()["pending"]
                 if a["attacker_ip"] == "9.9.9.9"][0]["id"]
    r = _approve({"id": action_id, "approver": "attacker"}, tamper=True)
    assert r.status_code == 401
    _no_real_ssh.assert_not_awaited()


# --- audit #164: a corrupted queue entry must not crash /approve --------------
def test_approve_corrupted_queue_entry_rejected(_no_real_ssh):
    # Simulate a drafted action whose attacker_ip was never validated (e.g. a
    # manually-edited or pre-#164 queue file) rather than relying on _post,
    # which now validates at draft time and could never produce this state.
    broker_app._append_action({
        "id": "deadbeef0001", "ts": time.time(), "status": "pending",
        "tenant": TENANT, "attacker_ip": "not-an-ip", "router_count": 1,
    })
    r = _approve({"id": "deadbeef0001", "approver": "analyst1"})
    assert r.status_code == 422
    _no_real_ssh.assert_not_awaited()


def test_pending_unsigned_rejected():
    assert client.get("/pending").status_code == 401


# --- audit P1-3: SSH host-key verification is strict by default -----------------
def test_known_hosts_strict_by_default():
    import dispatcher
    with mock.patch.object(dispatcher, "INSECURE_SSH", False):
        # Returns the known_hosts PATH (asyncssh then verifies), never None.
        assert dispatcher._resolve_known_hosts() == dispatcher.KNOWN_HOSTS
        assert dispatcher._resolve_known_hosts() is not None


def test_known_hosts_insecure_opt_out_returns_none():
    import dispatcher
    with mock.patch.object(dispatcher, "INSECURE_SSH", True):
        assert dispatcher._resolve_known_hosts() is None


# --- audit P1-1: replay protection on the dispatch path ------------------------
def test_replayed_dispatch_rejected(_no_real_ssh):
    # An immediate dispatch is accepted once; replaying the EXACT same body +
    # timestamp + signature is refused (nonce already seen).
    payload = {"attacker_ip": "9.9.9.9", "tenant_id": TENANT}
    ts = str(int(time.time()))
    first = _post_dispatch(payload, ts=ts)
    assert first.status_code == 200 and first.json()["executed"] is True
    replay = _post_dispatch(payload, ts=ts)
    assert replay.status_code == 401
    _no_real_ssh.assert_awaited_once()          # the replay never reaches dispatch


def test_stale_timestamp_rejected(_no_real_ssh):
    old = str(int(time.time()) - (broker_app.HMAC_REPLAY_WINDOW + 60))
    r = _post_dispatch({"attacker_ip": "9.9.9.9", "tenant_id": TENANT}, ts=old)
    assert r.status_code == 401
    _no_real_ssh.assert_not_awaited()


def test_missing_timestamp_rejected():
    # A valid signature with no timestamp header is refused.
    body = json.dumps({"attacker_ip": "9.9.9.9", "tenant_id": TENANT}).encode("utf-8")
    _, sig = _sign(body)
    r = client.post("/webhook/dispatch", data=body,
                    headers={"x-elastic-signature": sig})  # no timestamp
    assert r.status_code == 401


# --- audit P2-7: exclusion list supports CIDR + IPv6 --------------------------
def test_exclusion_supports_cidr_and_ipv6():
    import dispatcher
    with mock.patch.object(dispatcher, "load_excluded_ips",
                           return_value={"10.0.0.0/24", "2001:db8::/32"}):
        assert dispatcher.is_excluded_ip("10.0.0.5") is True      # inside the /24
        assert dispatcher.is_excluded_ip("10.0.1.5") is False     # outside it
        assert dispatcher.is_excluded_ip("2001:db8::1") is True   # IPv6 in the /32
        assert dispatcher.is_excluded_ip("2001:dead::1") is False
        # audit #164: a malformed address must be REJECTED, not silently
        # treated as "not excluded" (which previously let it flow on to
        # build_nft_command / an SSH-executed command).
        with pytest.raises(ValueError):
            dispatcher.is_excluded_ip("not-an-ip")


# --- #171: denied/replayed/invalid-signature requests are persisted, not just
# returned as an HTTP response (AU-2/3/12) ------------------------------------

def test_missing_signature_writes_denial_record(_mock_write_denial):
    client.post("/webhook/alert", json={"attacker_ip": "1.2.3.4"})
    _mock_write_denial.assert_awaited_once()
    assert _mock_write_denial.await_args[0][0] == "missing_signature_or_timestamp"


def test_invalid_signature_writes_denial_record(_mock_write_denial):
    _post({"attacker_ip": "1.2.3.4"}, tamper=True)
    _mock_write_denial.assert_awaited_once()
    assert _mock_write_denial.await_args[0][0] == "invalid_signature"


def test_missing_timestamp_writes_denial_record(_mock_write_denial):
    body = json.dumps({"attacker_ip": "9.9.9.9", "tenant_id": TENANT}).encode("utf-8")
    _, sig = _sign(body)
    client.post("/webhook/dispatch", data=body, headers={"x-elastic-signature": sig})
    _mock_write_denial.assert_awaited_once()
    assert _mock_write_denial.await_args[0][0] == "missing_signature_or_timestamp"


def test_stale_timestamp_writes_denial_record(_no_real_ssh, _mock_write_denial):
    old = str(int(time.time()) - (broker_app.HMAC_REPLAY_WINDOW + 60))
    _post_dispatch({"attacker_ip": "9.9.9.9", "tenant_id": TENANT}, ts=old)
    _mock_write_denial.assert_awaited_once()
    assert _mock_write_denial.await_args[0][0] == "timestamp_outside_replay_window"


def test_replayed_signature_writes_denial_record(_no_real_ssh, _mock_write_denial):
    payload = {"attacker_ip": "9.9.9.9", "tenant_id": TENANT}
    ts = str(int(time.time()))
    first = _post_dispatch(payload, ts=ts)
    assert first.status_code == 200
    _mock_write_denial.assert_not_awaited()   # a valid, non-replayed request is not a denial

    replay = _post_dispatch(payload, ts=ts)
    assert replay.status_code == 401
    _mock_write_denial.assert_awaited_once()
    assert _mock_write_denial.await_args[0][0] == "replayed_signature"


def test_write_denial_posts_create_only_document():
    """Unit-test write_denial() itself: correct index, op_type=create (append-only,
    matching the soc_audit_appender role), and a doc shape mirroring agent_app.py's
    write_audit()."""
    captured = {}

    async def _fake_post(url, content=None, headers=None, auth=None, **kwargs):
        captured["url"] = url
        captured["content"] = content
        captured["headers"] = headers
        captured["auth"] = auth
        return mock.Mock(raise_for_status=mock.Mock())  # 2xx: raise_for_status is a no-op

    fake_request = mock.Mock()
    fake_request.client.host = "203.0.113.9"
    fake_request.url.path = "/webhook/dispatch"

    with mock.patch.object(broker_app.httpx, "AsyncClient") as mock_client_cls:
        mock_client = mock.AsyncMock()
        mock_client.post = _fake_post
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        asyncio.run(_real_write_denial("invalid_signature", fake_request, detail="extra"))

    assert captured["url"] == f"{broker_app.ES_HOST}/soc-audit-unassigned/_bulk"
    assert captured["auth"] == (broker_app.ES_USER, broker_app.ES_PASS)
    lines = captured["content"].splitlines()
    assert json.loads(lines[0]) == {"create": {}}
    doc = json.loads(lines[1])
    assert doc["event.action"] == "invalid_signature"
    assert doc["actor"] == "203.0.113.9"
    assert doc["tenant.id"] == "unassigned"
    assert doc["event.outcome"] == "denied"
    assert doc["target"] == "/webhook/dispatch"
    assert doc["detail"] == "extra"


def test_write_denial_failure_does_not_raise():
    """A downed/misconfigured ES must never turn a 401/503 into a 500 — write_denial()
    catches and logs, exactly like agent_app.py's write_audit()."""
    fake_request = mock.Mock()
    fake_request.client.host = "203.0.113.9"
    fake_request.url.path = "/webhook/dispatch"

    with mock.patch.object(broker_app.httpx, "AsyncClient", side_effect=RuntimeError("boom")):
        asyncio.run(_real_write_denial("invalid_signature", fake_request))  # must not raise


def test_write_denial_non_2xx_response_is_not_swallowed_as_success(caplog):
    """A wrong hive_mind_broker password or a missing role grant returns a non-2xx
    ES response, not a network exception. Before this fix, write_denial() never
    inspected the response, so this looked identical to a successful write —
    silently defeating the AU-2/3/12 guarantee this PR exists to provide."""
    import httpx as real_httpx

    async def _fake_post(url, content=None, headers=None, auth=None, **kwargs):
        request = real_httpx.Request("POST", url)
        return real_httpx.Response(403, request=request, text="unauthorized")

    fake_request = mock.Mock()
    fake_request.client.host = "203.0.113.9"
    fake_request.url.path = "/webhook/dispatch"

    with mock.patch.object(broker_app.httpx, "AsyncClient") as mock_client_cls:
        mock_client = mock.AsyncMock()
        mock_client.post = _fake_post
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        with caplog.at_level("ERROR"):
            asyncio.run(_real_write_denial("invalid_signature", fake_request))  # must not raise

    assert "Failed to write denial record" in caplog.text
