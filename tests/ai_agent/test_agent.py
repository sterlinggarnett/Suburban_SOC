import os

# agent.py reads this at import time (module-level constant); other test
# files in this dir set it too, but Python only evaluates a module's top
# level on its FIRST import — whichever test file collects first "wins" for
# the whole process. Set it here too so collection order can't matter (#214).
os.environ.setdefault("SOC_AGENT_HMAC_SECRET", "unit_test_secret")
# #246: separate /approve + /pending credential — same collection-order
# reasoning. Deliberately a DIFFERENT literal than SOC_AGENT_HMAC_SECRET above
# (test_alert_auth.py proves the two secrets can't sign for each other).
os.environ.setdefault("SOC_APPROVER_HMAC_SECRET", "unit_test_approver_secret")

import pytest
from unittest.mock import patch
from agent import Agent

@pytest.fixture
def agent():
    return Agent()

@pytest.fixture
def payload():
    return {
        "tenant_id": "test-tenant",
        "source_ip": "192.168.1.10",
        "source_mac": "00:11:22:33:44:55",
        "severity": "critical",
        "raw_log": "Brute force attack detected"
    }

@patch('agent.is_duplicate')
@patch('agent.write_checkpoint')
@patch('agent.is_excluded')
@patch('agent._append_pending_action')
@patch('agent.analyze_alert_with_ai')
@patch('agent.create_case')
def test_phase_1_draft_human_gate(mock_case, mock_ai, mock_append, mock_excluded, mock_write, mock_dup, agent, payload):
    # Setup mocks
    mock_dup.return_value = False
    mock_excluded.return_value = False
    mock_ai.return_value = "AI summary"
    mock_case.return_value = "case-123"
    
    # Run Phase 1
    result = agent.run(payload)
    
    # Verify Human Gate: must park at PENDING_APPROVAL and draft action.
    # "drafted" is the external status word for the internal PENDING_APPROVAL
    # checkpoint phase (evidence-verified: evidence/README.md, section_a_evidence.sh).
    assert result.status_code == 200
    assert result.response['status'] == 'drafted'
    mock_append.assert_called_once()
    assert mock_append.call_args[0][0]['target_ip'] == "192.168.1.10"
    
    # Verify Checkpoints
    assert mock_write.call_count == 2
    # First checkpoint: PERCEIVING
    assert mock_write.call_args_list[0][0][2] == "PERCEIVING"
    # Second checkpoint: PENDING_APPROVAL
    assert mock_write.call_args_list[1][0][2] == "PENDING_APPROVAL"

@patch('agent.is_duplicate')
def test_idempotency_duplicate_rejected(mock_dup, agent, payload):
    mock_dup.return_value = True
    result = agent.run(payload)

    assert result.status_code == 200
    assert result.response['status'] == 'ignored'

@patch('agent.write_audit')
@patch('agent.should_suppress_technique')
@patch('agent.is_duplicate')
def test_repeated_technique_within_window_suppressed(mock_dup, mock_suppress, mock_audit, agent, payload):
    """#220: a host+technique repeat within the sliding window is suppressed
    before any checkpoint/case is created — independent of the 5-min
    tenant/IP/MAC/severity dedup above, which this test proves isn't what's
    gating here (mock_dup is False)."""
    mock_dup.return_value = False
    mock_suppress.return_value = True
    payload = {**payload, "technique": "T1046"}

    result = agent.run(payload)

    assert result.status_code == 200
    assert result.response['status'] == 'ignored'
    # target_mac is present, normalized (matches the exclusion-list's own
    # host-identity convention), and preferred as the suppression "host" key
    # (persists across IP/DHCP changes). severity is passed through too, so
    # a later escalation can break a window opened at a lower severity.
    mock_suppress.assert_called_once_with("test-tenant", "001122334455", "T1046", "critical")
    mock_audit.assert_called_once()
    assert mock_audit.call_args[0][0] == "alert_suppressed"

@patch('agent.write_audit')
@patch('agent.should_suppress_technique')
@patch('agent.is_duplicate')
def test_malformed_technique_treated_as_absent(mock_dup, mock_suppress, mock_audit, agent, payload):
    """#220: technique is validated at the perceive() boundary the same way
    MAC/IP already are — free text that doesn't look like a MITRE technique
    ID (e.g. attacker-controlled log-injection payload, or just a typo) is
    dropped rather than trusted, which also means it can never trigger
    suppression on an unintended shared bucket. mock_suppress=True here just
    to short-circuit before the unmocked think/act pipeline — the thing
    under test is the sanitized argument it's called with, not the result."""
    mock_dup.return_value = False
    mock_suppress.return_value = True
    payload = {**payload, "technique": "not-a-technique\nfake log line"}

    agent.run(payload)

    mock_suppress.assert_called_once_with("test-tenant", "001122334455", "", "critical")

@patch('agent.write_checkpoint')
@patch('agent.is_excluded')
@patch('agent._append_pending_action')
@patch('agent.analyze_alert_with_ai')
@patch('agent.create_case')
@patch('agent.should_suppress_technique')
@patch('agent.is_duplicate')
def test_technique_suppression_check_failure_fails_open(mock_dup, mock_suppress, mock_case, mock_ai,
                                                          mock_append, mock_excluded, mock_write, agent, payload):
    """An ES error on the suppression check must not drop a real alert —
    same intake leniency as the duplicate check's own failure handling."""
    mock_dup.return_value = False
    mock_suppress.side_effect = ConnectionError("ES unreachable")
    mock_excluded.return_value = False
    mock_ai.return_value = "AI summary"
    mock_case.return_value = "case-123"

    result = agent.run(payload)

    assert result.status_code == 200
    assert result.response['status'] == 'drafted'

@patch('agent._append_pending_action')
@patch('agent.is_awaiting_approval')
@patch('agent.read_checkpoint')
@patch('agent._execute_isolation')
@patch('agent.write_checkpoint')
@patch('agent.claim_approval')
def test_phase_2_execution(mock_claim, mock_write, mock_exec, mock_read, mock_awaiting, mock_append, agent, payload):
    # Setup mocks
    mock_awaiting.return_value = True
    mock_claim.return_value = True
    mock_read.return_value = {"context": payload}
    mock_exec.return_value = (True, "Blocked on router")

    # Run Phase 2
    result = agent.execute_approved("test-tenant", "fake-alert-id", "human")
    
    # Verify execution and final checkpoint
    assert result.status_code == 200
    assert result.response['status'] == 'executed'
    mock_exec.assert_called_once_with("00:11:22:33:44:55", "192.168.1.10", "test-tenant")
    mock_write.assert_called_once_with("test-tenant", "fake-alert-id", "EXECUTED", context=payload)

@patch('agent.is_awaiting_approval')
def test_phase_2_state_rejection(mock_awaiting, agent):
    mock_awaiting.return_value = False

    result = agent.execute_approved("test-tenant", "fake-alert-id", "human")

    assert result.status_code == 409
    assert result.response['status'] == 'error'


@patch('agent._append_pending_action')
@patch('agent.is_awaiting_approval')
@patch('agent.read_checkpoint')
@patch('agent._execute_isolation')
@patch('agent.claim_approval')
def test_phase_2_corrupt_checkpoint_context_fails_after_claim_without_executing(mock_claim, mock_exec, mock_read, mock_awaiting, mock_append, agent):
    """A claimed checkpoint whose stored context can't be re-perceived (e.g.
    corrupted/malformed) must still never reach isolation — claim_approval()
    already won by this point, so the failure has to surface as a clean
    error, not a crash, and isolation must not be attempted on garbage data."""
    mock_awaiting.return_value = True
    mock_claim.return_value = True
    mock_read.return_value = {"context": "not-a-dict"}  # perceive() raises -> None

    result = agent.execute_approved("test-tenant", "fake-alert-id", "human")

    assert result.status_code == 500
    assert result.response['status'] == 'error'
    mock_exec.assert_not_called()


@patch('agent._append_pending_action')
@patch('agent.is_awaiting_approval')
@patch('agent.read_checkpoint')
@patch('agent._execute_isolation')
@patch('agent.write_checkpoint')
@patch('agent.claim_approval')
def test_phase_2_claim_lost_blocks_replay(mock_claim, mock_write, mock_exec, mock_read, mock_awaiting, mock_append, agent, payload):
    """A second /approve for an id already claimed (e.g. a replayed request,
    or a genuine race) must be rejected with 409 and must never dispatch
    isolation a second time — this is the core #214 regression fix."""
    mock_awaiting.return_value = True
    mock_claim.return_value = False  # lost the ES create-if-absent race
    mock_read.return_value = {"context": payload}

    result = agent.execute_approved("test-tenant", "fake-alert-id", "human")

    assert result.status_code == 409
    assert result.response['status'] == 'error'
    mock_exec.assert_not_called()


@patch('agent._append_pending_action')
@patch('agent.is_awaiting_approval')
@patch('agent.claim_approval')
def test_phase_2_claim_store_unavailable_fails_closed(mock_claim, mock_awaiting, mock_append, agent):
    """ES unreachable during the claim attempt must fail closed (503), not
    silently allow execution — duplicate isolation is worse than a delayed
    approval."""
    mock_awaiting.return_value = True
    mock_claim.side_effect = ConnectionError("ES unreachable")

    result = agent.execute_approved("test-tenant", "fake-alert-id", "human")

    assert result.status_code == 503
    assert result.response['status'] == 'error'


@patch('agent._append_pending_action')
@patch('agent.is_awaiting_approval')
def test_phase_2_awaiting_check_store_unavailable_fails_closed(mock_awaiting, mock_append, agent):
    mock_awaiting.side_effect = ConnectionError("ES unreachable")

    result = agent.execute_approved("test-tenant", "fake-alert-id", "human")

    assert result.status_code == 503
    assert result.response['status'] == 'error'


@patch('agent._append_pending_action')
@patch('agent.is_awaiting_approval')
@patch('agent.read_checkpoint')
@patch('agent._execute_isolation')
@patch('agent.write_checkpoint')
@patch('agent.claim_approval')
def test_phase_2_writes_claimed_then_approved_queue_rows(mock_claim, mock_write, mock_exec, mock_read, mock_awaiting, mock_append, agent, payload):
    mock_awaiting.return_value = True
    mock_claim.return_value = True
    mock_read.return_value = {"context": payload}
    mock_exec.return_value = (True, "Blocked on router")

    agent.execute_approved("test-tenant", "fake-alert-id", "human")

    statuses = [call.args[0]['status'] for call in mock_append.call_args_list]
    assert statuses == ["claimed", "approved"]


@patch('agent._append_pending_action')
@patch('agent.is_awaiting_approval')
@patch('agent.read_checkpoint')
@patch('agent._execute_isolation')
@patch('agent.write_checkpoint')
@patch('agent.claim_approval')
@patch('agent.release_claim')
def test_phase_2_failed_execution_releases_claim_for_retry(
        mock_release, mock_claim, mock_write, mock_exec, mock_read, mock_awaiting, mock_append, agent, payload):
    """#247: a failed execution (broker down, no routers, etc.) must not
    permanently strand the alert — the claim is released and the checkpoint
    returns to PENDING_APPROVAL so a retried /approve can win the claim race
    again, and the failure is recorded distinctly from a real success."""
    mock_awaiting.return_value = True
    mock_claim.return_value = True
    mock_read.return_value = {"context": payload}
    mock_exec.return_value = (False, "no routers for tenant 'test-tenant'")

    result = agent.execute_approved("test-tenant", "fake-alert-id", "human")

    mock_release.assert_called_once_with("test-tenant", "fake-alert-id")
    mock_write.assert_called_once_with("test-tenant", "fake-alert-id", "PENDING_APPROVAL", context=payload)
    statuses = [call.args[0]['status'] for call in mock_append.call_args_list]
    assert statuses == ["claimed", "isolation_failed"]
    assert statuses[-1] != "approved"
    assert result.response["status"] == "isolation_failed"


@patch('agent._append_pending_action')
@patch('agent.is_awaiting_approval')
@patch('agent.read_checkpoint')
@patch('agent._execute_isolation')
@patch('agent.write_checkpoint')
@patch('agent.claim_approval')
def test_phase_2_release_claim_failure_does_not_crash_the_response(
        mock_claim, mock_write, mock_exec, mock_read, mock_awaiting, mock_append, agent, payload):
    """A release_claim() failure (ES unreachable) must not turn an already-
    truthfully-recorded failed execution into a 500 — it's logged as a stuck
    claim (see metric_stuck_approval_claims()), not silently swallowed, but
    the response to the caller still reflects what actually happened."""
    mock_awaiting.return_value = True
    mock_claim.return_value = True
    mock_read.return_value = {"context": payload}
    mock_exec.return_value = (False, "broker unreachable")

    with patch('agent.release_claim', side_effect=RuntimeError("ES down")):
        result = agent.execute_approved("test-tenant", "fake-alert-id", "human")

    assert result.status_code == 200
    assert result.response["status"] == "isolation_failed"


@patch('agent._append_pending_action')
@patch('agent.is_awaiting_approval')
@patch('agent.read_checkpoint')
@patch('agent._execute_isolation')
@patch('agent.write_checkpoint')
@patch('agent.claim_approval')
def test_phase_2_uses_the_claimed_alert_id_not_a_recomputed_one(mock_claim, mock_write, mock_exec, mock_read, mock_awaiting, mock_append, agent, payload):
    """perceive() recomputes alert_id from the payload's dedup key, which can
    drift from the id this call was actually claimed under (e.g. a new
    5-minute bucket). The checkpoint written for THIS execution must key on
    the original, claimed alert_id — not perceive()'s recomputed one."""
    mock_awaiting.return_value = True
    mock_claim.return_value = True
    mock_read.return_value = {"context": payload}
    mock_exec.return_value = (True, "Blocked on router")

    agent.execute_approved("test-tenant", "fake-alert-id", "human")

    mock_write.assert_called_once_with("test-tenant", "fake-alert-id", "EXECUTED", context=payload)
