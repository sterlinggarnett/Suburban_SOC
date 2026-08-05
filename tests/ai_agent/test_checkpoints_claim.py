"""
claim_approval() — the atomic at-most-once gate for /approve execution (#214).

Uses Elasticsearch op_type=create as the atomicity primitive: the first writer
to PUT .../{alert_id}.claim gets 201 and wins; every other writer gets 409 and
loses, regardless of process/thread — unlike a threading.Lock, this holds even
if the agent is ever scaled beyond gunicorn's pinned --workers 1.

#247: a claim doc is never deleted (agent_checkpoints's ES role deliberately
has no delete privilege — #245 — a compromised agent credential must not be
able to erase a claim and reopen the at-most-once gate). Instead it
transitions via partial update: RELEASED (confirmed non-dispatch, safe to
retry) or RESOLVED (confirmed success, never retryable). A 409 on
claim_approval() now re-reads the existing doc: only a RELEASED one can be
re-won, via optimistic concurrency (if_seq_no/if_primary_term) so exactly one
concurrent retrier still wins.
"""
import unittest
from unittest import mock

import requests

import checkpoints


def _mock_response(status_code, json_body=None, seq_no=None, primary_term=None):
    resp = mock.Mock()
    resp.status_code = status_code
    if status_code >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(f"{status_code} error")
    else:
        resp.raise_for_status.return_value = None
    body = dict(json_body or {})
    if seq_no is not None:
        body["_seq_no"] = seq_no
    if primary_term is not None:
        body["_primary_term"] = primary_term
    resp.json.return_value = body
    return resp


class ClaimApprovalTests(unittest.TestCase):
    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_wins_on_201_created(self, mock_put):
        mock_put.return_value = _mock_response(201)
        self.assertTrue(checkpoints.claim_approval("tenant-a", "alert-1", "human"))

    @mock.patch("checkpoints.requests.get")
    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_loses_on_409_when_still_claimed(self, mock_put, mock_get):
        # The existing doc is still CLAIMED (execution in flight, or an
        # UNKNOWN-outcome one #247 deliberately never releases) — must lose.
        mock_put.return_value = _mock_response(409)
        mock_get.return_value = _mock_response(200, {"_source": {"phase": "CLAIMED"}})
        self.assertFalse(checkpoints.claim_approval("tenant-a", "alert-1", "human"))

    @mock.patch("checkpoints.requests.get")
    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_loses_on_409_when_already_resolved(self, mock_put, mock_get):
        # A RESOLVED claim (already succeeded) must never be re-winnable.
        mock_put.return_value = _mock_response(409)
        mock_get.return_value = _mock_response(200, {"_source": {"phase": "RESOLVED"}})
        self.assertFalse(checkpoints.claim_approval("tenant-a", "alert-1", "human"))

    @mock.patch("checkpoints.requests.get")
    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_rewins_a_released_claim(self, mock_put, mock_get):
        # #247: a RELEASED claim (confirmed-failed, freed for retry) CAN be
        # re-won — via a conditional PUT keyed on the seq_no/primary_term this
        # GET observed, not a second op_type=create (the doc already exists).
        mock_get.return_value = _mock_response(
            200, {"_source": {"phase": "RELEASED"}}, seq_no=5, primary_term=1)
        mock_put.side_effect = [_mock_response(409), _mock_response(200)]
        self.assertTrue(checkpoints.claim_approval("tenant-a", "alert-1", "human"))
        reclaim_url = mock_put.call_args_list[1][0][0]
        self.assertIn("if_seq_no=5", reclaim_url)
        self.assertIn("if_primary_term=1", reclaim_url)

    @mock.patch("checkpoints.requests.get")
    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_loses_reclaim_race_to_a_concurrent_retrier(self, mock_put, mock_get):
        # Two retriers both see RELEASED and both attempt the conditional PUT;
        # only the first to land wins — the second's seq_no is now stale and
        # ES itself rejects it with 409, same "exactly one winner" guarantee
        # op_type=create gave the very first claim.
        mock_get.return_value = _mock_response(
            200, {"_source": {"phase": "RELEASED"}}, seq_no=5, primary_term=1)
        mock_put.side_effect = [_mock_response(409), _mock_response(409)]
        self.assertFalse(checkpoints.claim_approval("tenant-a", "alert-1", "human"))

    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_raises_on_es_connection_error(self, mock_put):
        mock_put.side_effect = requests.ConnectionError("ES unreachable")
        with self.assertRaises(requests.ConnectionError):
            checkpoints.claim_approval("tenant-a", "alert-1", "human")

    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_raises_on_es_server_error(self, mock_put):
        mock_put.return_value = _mock_response(500)
        with self.assertRaises(requests.HTTPError):
            checkpoints.claim_approval("tenant-a", "alert-1", "human")

    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_uses_create_op_type_url(self, mock_put):
        mock_put.return_value = _mock_response(201)
        checkpoints.claim_approval("tenant-a", "alert-1", "human")
        url = mock_put.call_args[0][0]
        self.assertIn("/_create/", url)
        self.assertIn("alert-1", url)


class ReleaseClaimTests(unittest.TestCase):
    """release_claim() — marks a claim RELEASED after a CONFIRMED execution
    failure so a retried /approve can win it again (#247), without ever
    risking the at-most-once guarantee claim_approval() provides (callers
    only release after confirming nothing was actually dispatched — never on
    an ambiguous/unknown outcome)."""

    @mock.patch("checkpoints.requests.post")
    def test_release_claim_succeeds_on_200(self, mock_post):
        mock_post.return_value = _mock_response(200)
        self.assertTrue(checkpoints.release_claim("tenant-a", "alert-1"))

    @mock.patch("checkpoints.requests.post")
    def test_release_claim_treats_already_gone_as_success(self, mock_post):
        mock_post.return_value = _mock_response(404)
        self.assertTrue(checkpoints.release_claim("tenant-a", "alert-1"))

    @mock.patch("checkpoints.requests.post")
    def test_release_claim_raises_on_es_server_error(self, mock_post):
        mock_post.return_value = _mock_response(500)
        with self.assertRaises(requests.HTTPError):
            checkpoints.release_claim("tenant-a", "alert-1")

    @mock.patch("checkpoints.requests.post")
    def test_release_claim_raises_on_es_connection_error(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("ES unreachable")
        with self.assertRaises(requests.ConnectionError):
            checkpoints.release_claim("tenant-a", "alert-1")

    @mock.patch("checkpoints.requests.post")
    def test_release_claim_targets_the_claim_document_with_released_phase(self, mock_post):
        mock_post.return_value = _mock_response(200)
        checkpoints.release_claim("tenant-a", "alert-1")
        url, kwargs = mock_post.call_args[0][0], mock_post.call_args[1]
        self.assertIn("/_update/alert-1.claim", url)
        self.assertEqual(kwargs["json"], {"doc": {"phase": "RELEASED"}})

    @mock.patch("checkpoints.requests.post")
    @mock.patch("checkpoints.requests.put")
    @mock.patch("checkpoints.requests.delete")
    def test_a_released_claim_is_never_deleted(self, mock_delete, mock_put, mock_post):
        # #247 security-auditor review: agent_checkpoints's ES role has no
        # delete privilege by design — release_claim() must never attempt one.
        mock_post.return_value = _mock_response(200)
        checkpoints.release_claim("tenant-a", "alert-1")
        mock_delete.assert_not_called()
        mock_put.assert_not_called()


class ResolveClaimTests(unittest.TestCase):
    """resolve_claim() — marks a claim RESOLVED after a CONFIRMED successful
    execution (#247), so it's never re-winnable and never mistaken for stuck."""

    @mock.patch("checkpoints.requests.post")
    def test_resolve_claim_succeeds_on_200(self, mock_post):
        mock_post.return_value = _mock_response(200)
        self.assertTrue(checkpoints.resolve_claim("tenant-a", "alert-1"))

    @mock.patch("checkpoints.requests.post")
    def test_resolve_claim_treats_already_gone_as_success(self, mock_post):
        mock_post.return_value = _mock_response(404)
        self.assertTrue(checkpoints.resolve_claim("tenant-a", "alert-1"))

    @mock.patch("checkpoints.requests.post")
    def test_resolve_claim_raises_on_es_server_error(self, mock_post):
        mock_post.return_value = _mock_response(500)
        with self.assertRaises(requests.HTTPError):
            checkpoints.resolve_claim("tenant-a", "alert-1")

    @mock.patch("checkpoints.requests.post")
    def test_resolve_claim_targets_the_claim_document_with_resolved_phase(self, mock_post):
        mock_post.return_value = _mock_response(200)
        checkpoints.resolve_claim("tenant-a", "alert-1")
        url, kwargs = mock_post.call_args[0][0], mock_post.call_args[1]
        self.assertIn("/_update/alert-1.claim", url)
        self.assertEqual(kwargs["json"], {"doc": {"phase": "RESOLVED"}})


if __name__ == "__main__":
    unittest.main()
