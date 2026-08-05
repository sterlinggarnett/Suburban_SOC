"""
claim_approval() — the atomic at-most-once gate for /approve execution (#214).

Uses Elasticsearch op_type=create as the atomicity primitive: the first writer
to PUT .../{alert_id}.claim gets 201 and wins; every other writer gets 409 and
loses, regardless of process/thread — unlike a threading.Lock, this holds even
if the agent is ever scaled beyond gunicorn's pinned --workers 1.
"""
import unittest
from unittest import mock

import requests

import checkpoints


class ClaimApprovalTests(unittest.TestCase):
    def _mock_response(self, status_code):
        resp = mock.Mock()
        resp.status_code = status_code
        if status_code >= 400:
            resp.raise_for_status.side_effect = requests.HTTPError(f"{status_code} error")
        else:
            resp.raise_for_status.return_value = None
        return resp

    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_wins_on_201_created(self, mock_put):
        mock_put.return_value = self._mock_response(201)
        self.assertTrue(checkpoints.claim_approval("tenant-a", "alert-1", "human"))

    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_loses_on_409_conflict(self, mock_put):
        mock_put.return_value = self._mock_response(409)
        self.assertFalse(checkpoints.claim_approval("tenant-a", "alert-1", "human"))

    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_raises_on_es_connection_error(self, mock_put):
        mock_put.side_effect = requests.ConnectionError("ES unreachable")
        with self.assertRaises(requests.ConnectionError):
            checkpoints.claim_approval("tenant-a", "alert-1", "human")

    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_raises_on_es_server_error(self, mock_put):
        mock_put.return_value = self._mock_response(500)
        with self.assertRaises(requests.HTTPError):
            checkpoints.claim_approval("tenant-a", "alert-1", "human")

    @mock.patch("checkpoints.requests.put")
    def test_claim_approval_uses_create_op_type_url(self, mock_put):
        mock_put.return_value = self._mock_response(201)
        checkpoints.claim_approval("tenant-a", "alert-1", "human")
        url = mock_put.call_args[0][0]
        self.assertIn("/_create/", url)
        self.assertIn("alert-1", url)


class ReleaseClaimTests(unittest.TestCase):
    """release_claim() — frees a claim after a confirmed execution failure so a
    retried /approve can win it again (#247), without ever risking the
    at-most-once guarantee claim_approval() provides (callers only release
    after confirming nothing was actually dispatched)."""

    def _mock_response(self, status_code):
        resp = mock.Mock()
        resp.status_code = status_code
        if status_code >= 400:
            resp.raise_for_status.side_effect = requests.HTTPError(f"{status_code} error")
        else:
            resp.raise_for_status.return_value = None
        return resp

    @mock.patch("checkpoints.requests.delete")
    def test_release_claim_succeeds_on_200(self, mock_delete):
        mock_delete.return_value = self._mock_response(200)
        self.assertTrue(checkpoints.release_claim("tenant-a", "alert-1"))

    @mock.patch("checkpoints.requests.delete")
    def test_release_claim_treats_already_gone_as_success(self, mock_delete):
        # A concurrent release, or a claim that was never created — the goal
        # state ("no claim exists") already holds either way.
        mock_delete.return_value = self._mock_response(404)
        self.assertTrue(checkpoints.release_claim("tenant-a", "alert-1"))

    @mock.patch("checkpoints.requests.delete")
    def test_release_claim_raises_on_es_server_error(self, mock_delete):
        # A real failure must propagate — callers need to know the claim may
        # still be stuck, not be told it was freed when it wasn't.
        mock_delete.return_value = self._mock_response(500)
        with self.assertRaises(requests.HTTPError):
            checkpoints.release_claim("tenant-a", "alert-1")

    @mock.patch("checkpoints.requests.delete")
    def test_release_claim_raises_on_es_connection_error(self, mock_delete):
        mock_delete.side_effect = requests.ConnectionError("ES unreachable")
        with self.assertRaises(requests.ConnectionError):
            checkpoints.release_claim("tenant-a", "alert-1")

    @mock.patch("checkpoints.requests.delete")
    def test_release_claim_targets_the_claim_document(self, mock_delete):
        mock_delete.return_value = self._mock_response(200)
        checkpoints.release_claim("tenant-a", "alert-1")
        url = mock_delete.call_args[0][0]
        self.assertIn("alert-1.claim", url)


if __name__ == "__main__":
    unittest.main()
