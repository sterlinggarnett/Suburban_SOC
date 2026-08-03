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


if __name__ == "__main__":
    unittest.main()
