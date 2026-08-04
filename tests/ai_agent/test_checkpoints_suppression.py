"""
should_suppress_technique() — bounded sliding host+technique suppression
window (#220).

Deliberately parallel to, and independent of, generate_dedup_key's 5-min
tumbling window over tenant|ip|mac|severity (the agent's alert_id / checkpoint
/ approval-claim primary key, #214) - this suppresses a different class of
duplicate: the same technique repeatedly firing against the same host.

"Bounded" because the first version of this (before security-auditor review)
refreshed last_seen on every firing with no ceiling, which meant a sustained
attack suppressed itself permanently after the first alert. Two escape
hatches are tested here: max_duration_seconds (force a fresh alert once a
window has been open too long) and severity escalation (a "critical" firing
always breaks a window that hasn't seen "critical" yet).
"""
import unittest
from unittest import mock

import requests

import checkpoints


class SuppressTechniqueTests(unittest.TestCase):
    def _mock_get(self, status_code, last_seen=None, first_seen=None,
                  suppressed_count=0, max_severity=""):
        resp = mock.Mock()
        resp.status_code = status_code
        if status_code == 200:
            resp.json.return_value = {"_source": {
                "last_seen": last_seen,
                "first_seen": first_seen if first_seen is not None else last_seen,
                "suppressed_count": suppressed_count,
                "max_severity": max_severity,
            }}
        elif status_code >= 400:
            resp.raise_for_status.side_effect = requests.HTTPError(f"{status_code} error")
        return resp

    def _mock_put(self, status_code=200):
        resp = mock.Mock()
        resp.status_code = status_code
        if status_code >= 400:
            resp.raise_for_status.side_effect = requests.HTTPError(f"{status_code} error")
        else:
            resp.raise_for_status.return_value = None
        return resp

    @mock.patch("checkpoints.requests.put")
    @mock.patch("checkpoints.requests.get")
    def test_first_firing_is_never_suppressed(self, mock_get, mock_put):
        mock_get.return_value = self._mock_get(404)
        mock_put.return_value = self._mock_put()

        self.assertFalse(checkpoints.should_suppress_technique("tenant-a", "AABBCCDDEEFF", "T1046"))
        mock_put.assert_called_once()

    @mock.patch("checkpoints.requests.put")
    @mock.patch("checkpoints.requests.get")
    def test_repeat_within_window_is_suppressed(self, mock_get, mock_put):
        now = checkpoints.time.time()
        mock_get.return_value = self._mock_get(200, last_seen=now - 60, first_seen=now - 60)
        mock_put.return_value = self._mock_put()

        self.assertTrue(checkpoints.should_suppress_technique("tenant-a", "AABBCCDDEEFF", "T1046", window_seconds=900))
        # Sliding window: even a suppressed firing refreshes last_seen.
        mock_put.assert_called_once()
        put_doc = mock_put.call_args.kwargs["json"]
        self.assertEqual(put_doc["suppressed_count"], 1)

    @mock.patch("checkpoints.requests.put")
    @mock.patch("checkpoints.requests.get")
    def test_repeat_outside_window_is_not_suppressed(self, mock_get, mock_put):
        now = checkpoints.time.time()
        mock_get.return_value = self._mock_get(200, last_seen=now - 1000, first_seen=now - 1000)
        mock_put.return_value = self._mock_put()

        self.assertFalse(checkpoints.should_suppress_technique("tenant-a", "AABBCCDDEEFF", "T1046", window_seconds=900))
        # Breaking suppression resets suppressed_count/first_seen for the new burst.
        put_doc = mock_put.call_args.kwargs["json"]
        self.assertEqual(put_doc["suppressed_count"], 0)

    @mock.patch("checkpoints.requests.put")
    @mock.patch("checkpoints.requests.get")
    def test_sustained_burst_still_realerts_after_max_duration(self, mock_get, mock_put):
        """The keep-alive evasion the security-auditor caught: last_seen alone
        refreshing forever meant a technique firing every few seconds never
        re-alerted. max_duration_seconds forces a fresh alert even though
        last_seen is well within window_seconds."""
        now = checkpoints.time.time()
        mock_get.return_value = self._mock_get(200, last_seen=now - 5, first_seen=now - 3700)
        mock_put.return_value = self._mock_put()

        self.assertFalse(checkpoints.should_suppress_technique(
            "tenant-a", "AABBCCDDEEFF", "T1046", window_seconds=900, max_duration_seconds=3600))

    @mock.patch("checkpoints.requests.put")
    @mock.patch("checkpoints.requests.get")
    def test_critical_severity_breaks_a_non_critical_window(self, mock_get, mock_put):
        now = checkpoints.time.time()
        mock_get.return_value = self._mock_get(200, last_seen=now - 5, first_seen=now - 5, max_severity="medium")
        mock_put.return_value = self._mock_put()

        self.assertFalse(checkpoints.should_suppress_technique(
            "tenant-a", "AABBCCDDEEFF", "T1046", severity="critical", window_seconds=900))

    @mock.patch("checkpoints.requests.put")
    @mock.patch("checkpoints.requests.get")
    def test_non_critical_repeat_within_an_already_critical_window_still_suppressed(self, mock_get, mock_put):
        now = checkpoints.time.time()
        mock_get.return_value = self._mock_get(200, last_seen=now - 5, first_seen=now - 5, max_severity="critical")
        mock_put.return_value = self._mock_put()

        self.assertTrue(checkpoints.should_suppress_technique(
            "tenant-a", "AABBCCDDEEFF", "T1046", severity="medium", window_seconds=900))

    @mock.patch("checkpoints.requests.put")
    @mock.patch("checkpoints.requests.get")
    def test_different_technique_same_host_not_suppressed(self, mock_get, mock_put):
        # Different technique -> different doc id -> a fresh 404, independent
        # of whatever window T1046 is currently in for this same host.
        mock_get.return_value = self._mock_get(404)
        mock_put.return_value = self._mock_put()

        self.assertFalse(checkpoints.should_suppress_technique("tenant-a", "AABBCCDDEEFF", "T1110"))

    def test_missing_host_never_suppresses_without_any_es_call(self):
        with mock.patch("checkpoints.requests.get") as mock_get, \
             mock.patch("checkpoints.requests.put") as mock_put:
            self.assertFalse(checkpoints.should_suppress_technique("tenant-a", "", "T1046"))
            mock_get.assert_not_called()
            mock_put.assert_not_called()

    def test_missing_technique_never_suppresses_without_any_es_call(self):
        with mock.patch("checkpoints.requests.get") as mock_get, \
             mock.patch("checkpoints.requests.put") as mock_put:
            self.assertFalse(checkpoints.should_suppress_technique("tenant-a", "AABBCCDDEEFF", ""))
            mock_get.assert_not_called()
            mock_put.assert_not_called()

    @mock.patch("checkpoints.requests.get")
    def test_es_error_on_read_propagates_for_caller_to_fail_open(self, mock_get):
        mock_get.side_effect = requests.ConnectionError("ES unreachable")
        with self.assertRaises(requests.ConnectionError):
            checkpoints.should_suppress_technique("tenant-a", "AABBCCDDEEFF", "T1046")

    @mock.patch("checkpoints.requests.get")
    def test_es_error_on_write_propagates_for_caller_to_fail_open(self, mock_get):
        mock_get.return_value = self._mock_get(404)
        with mock.patch("checkpoints.requests.put") as mock_put:
            mock_put.side_effect = requests.ConnectionError("ES unreachable")
            with self.assertRaises(requests.ConnectionError):
                checkpoints.should_suppress_technique("tenant-a", "AABBCCDDEEFF", "T1046")

    @mock.patch("checkpoints.requests.put")
    @mock.patch("checkpoints.requests.get")
    def test_doc_id_is_stable_for_same_host_and_technique(self, mock_get, mock_put):
        mock_get.return_value = self._mock_get(404)
        mock_put.return_value = self._mock_put()

        checkpoints.should_suppress_technique("tenant-a", "AABBCCDDEEFF", "T1046")
        url_1 = mock_get.call_args[0][0]
        mock_get.reset_mock()
        checkpoints.should_suppress_technique("tenant-a", "AABBCCDDEEFF", "T1046")
        url_2 = mock_get.call_args[0][0]

        self.assertEqual(url_1, url_2)
        self.assertIn("suppress:", url_1)


if __name__ == "__main__":
    unittest.main()
