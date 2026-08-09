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

    @mock.patch("checkpoints.requests.post")
    def test_release_claim_with_actor_and_reason_records_attribution(self, mock_post):
        # #276 security-auditor HIGH (unattributed operator writes): the
        # manual recovery path must record who and why, directly on the
        # claim doc — the agent's own calls (no actor kwarg) don't.
        mock_post.return_value = _mock_response(200)
        checkpoints.release_claim("tenant-a", "alert-1", actor="jdoe", reason="confirmed via SSH")
        doc = mock_post.call_args[1]["json"]["doc"]
        # security-auditor round-2 MEDIUM: --actor is operator-typed free
        # text — resolved_by must bind to what actually authenticated the
        # write (the ES credential + OS user/host), not the unverifiable
        # claimed name, same split as app.py's upstream_approver_claimed.
        self.assertEqual(doc["resolution_actor_claimed"], "jdoe")
        self.assertIn(checkpoints.ES_USER, doc["resolved_by"])
        self.assertEqual(doc["resolution_reason"], "confirmed via SSH")
        self.assertEqual(doc["resolution_source"], "manual")
        self.assertIn("resolved_at", doc)

    @mock.patch("checkpoints.requests.post")
    def test_release_claim_without_actor_omits_attribution_fields(self, mock_post):
        # agent.py's execute_approved() call site passes neither — must not
        # write resolved_by/resolution_reason/resolution_source as None
        # (dynamic:strict rejects unmapped fields, but None values for
        # mapped-but-irrelevant fields would still be noise on every
        # agent-driven transition).
        mock_post.return_value = _mock_response(200)
        checkpoints.release_claim("tenant-a", "alert-1")
        doc = mock_post.call_args[1]["json"]["doc"]
        self.assertEqual(doc, {"phase": "RELEASED"})

    @mock.patch("checkpoints.requests.post")
    def test_release_claim_with_seq_no_sends_conditional_update_params(self, mock_post):
        # #276 security-auditor MEDIUM (read-then-write race): cmd_resolve
        # passes get_claim()'s seq_no/primary_term through so a concurrent
        # modification is detected instead of silently overwritten.
        mock_post.return_value = _mock_response(200)
        checkpoints.release_claim("tenant-a", "alert-1", if_seq_no=7, if_primary_term=2)
        params = mock_post.call_args[1]["params"]
        self.assertEqual(params["if_seq_no"], 7)
        self.assertEqual(params["if_primary_term"], 2)

    def test_release_claim_rejects_a_half_set_seq_no_pair(self):
        # security-auditor LOW: if_seq_no/if_primary_term must be given
        # together or not at all — a half-set pair must not silently
        # degrade to an unconditional write, nor reach ES to fail there
        # with a generic 400 instead of a clear local error.
        with self.assertRaises(ValueError):
            checkpoints.release_claim("tenant-a", "alert-1", if_seq_no=7, if_primary_term=None)
        with self.assertRaises(ValueError):
            checkpoints.release_claim("tenant-a", "alert-1", if_seq_no=None, if_primary_term=1)

    @mock.patch("checkpoints.requests.post")
    def test_release_claim_conditional_conflict_returns_false_not_an_exception(self, mock_post):
        mock_post.return_value = _mock_response(409)
        self.assertFalse(checkpoints.release_claim(
            "tenant-a", "alert-1", if_seq_no=7, if_primary_term=2))

    def test_release_claim_rejects_invalid_tenant_id(self):
        with self.assertRaises(ValueError):
            checkpoints.release_claim("../etc", "alert-1")

    @mock.patch("checkpoints.requests.post")
    def test_release_claim_quotes_a_path_breaking_alert_id(self, mock_post):
        # #276 security-auditor MEDIUM (URL injection defense-in-depth):
        # alert_id becomes a URL path segment — a literal "/" must not add
        # an extra path segment.
        mock_post.return_value = _mock_response(200)
        checkpoints.release_claim("tenant-a", "weird/id")
        url = mock_post.call_args[0][0]
        self.assertNotIn("weird/id.claim", url)
        self.assertIn("weird%2Fid.claim", url)


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


class GetClaimTests(unittest.TestCase):
    """get_claim() — read-only lookup of a claim doc for the #276 stuck-claim
    recovery tool, distinct from read_checkpoint()'s paired phase doc."""

    @mock.patch("checkpoints.requests.get")
    def test_get_claim_returns_source_on_200(self, mock_get):
        mock_get.return_value = _mock_response(200, {"_source": {"phase": "CLAIMED", "alert_id": "alert-1"}})
        result = checkpoints.get_claim("tenant-a", "alert-1")
        self.assertEqual(result["phase"], "CLAIMED")
        self.assertEqual(result["alert_id"], "alert-1")

    @mock.patch("checkpoints.requests.get")
    def test_get_claim_carries_seq_no_and_primary_term_for_optimistic_concurrency(self, mock_get):
        # #276 security-auditor MEDIUM (read-then-write race): cmd_resolve
        # needs these to make its transition conditional.
        mock_get.return_value = _mock_response(
            200, {"_source": {"phase": "CLAIMED"}}, seq_no=7, primary_term=2)
        result = checkpoints.get_claim("tenant-a", "alert-1")
        self.assertEqual(result["_seq_no"], 7)
        self.assertEqual(result["_primary_term"], 2)

    def test_get_claim_rejects_invalid_tenant_id(self):
        with self.assertRaises(ValueError):
            checkpoints.get_claim("Not Valid!", "alert-1")

    @mock.patch("checkpoints.requests.get")
    def test_get_claim_returns_none_on_404(self, mock_get):
        mock_get.return_value = _mock_response(404)
        self.assertIsNone(checkpoints.get_claim("tenant-a", "alert-1"))

    @mock.patch("checkpoints.requests.get")
    def test_get_claim_raises_on_es_server_error(self, mock_get):
        mock_get.return_value = _mock_response(500)
        with self.assertRaises(requests.HTTPError):
            checkpoints.get_claim("tenant-a", "alert-1")

    @mock.patch("checkpoints.requests.get")
    def test_get_claim_targets_the_claim_document_not_the_checkpoint(self, mock_get):
        mock_get.return_value = _mock_response(200, {"_source": {}})
        checkpoints.get_claim("tenant-a", "alert-1")
        url = mock_get.call_args[0][0]
        self.assertTrue(url.endswith("/alert-1.claim"))


class SearchStuckClaimsTests(unittest.TestCase):
    """search_stuck_claims() — the #276 tool's list view, same population
    slo_metrics.metric_stuck_approval_claims() counts, surfaced with detail."""

    @mock.patch("checkpoints.requests.post")
    def test_search_stuck_claims_returns_sources_from_hits(self, mock_post):
        mock_post.return_value = _mock_response(200, {"hits": {
            "total": {"value": 2},
            "hits": [
                {"_source": {"alert_id": "a1", "phase": "CLAIMED"}},
                {"_source": {"alert_id": "a2", "phase": "CLAIMED"}},
            ]}})
        claims, total = checkpoints.search_stuck_claims()
        self.assertEqual([r["alert_id"] for r in claims], ["a1", "a2"])
        self.assertEqual(total, 2)

    @mock.patch("checkpoints.requests.post")
    def test_search_stuck_claims_surfaces_a_total_larger_than_the_page(self, mock_post):
        # #276 code-reviewer review: results are capped at size=200 — an
        # operator must be able to tell a partial list from a complete one.
        mock_post.return_value = _mock_response(200, {"hits": {
            "total": {"value": 250},
            "hits": [{"_source": {"alert_id": f"a{i}"}} for i in range(200)]}})
        claims, total = checkpoints.search_stuck_claims()
        self.assertEqual(len(claims), 200)
        self.assertEqual(total, 250)

    @mock.patch("checkpoints.requests.post")
    def test_search_stuck_claims_requests_accurate_total_hits_tracking(self, mock_post):
        mock_post.return_value = _mock_response(200, {"hits": {"hits": []}})
        checkpoints.search_stuck_claims()
        self.assertTrue(mock_post.call_args[1]["json"]["track_total_hits"])

    @mock.patch("checkpoints.requests.post")
    def test_search_stuck_claims_filters_on_claimed_phase_and_age(self, mock_post):
        mock_post.return_value = _mock_response(200, {"hits": {"hits": []}})
        checkpoints.search_stuck_claims(max_age_minutes=45)
        query = mock_post.call_args[1]["json"]["query"]
        filters = query["bool"]["filter"]
        self.assertIn({"term": {"phase": "CLAIMED"}}, filters)
        self.assertIn({"range": {"@timestamp": {"lte": "now-45m"}}}, filters)

    @mock.patch("checkpoints.requests.post")
    def test_search_stuck_claims_defaults_to_wildcard_tenant_index(self, mock_post):
        mock_post.return_value = _mock_response(200, {"hits": {"hits": []}})
        checkpoints.search_stuck_claims()
        url = mock_post.call_args[0][0]
        self.assertIn("agent-checkpoints-*/_search", url)

    @mock.patch("checkpoints.requests.post")
    def test_search_stuck_claims_scopes_to_one_tenant_when_given(self, mock_post):
        mock_post.return_value = _mock_response(200, {"hits": {"hits": []}})
        checkpoints.search_stuck_claims(tenant_id="home-smith")
        url = mock_post.call_args[0][0]
        self.assertIn("agent-checkpoints-home-smith/_search", url)

    @mock.patch("checkpoints.requests.post")
    def test_search_stuck_claims_raises_on_es_server_error(self, mock_post):
        mock_post.return_value = _mock_response(500)
        with self.assertRaises(requests.HTTPError):
            checkpoints.search_stuck_claims()

    def test_search_stuck_claims_rejects_invalid_tenant_id_that_is_not_the_wildcard(self):
        with self.assertRaises(ValueError):
            checkpoints.search_stuck_claims(tenant_id="tenant-a,other-index")

    def test_search_stuck_claims_rejects_non_positive_max_age_minutes(self):
        # code-reviewer Should-Fix: manage_stuck_claims.py's _positive_float
        # argparse type is an upstream gate, not a property of this
        # function itself — a future non-CLI caller passing -5/nan/inf
        # must not reach a malformed ES date-math expression.
        with self.assertRaises(ValueError):
            checkpoints.search_stuck_claims(max_age_minutes=-5)
        with self.assertRaises(ValueError):
            checkpoints.search_stuck_claims(max_age_minutes=float("nan"))
        with self.assertRaises(ValueError):
            checkpoints.search_stuck_claims(max_age_minutes=float("inf"))


if __name__ == "__main__":
    unittest.main()
