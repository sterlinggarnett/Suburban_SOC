"""
dispatcher.py — block_ip_on_router() / dispatch_block_to_all() outcome
classification (#247 security-auditor review).

A router-side SSH failure is NOT a single "it failed" bucket. block_ip_on_router()
must distinguish:
  - "failed"  — the command definitely did NOT run (connection never
                established) or ran and reported failure (asyncssh.ProcessError,
                a non-zero nft exit) — confirmed non-dispatch.
  - "unknown" — the connection was lost or the command timed out AFTER being
                sent, before its exit status could be confirmed — nft may
                already have applied the rule. NEVER collapsed into "failed":
                the agent-side caller (agent.py's dispatch_block_via_broker)
                treats a confirmed failure as safe-to-release-and-retry, and
                folding "unknown" into that risks a real double-dispatch.

dispatch_block_to_all() aggregates per-router outcomes into (success_count,
unknown_count) — two independent numbers, not one blended count.

Uses asyncio.run() directly (no pytest-asyncio dependency), matching this
repo's existing async-test convention (see test_app.py's write_denial tests).
"""
import asyncio
import unittest
from unittest import mock

import asyncssh

import dispatcher


def _mock_conn(run_side_effect=None):
    """A MagicMock standing in for an asyncssh.SSHClientConnection: supports
    `async with conn:` and an awaitable `conn.run(...)`."""
    conn = mock.MagicMock()
    conn.__aenter__ = mock.AsyncMock(return_value=conn)
    conn.__aexit__ = mock.AsyncMock(return_value=False)
    if run_side_effect is not None:
        conn.run = mock.AsyncMock(side_effect=run_side_effect)
    else:
        conn.run = mock.AsyncMock(return_value=mock.MagicMock())
    return conn


ROUTER = {"id": "test-router", "tenant": "home-smith", "ip_address": "192.168.1.1",
          "username": "root", "ssh_key_path": "~/.ssh/id_ed25519_hivemind"}


_SIGKILL = ("SIGKILL", False, "Killed", "en-US")


def _process_error(exit_signal=None, exit_status=1):
    return asyncssh.ProcessError(
        env=None, command="nft add rule ...", subsystem=None,
        exit_status=None if exit_signal else exit_status, exit_signal=exit_signal, returncode=1,
        stdout="", stderr="nft: rule rejected", reason="Command failed")


class BlockIpOnRouterTests(unittest.TestCase):
    def test_success_when_command_confirms(self):
        with mock.patch.object(dispatcher.asyncssh, "connect",
                               new=mock.AsyncMock(return_value=_mock_conn())):
            result = asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(result, "success")

    def test_failed_when_connection_never_establishes(self):
        # Auth failure, host-key mismatch, refused, connect timeout — the
        # command never even attempted to run. Confirmed non-dispatch.
        with mock.patch.object(dispatcher.asyncssh, "connect",
                               new=mock.AsyncMock(side_effect=ConnectionRefusedError("refused"))):
            result = asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(result, "failed")

    def test_failed_when_command_reports_process_error(self):
        # The command RAN on the router and nft itself rejected the rule
        # (check=True raises ProcessError on a non-zero exit) — confirmed
        # non-dispatch, safe to classify as "failed" (not "unknown").
        conn = _mock_conn(run_side_effect=_process_error())
        with mock.patch.object(dispatcher.asyncssh, "connect",
                               new=mock.AsyncMock(return_value=conn)):
            result = asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(result, "failed")

    def test_unknown_when_connection_lost_mid_command(self):
        # The connection was lost AFTER the command was sent — nft may
        # already have applied the rule. Must NOT be "failed".
        conn = _mock_conn(run_side_effect=ConnectionResetError("connection lost"))
        with mock.patch.object(dispatcher.asyncssh, "connect",
                               new=mock.AsyncMock(return_value=conn)):
            result = asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(result, "unknown")

    def test_unknown_when_command_times_out(self):
        async def _hang(*a, **k):
            await asyncio.sleep(999)
        conn = _mock_conn()
        conn.run = _hang
        with mock.patch.object(dispatcher.asyncssh, "connect",
                               new=mock.AsyncMock(return_value=conn)), \
             mock.patch.object(dispatcher, "SSH_COMMAND_TIMEOUT", 0.01):
            result = asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(result, "unknown")

    def test_unknown_when_process_error_is_a_signal_kill_not_a_clean_exit(self):
        # round-3 security-auditor review: a signal-killed remote process (e.g.
        # an OOM kill on a small router) may have already issued its netlink
        # call before being killed — NOT the same as a clean non-zero exit.
        conn = _mock_conn(run_side_effect=_process_error(exit_signal=_SIGKILL))
        with mock.patch.object(dispatcher.asyncssh, "connect",
                               new=mock.AsyncMock(return_value=conn)):
            result = asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(result, "unknown")

    def test_failed_when_router_entry_is_malformed(self):
        # round-3 security-auditor review: a bad inventory entry must not
        # crash the whole dispatch (it used to run outside any try) — nothing
        # was ever sent, so "failed" (confirmed non-dispatch) is correct.
        with mock.patch.object(dispatcher.asyncssh, "connect") as mock_connect:
            result = asyncio.run(dispatcher.block_ip_on_router(None, "1.2.3.4"))
        self.assertEqual(result, "failed")
        mock_connect.assert_not_called()

    def test_connect_is_bounded_by_both_timeouts(self):
        conn = _mock_conn()
        mock_connect = mock.AsyncMock(return_value=conn)
        with mock.patch.object(dispatcher.asyncssh, "connect", new=mock_connect):
            asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        kwargs = mock_connect.call_args.kwargs
        self.assertEqual(kwargs["connect_timeout"], dispatcher.SSH_CONNECT_TIMEOUT)
        # login_timeout bounds auth/KEX too, not just the TCP handshake —
        # connect_timeout alone may not cover a stalled authentication phase.
        self.assertEqual(kwargs["login_timeout"], dispatcher.SSH_CONNECT_TIMEOUT)


# --- #278: bounded follow-up reconciliation of an "unknown" outcome --------
class ReconciliationTests(unittest.TestCase):
    def test_stays_unknown_when_followup_confirms_present_membership_is_not_containment_proof(self):
        # security-auditor HIGH finding: `nft get element` proves SET
        # MEMBERSHIP, not that the referencing drop rule still exists in a
        # reachable chain. A false "success" here would flow into
        # agent.py's close_case(..., "true_positive_contained") with no
        # possibility of retry, so reconciliation must NEVER promote to
        # success — even when the follow-up gets a clean determinate
        # "present" answer, this must stay "unknown" for a human to decide.
        original_conn = _mock_conn(run_side_effect=ConnectionResetError("connection lost"))
        followup_conn = _mock_conn()  # run() succeeds by default
        with mock.patch.object(dispatcher.asyncssh, "connect",
                               new=mock.AsyncMock(side_effect=[original_conn, followup_conn])):
            result = asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(result, "unknown")

    def test_unknown_is_reconciled_to_failed_when_followup_confirms_absent(self):
        # Same ambiguous original attempt, but the follow-up's `nft get
        # element` cleanly reports the element is NOT present (non-zero
        # exit, no signal) -> promoted to a confirmed failure, safe to
        # release the approval claim and retry.
        original_conn = _mock_conn(run_side_effect=ConnectionResetError("connection lost"))
        followup_conn = _mock_conn(run_side_effect=_process_error())
        with mock.patch.object(dispatcher.asyncssh, "connect",
                               new=mock.AsyncMock(side_effect=[original_conn, followup_conn])):
            result = asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(result, "failed")

    def test_stays_unknown_when_followup_also_cannot_connect(self):
        # The common case (router recovers) didn't apply this time — the
        # follow-up itself couldn't reach the router either. Must NOT guess.
        original_conn = _mock_conn(run_side_effect=ConnectionResetError("connection lost"))
        with mock.patch.object(dispatcher.asyncssh, "connect",
                               new=mock.AsyncMock(
                                   side_effect=[original_conn, ConnectionRefusedError("still down")])):
            result = asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(result, "unknown")

    def test_stays_unknown_when_followup_exits_with_an_unrecognized_non_zero_status(self):
        # security-auditor MEDIUM finding: `nft get element` can exit
        # non-zero for reasons OTHER than "element absent" — missing
        # set/table, unsupported flag combo, nft not on PATH (127), etc.
        # Only exit 1 (nft's generic EXIT_FAILURE, not a code specific to
        # "element absent" — see dispatcher.py's comment) may resolve to
        # "failed"; anything else must stay unknown rather than misreport a
        # genuinely-applied block as confirmed-failed.
        original_conn = _mock_conn(run_side_effect=ConnectionResetError("connection lost"))
        followup_conn = _mock_conn(run_side_effect=_process_error(exit_status=127))
        with mock.patch.object(dispatcher.asyncssh, "connect",
                               new=mock.AsyncMock(side_effect=[original_conn, followup_conn])):
            result = asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(result, "unknown")

    def test_stays_unknown_when_followup_itself_is_signaled(self):
        # A signal-killed VERIFICATION command says nothing about whether
        # the element is present — it's a different ambiguity, not a clean
        # "absent" answer. Must not be treated as determinate.
        original_conn = _mock_conn(run_side_effect=_process_error(exit_signal=_SIGKILL))
        followup_conn = _mock_conn(run_side_effect=_process_error(exit_signal=_SIGKILL))
        with mock.patch.object(dispatcher.asyncssh, "connect",
                               new=mock.AsyncMock(side_effect=[original_conn, followup_conn])):
            result = asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(result, "unknown")

    def test_followup_uses_shorter_dedicated_timeouts(self):
        # Must NOT reuse SSH_CONNECT_TIMEOUT/SSH_COMMAND_TIMEOUT — the
        # combined worst case (original + follow-up) has to stay under the
        # agent's 20s HTTP timeout (see dispatcher.py's own comment on this).
        original_conn = _mock_conn(run_side_effect=ConnectionResetError("connection lost"))
        followup_conn = _mock_conn()
        mock_connect = mock.AsyncMock(side_effect=[original_conn, followup_conn])
        with mock.patch.object(dispatcher.asyncssh, "connect", new=mock_connect):
            asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        followup_kwargs = mock_connect.call_args_list[1].kwargs
        self.assertEqual(followup_kwargs["connect_timeout"], dispatcher.SSH_VERIFY_CONNECT_TIMEOUT)
        self.assertEqual(followup_kwargs["login_timeout"], dispatcher.SSH_VERIFY_CONNECT_TIMEOUT)
        self.assertNotEqual(dispatcher.SSH_VERIFY_CONNECT_TIMEOUT, dispatcher.SSH_CONNECT_TIMEOUT)

    def test_success_path_never_triggers_a_followup_connection(self):
        # The reconciliation follow-up must only fire on a genuine "unknown"
        # — a clean success shouldn't cost a second SSH round trip.
        mock_connect = mock.AsyncMock(return_value=_mock_conn())
        with mock.patch.object(dispatcher.asyncssh, "connect", new=mock_connect):
            asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(mock_connect.await_count, 1)

    def test_confirmed_failed_path_never_triggers_a_followup_connection(self):
        conn = _mock_conn(run_side_effect=_process_error())  # clean non-zero exit
        mock_connect = mock.AsyncMock(return_value=conn)
        with mock.patch.object(dispatcher.asyncssh, "connect", new=mock_connect):
            asyncio.run(dispatcher.block_ip_on_router(ROUTER, "1.2.3.4"))
        self.assertEqual(mock_connect.await_count, 1)


class NftCommandTests(unittest.TestCase):
    def test_build_nft_command_is_idempotent_set_element_add(self):
        # #278: `add element` on an already-present element is a no-op,
        # unlike the old bare `add rule ... drop` (running it twice created
        # two identical drop rules) — a genuine double-dispatch is now
        # harmless instead of leaving duplicate rules on the router.
        cmd = dispatcher.build_nft_command("1.2.3.4")
        self.assertIn("add element", cmd)
        self.assertIn(dispatcher.NFT_BLOCKLIST_SET, cmd)
        self.assertIn("1.2.3.4", cmd)
        self.assertNotIn("add rule", cmd)

    def test_build_nft_command_rejects_malformed_ip(self):
        with self.assertRaises(ValueError):
            dispatcher.build_nft_command("1.1.1.1 drop; reboot #")

    def test_build_nft_verify_command_is_read_only_get(self):
        cmd = dispatcher.build_nft_verify_command("1.2.3.4")
        self.assertIn("get element", cmd)
        self.assertIn(dispatcher.NFT_BLOCKLIST_SET, cmd)
        self.assertIn("1.2.3.4", cmd)
        self.assertNotIn("add", cmd)

    def test_module_refuses_to_import_with_a_malformed_blocklist_set_name(self):
        # security-auditor MEDIUM finding (RCE amplifier): NFT_BLOCKLIST_SET
        # is interpolated into a command run by the router's root shell over
        # SSH — an attacker-influenced env var with shell metacharacters
        # must be rejected at import time, not silently executed remotely.
        import importlib

        def _restore():
            # security-auditor round-2 INFO: run via addCleanup (executes
            # even if the test body errors, unlike a plain trailing
            # statement) and pin a KNOWN-good value rather than trusting
            # ambient os.environ — otherwise a bad NFT_BLOCKLIST_SET already
            # present in the CI environment could make this restore itself
            # fail, leaving every later test in the process importing a
            # module that never finished reloading.
            with mock.patch.dict("os.environ", {"NFT_BLOCKLIST_SET": "hivemind_blocklist"}):
                importlib.reload(dispatcher)
        self.addCleanup(_restore)

        with mock.patch.dict("os.environ", {"NFT_BLOCKLIST_SET": "x; wget evil #"}):
            with self.assertRaises(RuntimeError):
                importlib.reload(dispatcher)

    def test_module_refuses_a_digit_first_blocklist_set_name(self):
        # code-reviewer nitpick: nftables identifiers are alphanumeric/
        # underscore but NOT digit-first — a laxer check would only fail
        # at runtime on the router as a generic nft syntax error.
        import importlib

        def _restore():
            with mock.patch.dict("os.environ", {"NFT_BLOCKLIST_SET": "hivemind_blocklist"}):
                importlib.reload(dispatcher)
        self.addCleanup(_restore)

        with mock.patch.dict("os.environ", {"NFT_BLOCKLIST_SET": "123set"}):
            with self.assertRaises(RuntimeError):
                importlib.reload(dispatcher)


class DispatchBlockToAllTests(unittest.TestCase):
    def test_refuses_excluded_ip_without_dispatching(self):
        with mock.patch.object(dispatcher, "is_excluded_ip", return_value=True), \
             mock.patch.object(dispatcher, "block_ip_on_router") as mock_block:
            result = asyncio.run(dispatcher.dispatch_block_to_all([ROUTER], "192.168.1.1"))
        self.assertEqual(result, (0, 0))
        mock_block.assert_not_called()

    def test_aggregates_success_and_unknown_counts_independently(self):
        routers = [dict(ROUTER, id="r1"), dict(ROUTER, id="r2"), dict(ROUTER, id="r3")]
        outcomes = iter(["success", "failed", "unknown"])
        with mock.patch.object(dispatcher, "is_excluded_ip", return_value=False), \
             mock.patch.object(dispatcher, "block_ip_on_router",
                               new=mock.AsyncMock(side_effect=lambda *a, **k: next(outcomes))):
            success_count, unknown_count = asyncio.run(
                dispatcher.dispatch_block_to_all(routers, "1.2.3.4"))
        self.assertEqual(success_count, 1)
        self.assertEqual(unknown_count, 1)

    def test_all_unknown_is_never_reported_as_success(self):
        routers = [dict(ROUTER, id="r1"), dict(ROUTER, id="r2")]
        with mock.patch.object(dispatcher, "is_excluded_ip", return_value=False), \
             mock.patch.object(dispatcher, "block_ip_on_router",
                               new=mock.AsyncMock(return_value="unknown")):
            success_count, unknown_count = asyncio.run(
                dispatcher.dispatch_block_to_all(routers, "1.2.3.4"))
        self.assertEqual(success_count, 0)
        self.assertEqual(unknown_count, 2)

    def test_one_router_crashing_does_not_lose_the_others_results(self):
        # round-3 security-auditor review: asyncio.gather() without
        # return_exceptions=True lets ONE router's unexpected exception take
        # down every OTHER router's already-in-flight result. r1 succeeds, r2
        # raises something block_ip_on_router() itself didn't classify — must
        # still count r1's success and treat r2 as unknown, not crash entirely.
        # (gather() preserves input order, so this list lines up r1 -> r2.)
        routers = [dict(ROUTER, id="r1"), dict(ROUTER, id="r2")]
        with mock.patch.object(dispatcher, "is_excluded_ip", return_value=False), \
             mock.patch.object(dispatcher, "block_ip_on_router",
                               new=mock.AsyncMock(side_effect=["success", RuntimeError("unexpected bug")])):
            success_count, unknown_count = asyncio.run(
                dispatcher.dispatch_block_to_all(routers, "1.2.3.4"))
        self.assertEqual(success_count, 1)
        self.assertEqual(unknown_count, 1)


if __name__ == "__main__":
    unittest.main()
