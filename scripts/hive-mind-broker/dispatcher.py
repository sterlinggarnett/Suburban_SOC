"""
dispatcher.py — SSH-dispatches nftables blocks to the router fleet.

Enforces the §12.4 permanent exclusion list (fails closed if it can't be
read) and §12.3's SSH host-key verification (audit P1-3 — strict by default;
BROKER_INSECURE_SSH=true opts out for a lab/first-run only). Concurrently
blocks an IP across every router in a tenant's inventory.
"""

import asyncio
import asyncssh
import ipaddress
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# CDP §12.4: permanent exclusion list — IPs the broker may never block.
def _default_exclusion_path() -> str:
    """Locate governance/exclusion_list.txt by walking up from this file.

    A fixed parents[N] breaks across layouts: in the repo this file lives at
    scripts/hive-mind-broker/, but in the container it is /app/dispatcher.py (only
    two parents) — parents[2] raised IndexError at import and crash-looped the
    broker. Walking the parents finds it in both, with a container-mount fallback.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "governance" / "exclusion_list.txt"
        if candidate.is_file():
            return str(candidate)
    return "/governance/exclusion_list.txt"


EXCLUSION_LIST = os.environ.get("EXCLUSION_LIST") or _default_exclusion_path()

# SSH host-key verification (audit P1-3). Previously every router connection used
# known_hosts=None (no host-key checking), so a MITM on the router path could
# capture the root SSH session on the containment path. Default to verifying
# against a known_hosts file. Operators must pin the router host keys there (e.g.
# `ssh-keyscan -t ed25519 <router> >> ~/.ssh/known_hosts`). An explicit
# BROKER_INSECURE_SSH=true restores the old no-verification behaviour for a
# first-run/lab only — it logs loudly.
KNOWN_HOSTS = os.path.expanduser(
    os.environ.get("BROKER_KNOWN_HOSTS", "~/.ssh/known_hosts"))
INSECURE_SSH = os.environ.get("BROKER_INSECURE_SSH", "false").lower() == "true"


def _resolve_known_hosts():
    """Return the asyncssh `known_hosts` value: the known_hosts path (strict — the
    connection fails if the router key is unknown), or None ONLY when the operator
    explicitly opted out via BROKER_INSECURE_SSH=true."""
    if INSECURE_SSH:
        logger.warning("BROKER_INSECURE_SSH=true — SSH host-key verification is DISABLED "
                        "(lab/first-run only; do not use in production).")
        return None
    return KNOWN_HOSTS


class ExclusionListUnavailable(RuntimeError):
    """The §12.4 exclusion list could not be read. Callers MUST fail closed —
    refuse to dispatch a block — rather than proceed with an unverifiable list."""


def load_excluded_ips() -> set:
    """Read IP/CIDR entries (IPv4 or IPv6, single address or network) from the
    canonical exclusion list (audit P2-7). MAC lines and junk are skipped — the
    broker blocks by IP only.

    Raises ExclusionListUnavailable if the list can't be read, so is_excluded_ip
    fails CLOSED instead of silently returning an empty (block-everything) set."""
    ips = set()
    try:
        with open(EXCLUSION_LIST, "r", encoding="utf-8") as fh:
            for line in fh:
                entry = line.split("#", 1)[0].strip()
                if not entry:
                    continue
                try:
                    ipaddress.ip_network(entry, strict=False)  # validates v4/v6/CIDR
                    ips.add(entry)
                except ValueError:
                    pass  # not an IP/CIDR (e.g. a MAC) — broker excludes by IP
    except OSError as e:
        logger.error("EXCLUSION LIST UNREADABLE (%s): %s — failing CLOSED", EXCLUSION_LIST, e)
        raise ExclusionListUnavailable(str(e)) from e
    return ips


def validate_ip(attacker_ip) -> "ipaddress._BaseAddress":
    """Validate attacker_ip is a well-formed IPv4/IPv6 address string.

    Raises ValueError if attacker_ip is not a string, or is not a parseable IP
    address (audit #164 / NIST SI-10) — callers must reject malformed input
    rather than letting it reach a firewall command or SSH-executed string."""
    if not isinstance(attacker_ip, str):
        raise ValueError(f"attacker_ip must be a string, got {type(attacker_ip).__name__}")
    return ipaddress.ip_address(attacker_ip)


def is_excluded_ip(attacker_ip: str) -> bool:
    """True if attacker_ip falls inside any excluded address/CIDR (v4 or v6).

    Fails CLOSED: if the exclusion list can't be read, return True so the broker
    refuses to dispatch a block for ANY asset until the list is restored (§12.4).

    Raises ValueError if attacker_ip is not a parseable IP address (audit #164 /
    NIST SI-10) — a malformed address is refused outright instead of silently
    being treated as "not excluded", which previously let unvalidated input
    reach build_nft_command."""
    addr = validate_ip(attacker_ip)
    try:
        entries = load_excluded_ips()
    except ExclusionListUnavailable:
        return True
    for entry in entries:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


# Formulate the nftables drop command (Task 2.2.1)
# Drops traffic from the specified IP on the OpenWrt input chain.
# Note: For OpenWrt 22.03+, we assume 'inet fw4 input' is the default target chain.
#
# #278: `nft add element` to a named set (not a bare `nft add rule ... drop`)
# — element addition is idempotent (adding an already-present element is a
# no-op), unlike rule addition (running the old command twice created TWO
# identical drop rules). This matters because #278's own reconciliation
# below can leave a genuine double-dispatch on the table if a retry ever
# races an already-applied block; with a named set, that race is now
# harmless instead of leaving duplicate rules to clean up.
#
# Assumes NFT_BLOCKLIST_SET already exists in table `inet fw4` with a
# referencing rule (e.g. `ip saddr @hivemind_blocklist drop`) configured as
# part of the router's own base firewall config — this command only ever
# manages SET MEMBERSHIP, it does not create the set or the rule that
# references it. That's a one-time router-provisioning step, out of scope
# for a per-dispatch command (see docs/SOP-* for the provisioning note).
#
# security-auditor review (#278, Finding: RCE amplifier): this value is
# interpolated into a command string executed by the ROUTER'S ROOT SHELL over
# SSH (build_nft_command/build_nft_verify_command below). attacker_ip is
# validated by validate_ip(), but until now NFT_BLOCKLIST_SET was not —
# anyone who can influence the broker's environment (a compose override, the
# .env file, a CI variable) could turn "can edit broker config" into root RCE
# on every router in the inventory. nftables identifiers are
# alphanumeric/underscore, not digit-first (code-reviewer: a digit-first
# name would pass a laxer check only to fail at runtime on the router as a
# generic nft syntax error instead of being caught here), so this rejects
# nothing legitimate.
NFT_BLOCKLIST_SET = os.environ.get("NFT_BLOCKLIST_SET", "hivemind_blocklist")
if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,31}", NFT_BLOCKLIST_SET):
    raise RuntimeError(
        f"NFT_BLOCKLIST_SET={NFT_BLOCKLIST_SET!r} is not a valid nftables set "
        f"identifier — refusing to start rather than interpolate it unvalidated "
        f"into a command executed by the router's root shell.")


def build_nft_command(attacker_ip: str) -> str:
    validate_ip(attacker_ip)  # raises ValueError for malformed input (audit #164 / NIST SI-10)
    return f"nft add element inet fw4 {NFT_BLOCKLIST_SET} {{ {attacker_ip} }}"


def build_nft_verify_command(attacker_ip: str) -> str:
    """#278: read-only membership check for the reconciliation follow-up
    below — `nft get element` exits 0 iff the element IS present in the
    set, non-zero otherwise. A clean binary signal via exit code, no text
    parsing of `nft list chain`/`nft list ruleset` output needed."""
    validate_ip(attacker_ip)
    return f"nft get element inet fw4 {NFT_BLOCKLIST_SET} {{ {attacker_ip} }}"

# #247 security-auditor review (round 3): the ORIGINAL 10s/10s defaults gave a
# 20s worst case per router (connect + command), exceeding the agent's own 15s
# HTTP read timeout to /webhook/dispatch — meaning an ordinary slow-but-working
# router could make the AGENT time out and raise IsolationOutcomeUnknown before
# the broker ever got a chance to answer cleanly, turning routine latency into
# a stuck claim instead of a genuine ambiguity. Lowered to 5s/5s (agent.py's
# timeout was raised to 20s for headroom on top of that) and made
# env-overridable in case a real deployment's routers need more.
SSH_CONNECT_TIMEOUT = float(os.environ.get("SSH_CONNECT_TIMEOUT", "5"))  # seconds
SSH_COMMAND_TIMEOUT = float(os.environ.get("SSH_COMMAND_TIMEOUT", "5"))  # seconds

# #278: the bounded follow-up verification below (_verify_block_applied)
# uses its OWN, SHORTER timeouts — not SSH_CONNECT/COMMAND_TIMEOUT — so the
# combined worst case (original attempt + this follow-up) stays safely
# under the agent's 20s HTTP timeout to /webhook/dispatch.
#
# security-auditor review flagged connect_timeout and login_timeout as
# ADDITIVE sequential phase budgets (worst case 5+5+5=15s original,
# 3+3+3=9s follow-up, 24s total — over budget). Empirically verified
# otherwise: asyncssh.connect(connect_timeout=N, login_timeout=N) against a
# target that never completes the TCP handshake, AND separately against one
# that completes TCP but stalls the SSH banner/auth, both aborted at ~N
# seconds, not ~2N — connect_timeout is the single outer bound
# (asyncio.wait_for) wrapping TCP-connect-through-auth as one operation;
# login_timeout does not add on top of it. So each connect() call costs at
# most SSH_*_CONNECT_TIMEOUT once, not twice: 10s (original, 5s connect +
# 5s command) + 6s (this, 3s connect + 3s command) = 16s, leaving ~4s of
# slack. A follow-up that itself needed the full 5s/5s budget would risk
# the AGENT timing out and raising IsolationOutcomeUnknown before the
# broker's own reconciliation attempt even finishes — defeating the point
# of adding it (same class of mistake #247 round-3's SSH_CONNECT/
# COMMAND_TIMEOUT reduction was fixing).
SSH_VERIFY_CONNECT_TIMEOUT = float(os.environ.get("SSH_VERIFY_CONNECT_TIMEOUT", "3"))  # seconds
SSH_VERIFY_COMMAND_TIMEOUT = float(os.environ.get("SSH_VERIFY_COMMAND_TIMEOUT", "3"))  # seconds


async def _verify_block_applied(router: dict, attacker_ip: str) -> bool | None:
    """#278: ONE bounded, read-only follow-up connection after an ambiguous
    ("unknown") outcome, to reconcile it to a confirmed answer for the
    common case — a transient SSH blip, with the router reachable again a
    moment later. Returns True/False when the follow-up itself got a clean
    determinate answer, or None if it couldn't (still genuinely unknown —
    this never guesses; a failed/timed-out follow-up is not evidence of
    anything and must not be treated as though it were).

    Always opens a FRESH connection rather than trying to reuse whatever
    connection object the original attempt had (which may itself be in an
    unknown state, e.g. mid-teardown) — simpler to reason about than
    conditionally reusing one, at the cost of a little latency in the rare
    signal-killed-but-connection-still-alive case.
    """
    try:
        ip = router.get("ip_address")
        username = router.get("username", "root")
        key_path = os.path.expanduser(router.get("ssh_key_path", "~/.ssh/id_ed25519_hivemind"))
        command = build_nft_verify_command(attacker_ip)
    except Exception as exc:
        logger.error("Cannot verify block on malformed router entry %r: %s", router, exc)
        return None

    try:
        conn = await asyncssh.connect(
            host=ip,
            username=username,
            client_keys=[key_path],
            known_hosts=_resolve_known_hosts(),
            connect_timeout=SSH_VERIFY_CONNECT_TIMEOUT,
            login_timeout=SSH_VERIFY_CONNECT_TIMEOUT,
        )
    except Exception as exc:
        # Still unreachable — the common case this exists for didn't apply
        # this time. Stay "unknown", exactly as before this fix existed.
        logger.warning("Verification follow-up could not reach %s: %s", ip, exc)
        return None

    try:
        async with conn:
            await asyncio.wait_for(conn.run(command, check=True), timeout=SSH_VERIFY_COMMAND_TIMEOUT)
        logger.info("Verification follow-up confirms %s IS blocked on %s.", attacker_ip, ip)
        return True
    except asyncssh.ProcessError as exc:
        if exc.exit_signal is not None:
            # The VERIFICATION command itself was signal-killed — this says
            # nothing about whether the element is present, only that this
            # read-only check didn't get to finish. Same "not confirmed"
            # reasoning as block_ip_on_router's own signal-kill branch —
            # do not treat an interrupted check as a determinate "absent".
            logger.warning("Verification follow-up on %s was itself signaled: %s", ip, exc)
            return None
        if exc.exit_status == 1:
            # security-auditor round-2 MEDIUM: nft(8) documents no per-error
            # EXIT STATUS taxonomy — 1 (EXIT_FAILURE) is nft's generic
            # command-failure code, not a code specific to "element not in
            # set". This narrows round-1's "any non-zero -> absent" (which
            # misread 1 as element-specific) to "the common, but NOT
            # exclusively element-specific, code" — still an improvement
            # (a shell-level 127/126 or a signal no longer reads as
            # "absent"), but NOT the precise disambiguation this needs.
            # Confirming nft's real behavior (does a missing set/table also
            # exit 1 here, or something else?) needs the actual deployed nft
            # version — same as the "flags interval" idempotency question
            # above (SOP-005) — tracked as a tester-debugger follow-up, not
            # blind-fixed here. Until then this stays on the safe side of
            # the HIGH-1 asymmetry: a false "absent" only costs one harmless
            # idempotent retry, never a false "success".
            logger.info("Verification follow-up confirms %s is NOT blocked on %s.", attacker_ip, ip)
            return False
        # Any exit status OTHER than 1 (missing set/table producing a
        # different code on this nft version, unsupported flag combo, nft
        # not on PATH, permission error, ...) is NOT evidence the element is
        # absent — stay unknown rather than guess.
        logger.warning("Verification follow-up on %s exited %s (stderr=%r) — treating as "
                       "inconclusive, not confirmed-absent: %s",
                       ip, exc.exit_status, (exc.stderr or "")[:300], exc)
        return None
    except Exception as exc:
        # Connection lost / command timed out mid-verification — the
        # follow-up itself is now ambiguous too. Do not guess.
        logger.warning("Verification follow-up on %s was itself inconclusive: %s", ip, exc)
        return None


async def _reconcile_unknown(router: dict, attacker_ip: str, ip, reason: str) -> str:
    """#278: before block_ip_on_router() gives up as "unknown", make ONE
    bounded read-only follow-up attempt to actually check whether the block
    landed — closes the common case (the router recovers from a transient
    blip a moment later) without a human needing to intervene.

    Top-level, explicit-parameter function (not a closure over
    block_ip_on_router's locals) so it matches _verify_block_applied's own
    style and stays independently testable/reorderable — `ip` is passed
    through rather than re-derived from `router` purely for the log
    messages below (code-reviewer round-1: a closure capturing it silently
    depended on definition order relative to where `ip` gets assigned).

    security-auditor review (#278, HIGH): may promote to "failed" but MUST
    NEVER promote to "success". `nft get element` only proves SET
    MEMBERSHIP, not that the referencing drop rule
    (`ip saddr @hivemind_blocklist drop`) still exists in a reachable
    chain — the set could survive a partial fw4 rebuild while the rule
    doesn't. The two directions are not symmetric: a false "failed" costs
    one harmless idempotent retry, while a false "success" flows into
    agent.py's close_case(..., "true_positive_contained") and permanently
    forecloses any retry on a host that was never actually contained. So
    a determinate-present follow-up still leaves the outcome "unknown" —
    for a human to resolve via manage_stuck_claims.py, exactly as before
    #278 existed — while a determinate-absent one safely resolves to
    "failed"."""
    verified = await _verify_block_applied(router, attacker_ip)
    if verified is False:
        logger.info("Reconciled %s on %s to CONFIRMED failure (%s, "
                    "but follow-up verification found it NOT applied).", attacker_ip, ip, reason)
        return "failed"
    if verified is True:
        logger.warning("Verification follow-up found %s present in the blocklist SET on %s "
                       "(%s) — but set membership alone does not confirm the referencing "
                       "drop rule is still in place, so this is NOT auto-promoted to "
                       "success. Leaving unknown for manual review (manage_stuck_claims.py "
                       "show).", attacker_ip, ip, reason)
    return "unknown"


async def block_ip_on_router(router: dict, attacker_ip: str) -> str:
    """
    Connects to a single router and executes the block command. (Task 2.1.1 & 2.2.2)

    Returns "success" (command confirmed applied), "failed" (command confirmed
    NOT applied — the connection was never established, the router dict itself
    was malformed, or the remote command ran and reported a non-zero exit with
    no signal involved), or "unknown" (the SSH session was lost, or the command
    timed out, AFTER the command was sent but before its exit status could be
    confirmed — nft may already have run on the router, AND the #278 bounded
    follow-up verification below also couldn't determine it — see
    _verify_block_applied()). #247 security-auditor review: the agent-side
    caller MUST NEVER treat "unknown" the same as "failed" — releasing an
    approval claim on an unconfirmed outcome risks dispatching the same
    block twice on retry.
    """
    try:
        ip = router.get("ip_address")
        username = router.get("username", "root")
        key_path = os.path.expanduser(router.get("ssh_key_path", "~/.ssh/id_ed25519_hivemind"))
        command = build_nft_command(attacker_ip)
    except Exception as exc:
        # A malformed inventory entry — nothing was ever sent to any router,
        # confirmed non-dispatch (round-3 security-auditor review: this used
        # to run outside any try, so one bad entry could crash the whole
        # asyncio.gather() and silently drop every sibling router's outcome).
        logger.error("Malformed router entry %r: %s", router, exc)
        return "failed"

    try:
        conn = await asyncssh.connect(
            host=ip,
            username=username,
            client_keys=[key_path],
            known_hosts=_resolve_known_hosts(),  # strict by default (audit P1-3)
            connect_timeout=SSH_CONNECT_TIMEOUT,
            login_timeout=SSH_CONNECT_TIMEOUT,  # bounds auth/KEX too, not just TCP connect
        )
    except Exception as exc:
        # Never connected — the command never even attempted to run.
        logger.error("SSH connection failed to %s: %s", ip, exc)
        return "failed"

    try:
        async with conn:
            await asyncio.wait_for(conn.run(command, check=True), timeout=SSH_COMMAND_TIMEOUT)
        logger.info("Successfully blocked %s on %s", attacker_ip, ip)
        return "success"
    except asyncssh.ProcessError as exc:
        if exc.exit_signal is not None:
            # The remote process was KILLED (e.g. an OOM kill on a small
            # router), not a clean non-zero exit — it may have already issued
            # its netlink call before being signaled. Not confirmed.
            logger.error("Outcome UNKNOWN on %s (command was signaled, not a "
                         "clean exit): %s", ip, exc)
            return await _reconcile_unknown(router, attacker_ip, ip, "command was signaled")
        # A clean non-zero exit — the command ran ON THE ROUTER and nft itself
        # reported failure. Confirmed NOT applied.
        logger.error("Block command failed on %s: %s", ip, exc)
        return "failed"
    except Exception as exc:
        # Connection lost, or the command timed out, at some point after being
        # sent (including during connection teardown) — nft may have already
        # run before we lost the ability to confirm it. Not confirmed either way.
        logger.error("Outcome UNKNOWN executing on %s (connection lost/timed out "
                     "mid-command): %s", ip, exc)
        return await _reconcile_unknown(router, attacker_ip, ip, "connection lost/timed out mid-command")


async def dispatch_block_to_all(routers: list, attacker_ip: str):
    """
    Loops through the inventory and fires concurrent SSH block commands. (Task 2.1.2)

    Returns (success_count, unknown_count) out of len(routers). #247: callers
    must treat unknown_count > 0 as "some routers' outcome could not be
    confirmed" — NOT folded into either success or failure, since collapsing
    it into failure is exactly what let an agent-side retry risk a real
    double-dispatch (security-auditor review).
    """
    # §12.4: never push a block for a protected asset, even if an alert demands it.
    if is_excluded_ip(attacker_ip):
        logger.warning("REFUSED: %s is on the permanent exclusion list — no block dispatched.",
                        attacker_ip)
        return 0, 0

    logger.info("Dispatching block for %s to %d routers...", attacker_ip, len(routers))

    # Create a list of async tasks for all routers
    tasks = [block_ip_on_router(r, attacker_ip) for r in routers]

    # Run them concurrently (acting as a parallel connection pool).
    # return_exceptions=True (round-3 security-auditor review): block_ip_on_router()
    # already catches everything it can classify, but a truly unexpected exception
    # escaping it must not take down every OTHER router's already-in-flight result
    # — an unclassifiable outcome is exactly what "unknown" exists for.
    results = await asyncio.gather(*tasks, return_exceptions=True)
    results = ["unknown" if isinstance(r, BaseException) else r for r in results]

    success_count = sum(1 for r in results if r == "success")
    unknown_count = sum(1 for r in results if r == "unknown")
    logger.info("Immunization complete: %d/%d routers confirmed updated, %d unknown.",
                success_count, len(routers), unknown_count)
    return success_count, unknown_count
