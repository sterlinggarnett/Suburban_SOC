#!/usr/bin/env python3
"""
manage_stuck_claims.py — operator recovery tool for approval claims stuck
in phase=CLAIMED with no automatic resolution (#276).

#247 made execute_approved() auto-release a claim on a CONFIRMED execution
failure, but deliberately leaves it untouched on an IsolationOutcomeUnknown
(the broker connection dropped, or #278's own bounded reconciliation
attempt also couldn't determine the outcome) — releasing an unconfirmed
claim risks a real double-dispatch on retry. Until now, resolving one of
these meant hand-crafting a raw Elasticsearch _update call against
agent-checkpoints-<tenant>/_doc/{alert_id}.claim.

This script never deletes a claim doc — agent_checkpoints's ES role has no
delete privilege by design (#245), and this tool has no code path that
could bypass that even if it tried. It only calls checkpoints.py's own
release_claim()/resolve_claim() (the SAME functions execute_approved()
calls on a confirmed outcome) via the module-level search_stuck_claims()/
get_claim() helpers added alongside this tool — so there is exactly one
code path that ever writes a claim transition, not two independently
maintained ones.

The operator is expected to determine out-of-band (SSH to the router, an
inventory/traffic check, #278's own reconciliation log, etc.) whether the
block actually landed, THEN choose:
  --outcome released — it did NOT land; safe to retry /approve.
  --outcome resolved — it DID land; do not retry (marks the claim done).

Usage:
  python3 manage_stuck_claims.py list [--tenant TENANT] [--max-age-min N]
  python3 manage_stuck_claims.py show TENANT ALERT_ID
  python3 manage_stuck_claims.py resolve TENANT ALERT_ID --outcome {released,resolved} \\
      --actor YOUR_NAME --reason "how you confirmed this" [--force] [--yes]
"""
import argparse
import os
import sys
from datetime import datetime, timezone

import requests

import checkpoints

# Same env var and default slo_metrics.metric_stuck_approval_claims() reads
# (scripts/setup/ai_agent/slo_metrics.py) — an operator who has tuned the
# SLO threshold must see this tool's `list` agree with the dashboard count
# it's documented to match, not silently diverge from a hardcoded literal.
DEFAULT_MAX_AGE_MIN = float(os.environ.get("SLO_STUCK_CLAIM_MAX_MIN", "30"))


def _positive_float(value: str) -> float:
    """argparse `type=` for --max-age-min: rejects negative/zero/nan/inf
    (security-auditor LOW: these feed straight into an ES date-math
    expression as f"now-{v:g}m" — a negative or non-finite value produces
    malformed date math and an unhandled traceback deep inside requests)."""
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number")
    if not (0 < parsed < float("inf")):
        raise argparse.ArgumentTypeError(f"{value!r} must be a positive, finite number")
    return parsed


def _bounded_reason(value: str) -> str:
    """argparse `type=` for --reason: a value approaching Lucene's ~32KB
    keyword term limit would otherwise reach ES and be rejected with a
    generic 400 (security-auditor LOW) instead of a clear CLI-level error.
    1024 is a generous margin for a one-line justification, not a hard
    protocol limit."""
    if len(value) > 1024:
        raise argparse.ArgumentTypeError(
            f"--reason is {len(value)} chars, max 1024 — keep it to a short justification")
    return value


def _age_seconds(timestamp_iso):
    """Returns None (not raises) for an unparseable timestamp — callers use
    that to distinguish "genuinely unknown age" from any real value,
    including 0, which a truthiness check would treat as "no age"."""
    try:
        ts = datetime.fromisoformat(str(timestamp_iso).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return (datetime.now(timezone.utc) - ts).total_seconds()


def _age_str(timestamp_iso) -> str:
    seconds = _age_seconds(timestamp_iso)
    if seconds is None:
        return "unknown"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"


def cmd_list(args) -> int:
    claims, total = checkpoints.search_stuck_claims(
        max_age_minutes=args.max_age_min, tenant_id=args.tenant or "*")
    if not claims:
        print(f"No claims stuck in CLAIMED for longer than {args.max_age_min:g} minutes.")
        return 0
    print(f"{'TENANT':<20} {'ALERT_ID':<42} {'APPROVER':<20} AGE")
    for c in claims:
        tenant = c.get("tenant", {}).get("id", "?")
        print(f"{tenant:<20} {c.get('alert_id', '?'):<42} {c.get('approver', '?'):<20} "
              f"{_age_str(c.get('@timestamp'))}")
    if total > len(claims):
        print(f"\nShowing the oldest {len(claims)} of {total} stuck claims — narrow with "
              f"--tenant, or increase --max-age-min to shrink the population, to see the rest.")
    return 0


def cmd_show(args) -> int:
    claim = checkpoints.get_claim(args.tenant, args.alert_id)
    if claim is None:
        print(f"No claim doc found for tenant={args.tenant!r} alert_id={args.alert_id!r}.")
        return 1
    print(f"tenant:    {claim.get('tenant', {}).get('id')}")
    print(f"alert_id:  {claim.get('alert_id')}")
    print(f"phase:     {claim.get('phase')}")
    print(f"approver:  {claim.get('approver')}")
    print(f"claimed:   {claim.get('@timestamp')} ({_age_str(claim.get('@timestamp'))} ago)")
    if claim.get("phase") != "CLAIMED":
        print(f"\nNote: this claim's phase is {claim.get('phase')!r}, not CLAIMED — "
              f"it is not currently stuck, nothing to resolve.")
        # security-auditor round-2 LOW: these fields (#276 attribution) were
        # write-only from this tool's own perspective — an operator asking
        # "who resolved this and why" had no way to use the tool that
        # recorded the answer.
        if claim.get("resolved_by"):
            print(f"resolved_by:        {claim.get('resolved_by')}")
            print(f"resolution_actor_claimed: {claim.get('resolution_actor_claimed')}")
            print(f"resolved_at:        {claim.get('resolved_at')}")
            print(f"resolution_reason:  {claim.get('resolution_reason')}")
            print(f"resolution_source:  {claim.get('resolution_source')}")
    return 0


def cmd_resolve(args) -> int:
    claim = checkpoints.get_claim(args.tenant, args.alert_id)
    if claim is None:
        print(f"No claim doc found for tenant={args.tenant!r} alert_id={args.alert_id!r}. Nothing to do.")
        return 1
    if claim.get("phase") != "CLAIMED":
        print(f"Refusing: this claim's phase is {claim.get('phase')!r}, not CLAIMED — "
              f"it is not stuck (someone may already have resolved it). Nothing to do.")
        return 1

    # security-auditor MEDIUM (#276): the only prior guard was phase==CLAIMED
    # — a claim created seconds ago, with a dispatch actively in flight,
    # passed that check just as readily as a genuinely stuck one. Require
    # the same staleness bar `list` uses before a transition is even
    # previewed, unless the operator explicitly overrides with --force.
    age_seconds = _age_seconds(claim.get("@timestamp"))
    if age_seconds is None:
        print(f"Refusing: claimed timestamp {claim.get('@timestamp')!r} is unparseable — "
              f"cannot confirm this claim is actually stale. Nothing to do.", file=sys.stderr)
        return 1
    if age_seconds < args.max_age_min * 60 and not args.force:
        print(f"Refusing: this claim is only {_age_str(claim.get('@timestamp'))} old "
              f"(< {args.max_age_min:g}m) — it may still be in flight, not actually stuck. "
              f"Re-run with --force if you've confirmed out-of-band (SSH to the router, "
              f"#278's reconciliation log) that it's safe to transition anyway.",
              file=sys.stderr)
        return 1

    print(f"About to mark tenant={args.tenant!r} alert_id={args.alert_id!r} as "
          f"{args.outcome.upper()} (currently CLAIMED, claimed {_age_str(claim.get('@timestamp'))} ago "
          f"by {claim.get('approver')!r}).")
    if args.outcome == "released":
        print("  RELEASED means: the block did NOT land — a retried /approve may win this claim again.")
    else:
        print("  RESOLVED means: the block DID land — this claim can never be retried again.")
    print(f"  Recorded as: actor={args.actor!r}, reason={args.reason!r}")

    if not args.yes:
        print("\nRe-run with --yes to apply this transition. No changes made (dry run).")
        return 0

    seq_no, primary_term = claim.get("_seq_no"), claim.get("_primary_term")
    if seq_no is None or primary_term is None:
        # security-auditor LOW: get_claim() should always carry both from a
        # real ES response — but if it somehow didn't, silently falling
        # through to an unconditional write would drop the read-then-write
        # race protection exactly when this tool can't prove it isn't
        # racing something. Refuse rather than write blind.
        print("Refusing: could not read this claim's version metadata "
              "(_seq_no/_primary_term) — cannot safely guard against a "
              "concurrent modification. Re-run 'show' and try again.", file=sys.stderr)
        return 1

    transition = checkpoints.release_claim if args.outcome == "released" else checkpoints.resolve_claim
    ok = transition(args.tenant, args.alert_id, actor=args.actor, reason=args.reason,
                    if_seq_no=seq_no, if_primary_term=primary_term)
    if ok:
        print(f"Done — {args.alert_id} is now {args.outcome.upper()}.")
        return 0
    print("Transition call did not confirm success — someone may have changed this claim "
          "concurrently (or the write was otherwise rejected). Re-run 'show' to check the "
          "claim's current state before retrying.", file=sys.stderr)
    return 1


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List claims stuck in CLAIMED")
    p_list.add_argument("--tenant", help="Restrict to one tenant (default: all)")
    p_list.add_argument("--max-age-min", type=_positive_float, default=DEFAULT_MAX_AGE_MIN,
                        help=f"Only show claims older than this many minutes "
                             f"(default {DEFAULT_MAX_AGE_MIN:g}, reading SLO_STUCK_CLAIM_MAX_MIN "
                             f"the same way slo_metrics.metric_stuck_approval_claims() does)")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Show one claim's current state")
    p_show.add_argument("tenant")
    p_show.add_argument("alert_id")
    p_show.set_defaults(func=cmd_show)

    p_resolve = sub.add_parser("resolve", help="Transition a stuck claim to RELEASED or RESOLVED")
    p_resolve.add_argument("tenant")
    p_resolve.add_argument("alert_id")
    p_resolve.add_argument("--outcome", choices=["released", "resolved"], required=True,
                           help="released = did NOT land, safe to retry. resolved = DID land, done.")
    p_resolve.add_argument("--actor", required=True,
                           help="Who is making this call (name/handle) — recorded on the claim "
                                "doc as resolution_actor_claimed (a label; the security-relevant "
                                "resolved_by field binds to the authenticating ES credential and "
                                "OS user/host, not to this flag, since a self-asserted name alone "
                                "would be forgeable by anyone holding the credential)")
    p_resolve.add_argument("--reason", required=True, type=_bounded_reason,
                           help="Why this claim is being transitioned, e.g. how you confirmed "
                                "the outcome out-of-band — recorded as resolution_reason "
                                "(max 1024 chars)")
    p_resolve.add_argument("--max-age-min", type=_positive_float, default=DEFAULT_MAX_AGE_MIN,
                           help=f"Refuse to transition a claim younger than this (default "
                                f"{DEFAULT_MAX_AGE_MIN:g}, same as 'list' — it may still be "
                                f"in flight below this age). See --force.")
    p_resolve.add_argument("--force", action="store_true",
                           help="Override the --max-age-min staleness check")
    p_resolve.add_argument("--yes", action="store_true",
                           help="Actually apply the transition (omit for a dry run)")
    p_resolve.set_defaults(func=cmd_resolve)

    args = parser.parse_args()
    try:
        sys.exit(args.func(args))
    except ValueError as e:
        # checkpoints.py's _validate_tenant_id/_transition_claim raise
        # ValueError on a malformed tenant or a half-set seq_no pair
        # (code-reviewer: this tool is for incident-response operators
        # under time pressure — a raw Python traceback from a fat-fingered
        # argument is a real usability gap, not just cosmetic).
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.HTTPError as e:
        # security-auditor MEDIUM: an ES rejection (e.g. a claim-attribution
        # write against an index whose mapping wasn't migrated — see
        # apply-templates.sh's #276 step) must surface as an actionable
        # message, not a raw traceback, from the one recovery tool
        # operators reach for when something is already broken.
        print(f"Error: Elasticsearch rejected the request: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
