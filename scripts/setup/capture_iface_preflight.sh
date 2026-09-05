#!/usr/bin/env bash
# Suburban-SOC — capture-interface preflight for zeek-host-capture.service.
#
# Exits 0 if <interface> is usable for live capture, or 78 (EX_CONFIG from
# sysexits.h) with an operator diagnostic if it is not.
#
# WHY THIS EXISTS
# ---------------
# 2026-09-05: /etc/default/zeek-host-capture still pinned CAPTURE_IFACE=eth6
# after WSL2 renumbered the host NICs across a reboot. eth6 came back DOWN
# (the live LAN interface was eth4, holding the default route), so every
# start died instantly with "tcpdump: eth6: That device is not up" and the
# Zeek lane wrote nothing for five days. Two effects kept that invisible:
#
#   1. Restart=always + StartLimitIntervalSec=0 — both deliberate, so the
#      unit survives the Docker Desktop engine's slow start after boot —
#      turned a PERMANENT config error into an unbounded crash loop, 123
#      restarts deep, with `systemctl is-active` reporting `active`
#      throughout (systemd re-enters the active state between failures).
#   2. Then it WEDGED: the dead tcpdump leg left `docker run` attached to a
#      container whose Zeek had already exited, and that client never
#      returns, so systemd parked the unit at `active (running)`
#      indefinitely while capturing nothing.
#
# Because StartLimitIntervalSec=0 must stay, the fix cannot be "let the rate
# limiter fail the unit" — that would reintroduce the boot race. Instead the
# two failure classes are separated by EXIT CODE: a transient failure
# (Docker not up yet) exits non-zero and keeps its unbounded retry, while an
# unusable interface exits 78, which the unit's RestartPreventExitStatus=78
# turns into a terminal `failed` state where `systemctl is-active` finally
# reports the truth.
#
# Kept in its own file, rather than inline in host_capture.sh, for the same
# reason #320 moved the capture pipeline out of the unit's ExecStart= into a
# script: it makes the logic runnable — and therefore testable — in
# isolation. Testing it through host_capture.sh is not safe, because past
# the preflight that script invokes `docker run --name zeek-host-capture`
# and would race the real service. See
# tests/pipeline/test_zeek_capture_iface_validation.py.
#
# Usage: capture_iface_preflight.sh <interface>

set -euo pipefail

# sysexits.h EX_CONFIG. Reserved to THIS script: host_capture.sh remaps a
# downstream 78 (from tcpdump, docker, or the Zeek container, whose exit
# status `docker run` passes through verbatim) to an ordinary failure, so
# nothing but a genuine config error can trip RestartPreventExitStatus.
EX_CONFIG=78

IFACE_WAIT_DEFAULT=30
# Upper bound on the grace period. Without it, SOC_IFACE_WAIT_SECS=999999999
# in the env file would hold the unit at `active (running)` for ~31 years —
# the original invisible outage restored by a one-line edit, with no crash
# loop at all.
IFACE_WAIT_MAX=300

IFACE="${1-}"

warn() { echo "WARN: $*" >&2; }

# SOC_IFACE_WAIT_SECS is NOT a trusted knob: the unit loads
# EnvironmentFile=-/etc/default/zeek-host-capture, which injects arbitrary
# variables, so anyone who can write that file can set it.
#
# A malformed value deliberately does NOT exit 78. Making it terminal would
# hand that same writer a one-character permanent sensor kill — strictly
# worse than the bug this script fixes. It loses its grace period instead
# (check once, fail fast), so garbage can never buy silence, and a healthy
# interface is never parked over a typo in an unrelated tuning knob.
#
# Note the comparison below uses `[ ... -gt ... ]`, never `[[ ... ]]` or
# `(( ... ))`. `[` parses operands with legal_number() and errors on
# garbage; the other two ARITHMETIC-EVALUATE their operands, under which an
# env-file value like `a[$(id)]` would execute as root. A test pins this.
_raw_wait="${SOC_IFACE_WAIT_SECS-}"
if [ -z "$_raw_wait" ]; then
    IFACE_WAIT_SECS="$IFACE_WAIT_DEFAULT"
else
    case "$_raw_wait" in
        *[!0-9]*)
            warn "SOC_IFACE_WAIT_SECS=\"${_raw_wait}\" is not a whole number of" \
                 "seconds — invalid, ignoring it and using no grace period."
            IFACE_WAIT_SECS=0
            ;;
        *)
            IFACE_WAIT_SECS="$_raw_wait"
            ;;
    esac
fi
if [ "$IFACE_WAIT_SECS" -gt "$IFACE_WAIT_MAX" ]; then
    warn "SOC_IFACE_WAIT_SECS=${IFACE_WAIT_SECS} exceeds the maximum grace" \
         "period — clamped to ${IFACE_WAIT_MAX}s so it cannot hold this unit" \
         "at 'active (running)' indefinitely."
    IFACE_WAIT_SECS="$IFACE_WAIT_MAX"
fi

# Extract the kernel's flag field — the FIRST <...> group on the line.
#
# Anchoring to the first group is load-bearing, not style. `ip -o link show`
# inlines the interface ALIAS onto the same line, so a greedy `.*<` binds to
# the LAST `<` and an alias like `rack<A,UP>` makes a genuinely DOWN
# interface parse as up — silently defeating this entire script (no exit 78,
# no diagnostic, just a false pass into a dead capture). Bracketed
# asset-tag/rack aliases are a real convention, and the kernel's
# dev_valid_name() permits `<` and `>` in an interface NAME too.
iface_flags() {
    ip -o link show dev "$1" 2>/dev/null |
        sed -n 's/^[^<]*<\([^>]*\)>.*/\1/p'
}

# Test the administrative UP flag rather than `ip -br`'s operstate column:
# operstate reads "unknown" for several perfectly usable device types,
# whereas UP means administratively up in every case.
#
# The ",${flags}," padding with a ",UP," pattern is what distinguishes UP
# from LOWER_UP — an unpadded "UP" substring would match inside "LOWER_UP".
iface_is_up() {
    local flags
    flags="$(iface_flags "$1")" || flags=""
    [ -n "$flags" ] || return 1
    case ",${flags}," in *,UP,*) return 0 ;; esac
    return 1
}

# Carrier is deliberately NOT part of the up/down decision — see the warning
# emitted below for the reasoning.
iface_has_carrier() {
    local flags
    flags="$(iface_flags "$1")" || flags=""
    case ",${flags}," in *,NO-CARRIER,*) return 1 ;; esac
    return 0
}

# Everything here is best-effort reporting. It runs inside a function called
# with `|| true` because a bare `var="$(cmd | ...)"` assignment takes the
# substitution's exit status, and under `set -euo pipefail` a non-zero one
# would exit the script IMMEDIATELY with that status — before `exit
# "$EX_CONFIG"` below is ever reached. A missing or erroring `ip` would then
# make RestartPreventExitStatus=78 inert and restore the unbounded crash
# loop. shellcheck does not catch that: SC2155 fires only for
# local/export/declare.
emit_diagnosis() {
    if [ -z "$IFACE" ]; then
        echo "FATAL: no capture interface is configured (CAPTURE_IFACE is empty)."
    else
        echo "FATAL: capture interface \"$IFACE\" is not up (waited ${IFACE_WAIT_SECS}s)."
    fi
    echo "  Set a live interface in /etc/default/zeek-host-capture, then restart this unit:"
    echo "    echo 'CAPTURE_IFACE=<iface>' | sudo tee /etc/default/zeek-host-capture"
    echo "    sudo systemctl restart zeek-host-capture"
    echo "  Candidate interfaces currently up on this host:"
    # Print only the device name (field 2, before any '@peer' suffix).
    # Deliberately narrow: `ip -o link show up` also carries link/ether, so
    # widening this to `print $0` would start leaking MAC addresses into the
    # journal.
    ip -o link show up 2>/dev/null |
        awk -F': ' '{split($2, a, "@"); print "    " a[1]}'
    local default_dev
    default_dev="$(ip route show default 2>/dev/null |
                   awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' |
                   head -n1)" || default_dev=""
    if [ -n "$default_dev" ]; then
        echo "  The default route currently uses: ${default_dev}"
    fi
}

fail_config() {
    emit_diagnosis >&2 || true
    exit "$EX_CONFIG"
}

# An empty pin (env-file typo, truncation, or a deliberate one-character
# sabotage) must reach the SAME terminal exit as any other unusable value —
# a bare `${1:?}` would exit 1 and crash-loop forever behind `active`.
[ -n "$IFACE" ] || fail_config

waited=0
while ! iface_is_up "$IFACE"; do
    if [ "$waited" -ge "$IFACE_WAIT_SECS" ]; then
        fail_config
    fi
    sleep 1
    waited=$((waited + 1))
done

# An interface can be administratively UP with no carrier — unplugged cable,
# downed AP — and will then capture exactly zero packets: the same silent
# failure shape this script exists to surface, one layer down. It is NOT
# treated as terminal, for two reasons: carrier can drop at any moment AFTER
# this check passes, so no start-time test can own it (sustained
# zero-traffic is the capture-loss monitor's job), and making it terminal
# would risk permanently parking device types that never report carrier.
# So: proceed, but say so loudly rather than leaving it to be inferred.
if ! iface_has_carrier "$IFACE"; then
    warn "capture interface \"$IFACE\" is up but reports NO-CARRIER — it will" \
         "capture zero packets until the link comes up. Proceeding; sustained" \
         "zero-traffic is covered by capture-loss monitoring, not by this check."
fi
