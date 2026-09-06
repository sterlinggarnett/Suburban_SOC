#!/usr/bin/env bash
# Suburban-SOC — persist the fingerprint-verified Elasticsearch CA under a
# unit's StateDirectory= so a run whose `docker cp` extraction could not
# happen still has a usable trust anchor (#550).
#
# WHY THIS EXISTS
#
# slo-metrics.service pulls the stack CA out of the `elasticsearch` container
# on every run, because under Docker Desktop/WSL that cert lives only inside a
# docker volume with no stable host path. `/usr/bin/docker` there is a symlink
# into the docker-desktop WSL distro and DANGLES whenever Docker Desktop is
# stopped, so that extraction step fails at the systemd exec layer (203/EXEC).
# #550 makes the step "-"-prefixed so the run survives — but RuntimeDirectory=
# is torn down between every Type=oneshot run, so surviving is not enough on
# its own: ES_CA then points at a file that does not exist, and `requests`
# reports a TLS **CA bundle** error for every metric. That misdirects the
# operator, because the actual fact in that situation is "Elasticsearch is
# down" (the ES container shares the Docker daemon that just went away).
#
# Caching a verified copy under StateDirectory= (which, unlike
# RuntimeDirectory=, survives across runs — the same reason the TOFU pin file
# lives there) makes the degraded run report the true error instead.
#
# TRUST MODEL
#
# Both verbs check the cert's SHA-256 fingerprint against the TOFU pin
# themselves. They do NOT rely on the caller ordering them correctly around
# verify_ca_fingerprint.sh, because "correct only if the unit file stays in
# this order" is not a property worth betting a trust anchor on
# (security-auditor, MEDIUM 1). What each check buys:
#
#   restore  a cached cert that no longer matches the pin is DISCARDED rather
#            than installed. Without this, a stale cache turns every
#            Docker-down run into: restore installs it -> verify_ca_fingerprint
#            .sh deletes it and exits 1 -> ExecStartPre failure -> unit dead
#            before ExecStart. That is exactly the hard-fail loop #550 exists
#            to remove, and it would be permanent, because
#            verify_ca_fingerprint.sh only ever deletes the RUNTIME copy — the
#            cache is not in its argv. The likeliest way in is not an attacker
#            but an operator who re-pins a rotated CA by editing
#            ca_fingerprint.sha256 instead of deleting it.
#   save     closes the window between verify_ca_fingerprint.sh accepting the
#            runtime cert and this script copying it, during which anything
#            with the service UID could swap the file and poison the cache
#            permanently.
#
# One further hazard `restore` has to guard: an operator re-arms TOFU for a
# deliberate cert rotation by DELETING the pin file. If the docker extraction
# also happened to be unavailable in that window, restoring the stale cached
# cert would let it be re-pinned as the new "trusted" value — quietly undoing
# the rotation. `restore` therefore refuses to act when the pin is absent: a
# re-arm window must be served by a real extraction or not at all.
#
# EXIT STATUS — always 0 for anything short of a usage error
#
# Both modes are best-effort by design. This script exists to make a degraded
# run more legible; it must never be the reason a run dies. Killing the
# metrics lane because a cache copy could not be written would reintroduce the
# exact failure class #550 is about (an auxiliary dependency taking down the
# unit's primary purpose). Degraded paths log to stderr — which is the
# journal, for a systemd caller — and return 0.
#
# The usage-error status is 64 (sysexits EX_USAGE), deliberately NOT 2:
# slo-metrics.service carries `SuccessExitStatus=0 2`, and that directive was
# empirically confirmed on this host to apply to ExecStartPre CONTROL
# processes, not just the main process — a control process exiting 2 is
# reported as a successful start and ExecStart still runs. No script in this
# unit's start path may return a status the unit is configured to forgive
# (security-auditor, MEDIUM 2).
#
# Usage: es_ca_cache.sh <restore|save> <runtime ca path> <cache ca path> <pin path>
set -euo pipefail

MODE="${1:?Usage: $0 <restore|save> <runtime ca path> <cache ca path> <pin path>}"
RUNTIME_CA="${2:?Usage: $0 <restore|save> <runtime ca path> <cache ca path> <pin path>}"
CACHE_CA="${3:?Usage: $0 <restore|save> <runtime ca path> <cache ca path> <pin path>}"
PIN_PATH="${4:?Usage: $0 <restore|save> <runtime ca path> <cache ca path> <pin path>}"

# A SIGTERM between mktemp and mv would otherwise strand a temp file in
# StateDirectory= forever (RuntimeDirectory= self-cleans; /var/lib does not),
# leaving "which file is the real trust anchor?" ambiguous during triage.
# That signal is reachable: the caller bounds its own start job with
# TimeoutStartSec=.
TMP_FILE=""
# shellcheck disable=SC2317  # invoked via the trap below, not by a direct call
cleanup() {
  if [ -n "${TMP_FILE:-}" ]; then
    rm -f "$TMP_FILE"
  fi
  return 0
}
trap cleanup EXIT INT TERM

# `|| true` is load-bearing under `set -euo pipefail`: without it a malformed
# cert makes openssl fail, pipefail propagates that, and errexit aborts the
# script before the `[ -z ]` branch that is supposed to handle exactly this
# case can run. (The same latent bug exists upstream in
# verify_ca_fingerprint.sh and is fixed there in this change.)
fingerprint_of() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true
}

# 0600 on both the temp file and the installed copy: this is a trust anchor
# sitting in a directory the service user owns. `install -m` sets the mode
# explicitly rather than leaning on the caller's UMask=, so a future change to
# that unit setting cannot silently widen it (same reasoning as the unit's own
# RuntimeDirectoryMode=/StateDirectoryMode=0700). mktemp targets the
# DESTINATION directory so the `mv` is a same-filesystem rename(2), which is
# what makes the swap atomic — a reader never observes a half-written cert.
install_atomically() {
  local src="$1" dest="$2"
  TMP_FILE="$(mktemp "${dest}.XXXXXX" 2>/dev/null)" || { TMP_FILE=""; return 1; }
  if install -m 0600 "$src" "$TMP_FILE" && mv -f "$TMP_FILE" "$dest"; then
    TMP_FILE=""
    return 0
  fi
  rm -f "$TMP_FILE"
  TMP_FILE=""
  return 1
}

case "$MODE" in
  restore)
    if [ -s "$RUNTIME_CA" ]; then
      # A live extraction already succeeded this run; it always wins.
      exit 0
    fi
    if [ -L "$CACHE_CA" ]; then
      echo "[WARN] $CACHE_CA is a symlink -- refusing to restore through it" >&2
      exit 0
    fi
    if [ ! -s "$CACHE_CA" ]; then
      echo "[INFO] no cached ES CA at $CACHE_CA and none extracted this run -- nothing to restore" >&2
      exit 0
    fi
    if [ ! -s "$PIN_PATH" ]; then
      echo "[WARN] cached ES CA present at $CACHE_CA but the TOFU pin $PIN_PATH is absent -- refusing to restore, because re-pinning a cached cert during a rotation re-arm would silently undo the rotation. Start the Docker engine so the CA can be re-extracted for real." >&2
      exit 0
    fi

    cached_fp="$(fingerprint_of "$CACHE_CA")"
    pinned="$(cat "$PIN_PATH")"
    if [ -z "$cached_fp" ]; then
      echo "[WARN] could not read a SHA-256 fingerprint from the cached ES CA $CACHE_CA -- discarding it" >&2
      rm -f "$CACHE_CA"
      exit 0
    fi
    if [ "$cached_fp" != "$pinned" ]; then
      # Self-heal rather than hand the next step a cert it is guaranteed to
      # reject: an undiscarded stale cache makes every later Docker-down run
      # fail at ExecStartPre, permanently and with no alert.
      echo "[WARN] cached ES CA $CACHE_CA no longer matches the pin in $PIN_PATH (cached $cached_fp, pinned $pinned) -- discarding it. It will be re-cached from the container on the next run that can reach the Docker engine." >&2
      rm -f "$CACHE_CA"
      exit 0
    fi
    if ! openssl x509 -in "$CACHE_CA" -noout -checkend 0 >/dev/null 2>&1; then
      # Deliberately no hard max-age: refusing a merely OLD anchor would
      # resurrect the misleading CA-bundle error #550 exists to eliminate.
      # An EXPIRED one cannot complete a handshake anyway.
      echo "[WARN] cached ES CA $CACHE_CA has expired -- refusing to restore it" >&2
      exit 0
    fi

    if install_atomically "$CACHE_CA" "$RUNTIME_CA"; then
      age_days="unknown"
      cached_epoch="$(stat -c %Y "$CACHE_CA" 2>/dev/null || true)"
      if [ -n "$cached_epoch" ]; then
        age_days="$(( ( $(date +%s) - cached_epoch ) / 86400 ))"
      fi
      echo "[INFO] ES CA could not be extracted this run (Docker engine unavailable?) -- reinstated the cached copy from $CACHE_CA, cached ${age_days} day(s) ago; it matches $PIN_PATH and is checked again below" >&2
    else
      echo "[WARN] failed to reinstate the cached ES CA from $CACHE_CA to $RUNTIME_CA -- continuing without it" >&2
    fi
    ;;
  save)
    # Sweep any temp file a previous run was killed mid-write (see the trap
    # above -- this catches a SIGKILL, which no trap can).
    for stale in "${CACHE_CA}".??????; do
      if [ -e "$stale" ]; then
        rm -f "$stale"
      fi
    done

    if [ ! -s "$RUNTIME_CA" ]; then
      # Nothing verified to cache. Not an error: this is the ordinary
      # Docker-unavailable run, already reported by `restore` above.
      exit 0
    fi
    if [ ! -s "$PIN_PATH" ]; then
      echo "[WARN] refusing to cache $RUNTIME_CA -- no TOFU pin at $PIN_PATH, so it has not been verified against anything" >&2
      exit 0
    fi

    runtime_fp="$(fingerprint_of "$RUNTIME_CA")"
    pinned="$(cat "$PIN_PATH")"
    if [ -z "$runtime_fp" ] || [ "$runtime_fp" != "$pinned" ]; then
      echo "[WARN] refusing to cache $RUNTIME_CA -- its fingerprint (${runtime_fp:-unreadable}) does not match the pin in $PIN_PATH ($pinned)" >&2
      exit 0
    fi

    if cmp -s "$RUNTIME_CA" "$CACHE_CA" 2>/dev/null; then
      exit 0
    fi
    if install_atomically "$RUNTIME_CA" "$CACHE_CA"; then
      echo "[INFO] cached the verified ES CA to $CACHE_CA for use when the Docker engine is unavailable" >&2
    else
      echo "[WARN] could not write the ES CA cache at $CACHE_CA -- this run is unaffected, but a later run with no Docker engine will have no CA to fall back on" >&2
    fi
    ;;
  *)
    echo "[FATAL] unknown mode '$MODE' (expected 'restore' or 'save')" >&2
    exit 64
    ;;
esac

exit 0
