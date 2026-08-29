# shellcheck shell=bash
# =============================================================================
# intel_dir_perms.sh — shared root-owner + tjlam-group-sticky-bit permission
# fix for /storage/PCAP/intel (#321).
#
# configs/systemd/zeek-host-capture.service's own crash-loop fix (#209/#222)
# makes root the PERMANENT owner of this directory, with tjlam getting
# group-write + sticky-bit access (chown -h root:tjlam ... && chmod 1775 ...)
# so intel-refresh.service's live sync keeps working across every restart,
# not just the first — see that unit's own comments for the full history.
# Three sibling manual-capture helpers (stream_capture.sh, zeek_connect_host.sh,
# zeek_run_pcap.sh) each independently `sudo mkdir -p /storage/PCAP/intel`
# with no chown/chmod of their own — running any of them on a host where the
# directory doesn't exist yet silently reintroduces the exact root:root 0755
# state the systemd unit's fix corrects, since they run under full root
# (sudo, real DAC_OVERRIDE) and would happily leave it there.
#
# Usage — source AFTER the caller has already mkdir'd the directory (this
# helper does not create it, only fix its ownership/mode):
#   source "<repo>/scripts/setup/lib/intel_dir_perms.sh"
#   harden_intel_dir_perms /storage/PCAP/intel "${SOC_USER:-tjlam}"
# A broad early symlink sweep in the caller (before its own mkdir -p) is
# still worthwhile for a fast, clear failure — but is no longer the only
# thing standing between an attacker and a misapplied chmod: see the
# guard inside this function below (security-auditor review, #321 round 2).
# =============================================================================

# Idempotent: if already sourced in this shell, skip redefining the function.
[[ -n "${_INTEL_DIR_PERMS_LOADED:-}" ]] && return 0
_INTEL_DIR_PERMS_LOADED=1

# "-h" on chown: GNU chown dereferences a symlink argument by default — run
# against a symlinked path, it would retarget whatever the symlink points at
# instead. "-h" operates on the link itself, a no-op on a real directory but
# a real guard if this path were ever replaced by a symlink. chmod has NO
# "-h"/no-dereference equivalent on Linux (symlinks carry no permission bits
# of their own) — the same residual limitation configs/systemd/
# zeek-host-capture.service's own #321 fix documents and narrows there via a
# hard not-a-symlink guard immediately before its own equivalent chown+chmod
# ExecStartPre step.
#
# security-auditor review (round 2): the first version of this function
# relied on EACH CALLER to enforce that same precondition itself before
# calling in — but all 3 real callers only checked for a symlink well
# before their own `mkdir -p` (a much wider window than "immediately
# before"), leaving the exact race the systemd-unit fix narrows wide open
# here. The guard now lives IN the function, immediately before the
# chown/chmod it protects, so every caller gets it for free regardless of
# what its own earlier checks did or didn't cover.
harden_intel_dir_perms() {
  local dir="$1" group_user="$2"
  if [ ! -d "$dir" ] || [ -L "$dir" ]; then
    echo "[FATAL] ${dir} is missing or a symlink, refusing to chown/chmod a possibly-compromised path" >&2
    return 1
  fi
  # Chained via && (not run as two independent commands) so a failed chown
  # never leaves a root:root directory silently chmod'd to 1775 anyway.
  sudo chown -h "root:${group_user}" "$dir" && sudo chmod 1775 "$dir"
}
