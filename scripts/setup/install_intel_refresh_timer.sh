#!/usr/bin/env bash
# =============================================================================
# install_intel_refresh_timer.sh — first-time (and idempotent re-run) install
# of the threat-intel refresh systemd timer (#222).
#
# Replaces the old manual step of editing crontab by hand
# (configs/intel/intel-refresh.cron, removed):
#   crontab -l 2>/dev/null | cat - configs/intel/intel-refresh.cron | crontab -
#
# Requires sudo. Safe to re-run — `cp` + `daemon-reload` + `enable --now` are
# all idempotent, so running this again after a `git pull` that touched
# configs/systemd/intel-refresh.{service,timer} picks up the change (same
# role redeploy_systemd_units.sh plays for slo-metrics/zeek-host-capture).
#
# Usage:
#   git pull origin main   # make sure configs/systemd/intel-refresh.* is current
#   bash scripts/setup/install_intel_refresh_timer.sh
# =============================================================================
set -euo pipefail

# $HERE is scripts/setup — two levels under the repo root, not one (matches
# redeploy_systemd_units.sh's own $HERE/../.. in this same directory; this
# line originally had only one ".." and resolved REPO to scripts/, not the
# repo root, so every path below it 404'd).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"

echo "==> Installing intel-refresh unit files"
sudo cp configs/systemd/intel-refresh.service /etc/systemd/system/intel-refresh.service
sudo cp configs/systemd/intel-refresh.timer /etc/systemd/system/intel-refresh.timer
sudo systemctl daemon-reload

echo
echo "==> Enabling and starting the timer (6h cadence, first run ~5 min after boot)"
sudo systemctl enable --now intel-refresh.timer

echo
echo "==> Running intel-refresh.service once now to verify"
sudo systemctl start intel-refresh.service
sleep 2
sudo journalctl -u intel-refresh -n 30 --no-pager

echo
echo "==> Timer status"
sudo systemctl list-timers intel-refresh.timer --no-pager

echo
echo "==> Verification checklist:"
echo "  1. journalctl output above shows both feeds fetched (Feodo Tracker,"
echo "     Emerging Threats compromised-ips) and a heartbeat recorded — exit"
echo "     status 0 (ok) or 2 (a feed was stale, still a successful run) is"
echo "     fine; anything else needs investigating."
echo "  2. list-timers above shows intel-refresh.timer with a NEXT time ~6h out."
echo "  3. Kibana -> [SOC] Threat Intel Feed Health dashboard: Indicators in"
echo "     Feed / Live Indicators should reflect the new combined count from"
echo "     both feeds (roughly seed + Feodo + Emerging Threats, minus overlap)."
