#!/usr/bin/env bash
# =============================================================================
# redeploy_systemd_units.sh — apply updated configs/systemd/*.service files to
# the live, installed units on the SOC host (audit #167).
#
# Repo template changes to configs/systemd/*.service never affect the actually
# running services until this (or the equivalent manual steps) is run — see
# each unit's own "Install:" header. Requires sudo.
#
# zeek-host-capture.service and suricata-host-capture.service (#443) are both
# long-running capture processes; restarting either briefly interrupts live
# packet capture, so this script asks before doing so, once per unit.
# slo-metrics.service is Type=oneshot, triggered by slo-metrics.timer — no
# restart needed, it picks up the new unit definition on its next run after
# `daemon-reload`. This script runs it once immediately to verify.
#
# The slo_metrics ES role + user (audit #167) are a separate, already-applied
# change on the live cluster — this script only touches systemd unit files.
#
# Usage:
#   git pull origin main   # make sure configs/systemd/*.service is current
#   bash scripts/setup/redeploy_systemd_units.sh
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"

echo "==> Before scores (for comparison)"
sudo systemd-analyze security --no-pager slo-metrics.service || true
sudo systemd-analyze security --no-pager zeek-host-capture.service || true
sudo systemd-analyze security --no-pager suricata-host-capture.service || true

echo
echo "==> Installing updated unit files"
sudo cp configs/systemd/slo-metrics.service /etc/systemd/system/slo-metrics.service
sudo cp configs/systemd/zeek-host-capture.service /etc/systemd/system/zeek-host-capture.service
sudo cp configs/systemd/suricata-host-capture.service /etc/systemd/system/suricata-host-capture.service
sudo systemctl daemon-reload

echo
echo "==> Restarting zeek-host-capture.service (brief capture interruption)"
read -rp "Proceed with restart now? [y/N] " ans
if [[ "${ans,,}" == "y" ]]; then
  sudo systemctl restart zeek-host-capture.service
  sleep 2
  sudo systemctl status zeek-host-capture.service --no-pager -l | head -15
else
  echo "Skipped. Run manually when ready: sudo systemctl restart zeek-host-capture.service"
fi

echo
echo "==> Restarting suricata-host-capture.service (#443, brief capture interruption)"
read -rp "Proceed with restart now? [y/N] " ans
if [[ "${ans,,}" == "y" ]]; then
  sudo systemctl restart suricata-host-capture.service
  sleep 2
  sudo systemctl status suricata-host-capture.service --no-pager -l | head -15
else
  echo "Skipped. Run manually when ready: sudo systemctl restart suricata-host-capture.service"
fi

echo
echo "==> Running slo-metrics.service once now (Type=oneshot; picks up the new"
echo "    unit + slo_metrics credentials without needing a restart — no"
echo "    long-running process to interrupt)"
sudo systemctl start slo-metrics.service
sleep 2
sudo journalctl -u slo-metrics -n 30 --no-pager

echo
echo "==> After scores"
sudo systemd-analyze security --no-pager slo-metrics.service || true
sudo systemd-analyze security --no-pager zeek-host-capture.service || true
sudo systemd-analyze security --no-pager suricata-host-capture.service || true

echo
echo "==> Verification checklist:"
echo "  1. journalctl output above shows slo_metrics (not elastic) auth succeeding"
echo "     and SLO metrics indexed (breach or ok, but no 401/403/exit-3 error)."
echo "  2. tail -f /storage/PCAP/zeek_logs/conn.log (or similar) to confirm capture"
echo "     resumed after the zeek-host-capture restart, if you did it."
echo "  3. docker logs zeek-host-capture --tail 30  — no permission errors."
echo "  4. tail -f /storage/PCAP/suricata/eve.json to confirm the Suricata sensor"
echo "     (#443) started and is writing, if you restarted it — journalctl -u"
echo "     suricata-host-capture -n 30 --no-pager for its own startup errors."
echo "  5. systemd-analyze security scores above should be meaningfully lower"
echo "     than baseline (slo-metrics: was 9.2 UNSAFE; zeek-host-capture: was 9.6"
echo "     UNSAFE — zeek-host-capture will NOT reach <=6.0, see issue #182)."
echo "     suricata-host-capture has no established baseline yet (#443's own"
echo "     unit deliberately skips untested sandboxing directives — see its"
echo "     header) — record its score here on first real deploy."
