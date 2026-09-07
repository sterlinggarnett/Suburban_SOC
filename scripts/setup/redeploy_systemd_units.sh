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
# slo-metrics.service and stack-health.service (#555) are Type=oneshot, triggered by
# their timers — no restart needed, they pick up the new unit definition on their next
# run after `daemon-reload`. This script runs slo-metrics once immediately to verify.
#
# stack-health.timer may not be installed yet on a given host (#555 shipped it new).
# This script ENABLES it if it is not already enabled, but deliberately does not run
# the service: stack_health.sh needs SOC_HEALTH_PASSWORD provisioned and the CA pin
# seeded first — see the install sequence in docs/SOP-005-reliability.md, which must be
# followed once before this script is useful for that unit.
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
sudo systemd-analyze security --no-pager stack-health.service || true
sudo systemd-analyze security --no-pager zeek-host-capture.service || true
sudo systemd-analyze security --no-pager suricata-host-capture.service || true

echo
echo "==> Installing updated unit files"
sudo cp configs/systemd/slo-metrics.service /etc/systemd/system/slo-metrics.service
sudo cp configs/systemd/stack-health.service /etc/systemd/system/stack-health.service
sudo cp configs/systemd/stack-health.timer /etc/systemd/system/stack-health.timer
sudo cp configs/systemd/zeek-host-capture.service /etc/systemd/system/zeek-host-capture.service
sudo cp configs/systemd/suricata-host-capture.service /etc/systemd/system/suricata-host-capture.service
# #554: the OnFailure= alert dispatcher slo-metrics.service and
# zeek-host-capture.service now point at. Instantiated on demand by systemd --
# nothing to enable/start here, just needs to exist before daemon-reload.
sudo cp configs/systemd/soc-alert-on-failure@.service /etc/systemd/system/soc-alert-on-failure@.service
# #549: output-derived liveness supervisor for zeek-host-capture.service.
sudo cp configs/systemd/zeek-capture-liveness.service /etc/systemd/system/zeek-capture-liveness.service
sudo cp configs/systemd/zeek-capture-liveness.timer /etc/systemd/system/zeek-capture-liveness.timer
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
echo "==> Enabling stack-health.timer if it is not already enabled (#555)"
if [[ "$(systemctl is-enabled stack-health.timer 2>/dev/null || true)" == "enabled" ]]; then
  echo "    already enabled — nothing to do"
else
  echo "    NOT enabled. Enable it only AFTER the one-time install sequence in"
  echo "    docs/SOP-005-reliability.md (provision SOC_HEALTH_PASSWORD, seed the CA pin):"
  echo "      sudo systemctl enable --now stack-health.timer"
fi

echo
echo "==> Enabling zeek-capture-liveness.timer if it is not already enabled (#549)"
if [[ "$(systemctl is-enabled zeek-capture-liveness.timer 2>/dev/null || true)" == "enabled" ]]; then
  echo "    already enabled — nothing to do"
else
  echo "    NOT enabled — no credential/CA prerequisite (unlike stack-health.timer, this"
  echo "    unit talks only to systemctl and, optionally, ntfy):"
  echo "      sudo systemctl enable --now zeek-capture-liveness.timer"
fi

echo
echo "==> After scores"
sudo systemd-analyze security --no-pager slo-metrics.service || true
sudo systemd-analyze security --no-pager stack-health.service || true
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
echo "  4a. (#554) Confirm the failure-alert dispatcher is reachable without waiting"
echo "      for a real failure: sudo systemctl start soc-alert-on-failure@test.service"
echo "      then journalctl -u 'soc-alert-on-failure@*' -n 10 --no-pager. If"
echo "      NTFY_TOPIC is set in scripts/setup/.env you should also see a push"
echo "      arrive; if it's unset, expect the 'cannot deliver alert' stderr line"
echo "      instead — see docs/SOP-005-reliability.md for provisioning it."
echo "  5. systemd-analyze security scores above should be meaningfully lower"
echo "     than baseline (slo-metrics: was 9.2 UNSAFE; zeek-host-capture: was 9.6"
echo "     UNSAFE — zeek-host-capture will NOT reach <=6.0, see issue #182)."
echo "     Recorded for #558, measured with 'systemd-analyze security --offline=true'"
echo "     against the repo unit files (this host had no live systemd copy of the"
echo "     new definition at the time):"
echo "       slo-metrics.service       3.8 OK  ->  1.6 OK   (this change)"
echo "       intel-refresh.service     1.6 OK              (unchanged, the source)"
echo "       checkpoints-compact       1.6 OK              (unchanged)"
echo "       threat-intel-compact      1.6 OK              (unchanged)"
echo "       stack-health.service      1.6 OK              (#555, born at parity)"
echo "     A LIVE score from the command above may differ slightly from the offline"
echo "     one; if it does, the live number is the one to trust and record."
echo "     suricata-host-capture has no established baseline yet (#443's own"
echo "     unit deliberately skips untested sandboxing directives — see its"
echo "     header) — record its score here on first real deploy."
