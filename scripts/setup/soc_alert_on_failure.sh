#!/usr/bin/env bash
# =============================================================================
# soc_alert_on_failure.sh — OnFailure= alert dispatcher for the SOC self-health
# lane (#554).
#
# Wired via `OnFailure=soc-alert-on-failure@%n.service` on slo-metrics.service
# and zeek-host-capture.service (see
# configs/systemd/soc-alert-on-failure@.service) so a unit that fails before
# its own body ever runs — e.g. an ExecStartPre credential check or CA-pin
# mismatch — still produces something off the host, not just a journal line
# nobody is watching.
#
# Deliberately depends on neither Docker nor Elasticsearch: those are exactly
# what slo-metrics.service and zeek-host-capture.service report on, and a
# delivery path sharing their dependency would go dark in the same outage it
# exists to report.
#
# Usage: soc_alert_on_failure.sh <failed-unit-name>
#   (systemd supplies this via the "@%n.service" instance name on the
#   OnFailure= directive, which the template unit passes through as %i.)
# =============================================================================
set -uo pipefail

FAILED_UNIT="${1:?usage: soc_alert_on_failure.sh <failed-unit-name>}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$HERE/.env" ]] && { set -a; . "$HERE/.env"; set +a; }
NTFY_TOPIC="${NTFY_TOPIC:-}"

if [[ -z "$NTFY_TOPIC" ]]; then
  # #554: an unset sink must be visible, not a silently-successful no-op. Exit 0
  # rather than failing this unit itself, though — slo_metrics.py's own startup
  # warning (also #554) already flags the missing topic on every 15-minute run;
  # a second alarm for the same root cause from the dispatcher that can't reach
  # ntfy in the first place would just be noise layered on the same gap.
  echo "soc_alert_on_failure: NTFY_TOPIC is unset -- cannot deliver alert for ${FAILED_UNIT}" >&2
  exit 0
fi

# Same call shape as stack_health.sh's own ntfy push: -s/-m bound the call, the
# push itself is best-effort (a dead network path here must not turn one failed
# unit into two).
curl -s -m 10 -o /dev/null "https://ntfy.sh/${NTFY_TOPIC}" \
  -H "Title: Suburban-SOC unit failure" -H "Priority: high" -H "Tags: rotating_light" \
  -d "SOC unit failed: ${FAILED_UNIT} -- journalctl -u ${FAILED_UNIT}" 2>/dev/null || true
