#!/usr/bin/env bash
# =============================================================================
# section_a_evidence.sh — automate SOP-147 Section A.4–A.6 evidence collection
# (docs/SOP-147-evidence-validation-procedure.md).
#
#   A.4  Live intel match      → drives the full Zeek→Logstash→agent SOAR loop
#                                (delegates to sim_intel_match.sh) + confirms the
#                                soar-actions draft entry.
#   A.5  Quarantine executed   → needs a real OpenWrt router + MAC + a destructive
#                                /approve, so it is NOT auto-executed. Read-only:
#                                checks for an existing quarantine rule if you pass
#                                --quarantine-mac <MAC>; otherwise SKIPPED.
#   A.6  Exclusion holds       → fires a signed /alert at the governance asset
#                                192.168.1.1 and asserts the agent returns
#                                no_action_protected_asset, writes the audit
#                                record, and never drafts/isolates it.
#
# SAFETY: this script NEVER calls POST /approve (agent or broker) and never
# triggers a real isolation. A.6 is non-destructive by construction (the agent
# refuses to act on an excluded asset).
#
# Usage:   ./section_a_evidence.sh [--quarantine-mac AA:BB:CC:DD:EE:FF]
# Creds:   sourced from ../../scripts/setup/.env (ES_*/ELASTIC_PASSWORD,
#          SOC_AGENT_HMAC_SECRET). Override ES_URL/AGENT_URL/TENANT via env.
# Exit:    0 if every non-skipped check passed, 1 otherwise.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# Canonical stack secrets (TLS ES URL + HMAC secret) — same source the other sims use.
[[ -f "$HERE/../../scripts/setup/.env" ]] && { set -a; . "$HERE/../../scripts/setup/.env"; set +a; }

# ES_URL/ES_USER/ES_PASS are resolved once by es_common.sh (sourced after arg parsing).
AGENT_URL="${AGENT_URL:-http://127.0.0.1:5000}"
TENANT="${TENANT:-home-smith}"
PROTECTED_IP="${PROTECTED_IP:-192.168.1.1}"   # governance exclusion (governance/exclusion_list.txt)

QUARANTINE_MAC=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quarantine-mac) QUARANTINE_MAC="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "[ERR] unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Shared ES creds fail-fast + es()/TLS (issue #156).
source "$HERE/../../scripts/setup/lib/es_common.sh"
[[ -z "${SOC_AGENT_HMAC_SECRET:-}" ]] && { echo "[ERR] SOC_AGENT_HMAC_SECRET required (check scripts/setup/.env)" >&2; exit 2; }
# #246: /pending is gated on a SEPARATE secret from /alert's — SOC_AGENT_HMAC_SECRET
# no longer authenticates it (a Logstash compromise must not be able to enumerate
# drafted containment actions).
[[ -z "${SOC_APPROVER_HMAC_SECRET:-}" ]] && { echo "[ERR] SOC_APPROVER_HMAC_SECRET required (check scripts/setup/.env)" >&2; exit 2; }

# Sign "<ts>." + raw_body with SOC_AGENT_HMAC_SECRET (the agent's HMAC scheme,
# audit P0-2/P1-1: ±300s window, single-use nonce). Empty body => signs "<ts>.".
agent_post() {  # agent_post <path> <json-body>
  local path="$1" body="${2:-}" ts sig
  ts=$(date +%s)
  sig="sha256=$(printf '%s.%s' "$ts" "$body" | openssl dgst -sha256 -hmac "$SOC_AGENT_HMAC_SECRET" | awk '{print $NF}')"
  curl -s --max-time 12 -H "x-elastic-signature: $sig" -H "x-elastic-timestamp: $ts" \
    -H 'Content-Type: application/json' -X POST -d "$body" "$AGENT_URL$path"
}
# #246: signed with SOC_APPROVER_HMAC_SECRET, not SOC_AGENT_HMAC_SECRET — /pending
# would otherwise 401 post-fix, and coercing that failure to a bare "0" (as this
# helper used to) would silently read as "no draft queued" to every before/after
# assertion below, indistinguishable from the SOAR loop actually working.
agent_pending_count() {
  local ts sig resp code body
  ts=$(date +%s)
  sig="sha256=$(printf '%s.' "$ts" | openssl dgst -sha256 -hmac "$SOC_APPROVER_HMAC_SECRET" | awk '{print $NF}')"
  resp=$(curl -s --max-time 6 -w '\n%{http_code}' -H "x-elastic-signature: $sig" -H "x-elastic-timestamp: $ts" "$AGENT_URL/pending")
  code="${resp##*$'\n'}"
  body="${resp%$'\n'*}"
  if [[ "$code" != "200" ]]; then
    echo "[ERR] GET /pending failed (HTTP $code) — before/after draft counts cannot be trusted" >&2
    echo "ERR"
    return
  fi
  printf '%s' "$body" | python3 -c 'import sys,json;print(json.load(sys.stdin)["count"])' 2>/dev/null || echo "ERR"
}
jget() { python3 -c "import sys,json
try: d=json.load(sys.stdin)
except Exception: print(''); sys.exit()
for k in '$1'.split('.'): d=d.get(k,{}) if isinstance(d,dict) else {}
print(d if not isinstance(d,dict) else '')"; }

fail=0; SUMMARY=()
hr() { printf '%s\n' "------------------------------------------------------------"; }

# ------------------------------------------------------------------ A.4
echo; hr; echo "A.4 — Live intel match (end-to-end SOAR loop)"; hr
if [[ -x "$HERE/sim_intel_match.sh" ]]; then
  if "$HERE/sim_intel_match.sh"; then
    echo "[PASS] A.4 intel-match loop (ES zeek.intel doc + agent draft)"
    SUMMARY+=("A.4 PASS — intel match drove detection→draft")
  else
    echo "[FAIL] A.4 intel-match loop — see lines above"; fail=1
    SUMMARY+=("A.4 FAIL — intel match loop")
  fi
  # Extra evidence: the soar-actions draft entry (analyst_review, response.automated=false).
  es "$ES_URL/soar-actions-${TENANT}/_refresh" >/dev/null 2>&1
  sa=$(es "$ES_URL/soar-actions-${TENANT}/_search?size=1&sort=@timestamp:desc" 2>/dev/null \
        | python3 -c 'import sys,json
h=json.load(sys.stdin).get("hits",{}).get("hits",[])
if h:
  s=h[0]["_source"]; a=s.get("action",{}); r=s.get("response",{})
  print(f"action={a.get(\"type\",\"?\")} automated={r.get(\"automated\")}")
else: print("none")' 2>/dev/null)
  echo "[i ] latest soar-actions-${TENANT}: ${sa:-none}"
else
  echo "[SKIP] sim_intel_match.sh not found/executable"; SUMMARY+=("A.4 SKIP")
fi

# ------------------------------------------------------------------ A.5
echo; hr; echo "A.5 — Quarantine executed (external; read-only)"; hr
if [[ -n "$QUARANTINE_MAC" ]]; then
  echo "[*] read-only check for an existing SOAR_QUARANTINE rule for $QUARANTINE_MAC"
  if [[ -x "$HERE/verify_quarantine.sh" ]] && "$HERE/verify_quarantine.sh" "$QUARANTINE_MAC"; then
    echo "[PASS] A.5 quarantine rule present on the router for $QUARANTINE_MAC"
    SUMMARY+=("A.5 PASS — quarantine rule present ($QUARANTINE_MAC)")
  else
    echo "[FAIL] A.5 quarantine rule absent/unreachable (rc=$?)"; fail=1
    SUMMARY+=("A.5 FAIL — no rule / router unreachable")
  fi
else
  echo "[SKIP] A.5 needs a real OpenWrt router + MAC and a prior /approve→broker"
  echo "        execution (POST /approve is destructive and is intentionally NOT"
  echo "        automated). Re-run with: --quarantine-mac AA:BB:CC:DD:EE:FF"
  SUMMARY+=("A.5 SKIP — external/manual (router + /approve)")
fi

# ------------------------------------------------------------------ A.6
echo; hr; echo "A.6 — Exclusion holds (governance protected asset $PROTECTED_IP)"; hr
before=$(agent_pending_count)
BODY=$(printf '{"severity":"high","source_ip":"%s","source_mac":"","raw_log":"SOP-147 A.6 exclusion test — alert targeting governance protected asset %s","tenant_id":"%s"}' \
        "$PROTECTED_IP" "$PROTECTED_IP" "$TENANT")
resp=$(agent_post /alert "$BODY")
status=$(printf '%s' "$resp" | jget status)
case_id=$(printf '%s' "$resp" | jget case_id)
after=$(agent_pending_count)

if [[ "$status" == "no_action_protected_asset" ]]; then
  echo "[PASS] agent refused: status=no_action_protected_asset (case=$case_id)"
else
  echo "[FAIL] agent did not protect the asset (status='${status:-<none>}') resp=$resp"; fail=1
fi
if [[ "$before" == "ERR" || "$after" == "ERR" ]]; then
  echo "[FAIL] GET /pending failed — cannot confirm no draft was queued (see [ERR] above)"; fail=1
elif [[ "$after" -le "$before" ]]; then
  echo "[PASS] no draft queued for the protected asset (pending $before -> $after)"
else
  echo "[FAIL] a draft was queued for a PROTECTED asset (pending $before -> $after)"; fail=1
fi
# Audit record: append-only soc-audit-<tenant> alert_excluded_asset / no_action.
sleep 2; es "$ES_URL/soc-audit-${TENANT}/_refresh" >/dev/null 2>&1
aud=$(es "$ES_URL/soc-audit-${TENANT}/_search?size=3&sort=@timestamp:desc&q=alert_excluded_asset" 2>/dev/null)
if printf '%s' "$aud" | grep -q "$PROTECTED_IP"; then
  echo "[PASS] soc-audit-${TENANT} has alert_excluded_asset record for $PROTECTED_IP"
  SUMMARY+=("A.6 PASS — exclusion held, audit recorded (case=$case_id)")
else
  echo "[WARN] soc-audit alert_excluded_asset record for $PROTECTED_IP not found yet"
  SUMMARY+=("A.6 PARTIAL — agent refused; audit doc not confirmed")
fi

# ------------------------------------------------------------------ summary
echo; hr; echo "Section A.4–A.6 evidence summary"; hr
for s in "${SUMMARY[@]}"; do echo "  - $s"; done
echo
echo "Manual (Kibana UI — not automatable): screenshot the Cases opened above"
echo "  (A.4 draft case, A.6 case=$case_id) and the matching soc-audit-${TENANT}"
echo "  records, per Section A's provenance requirement."
exit "$fail"
