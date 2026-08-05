#!/usr/bin/env bash
# =============================================================================
# sim_intel_match.sh — WS1.1 scenario: live-intel match drives the SOAR loop.
#
# Asserts the detection->response loop that WS1.1 restored:
#   Zeek Intel match (intel.log)  ->  Logstash maps it to ECS threat.indicator.*
#   ->  SOAR trigger fires /alert  ->  AI agent DRAFTS a response.
#
# It injects a Zeek-intel.log-shaped event for the deterministic TEST indicator
# (198.51.100.66, RFC-5737, shipped in configs/intel/intel.seed.dat) into the REAL
# running pipeline via the Logstash HTTP input, then verifies:
#   1. Elasticsearch indexed a zeek.intel doc with threat.indicator.ip set;
#   2. the AI agent received /alert and queued a draft (/pending count increased).
#
# This exercises the WS1.1 wiring end-to-end without needing a live capture NIC.
# (The Zeek->intel.log half is the Intel framework + WS1.3 feed.)
#
# Usage:  ./sim_intel_match.sh        (run from anywhere; loads ../../scripts/setup/.env)
# Env:    ES_URL, ES_USER, ES_PASS/ELASTIC_PASSWORD, AGENT_URL (default :5000),
#         MESH_CONTAINER (a container on soc-mesh-net used to reach logstash:5514).
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# Source the canonical stack secrets only (scripts/setup/.env). We intentionally do
# NOT inherit tests/anomaly_simulation/.env's ES_URL — it predates WS0.1 and points
# at plain http://, which fails against the now TLS-secured stack.
[[ -f "$HERE/../../scripts/setup/.env" ]] && { set -a; . "$HERE/../../scripts/setup/.env"; set +a; }

# ES_URL/ES_USER/ES_PASS are resolved once by es_common.sh (sourced below).
AGENT_URL="${AGENT_URL:-http://127.0.0.1:5000}"
MESH_CONTAINER="${MESH_CONTAINER:-elasticsearch}"
TEST_IP="198.51.100.66"
TENANT="${TENANT:-home-smith}"

# Shared ES creds fail-fast + es()/TLS (issue #156).
source "$HERE/../../scripts/setup/lib/es_common.sh"

# /pending is HMAC-gated (audit P0-2) with replay protection (audit P1-1): sign
# "<timestamp>." + empty-body and send both x-elastic-signature and
# x-elastic-timestamp. #246: gated on SOC_APPROVER_HMAC_SECRET, a SEPARATE secret
# from /alert's SOC_AGENT_HMAC_SECRET (a Logstash compromise must not be able to
# enumerate drafted containment actions) — sign with that one, not the agent's.
agent_pending_count() {
  local ts sig resp code body
  if [[ -n "${SOC_APPROVER_HMAC_SECRET:-}" ]]; then
    ts=$(date +%s)
    sig="sha256=$(printf '%s.' "$ts" | openssl dgst -sha256 -hmac "$SOC_APPROVER_HMAC_SECRET" | awk '{print $2}')"
  fi
  resp=$(curl -s --max-time 6 -w '\n%{http_code}' -H "x-elastic-signature: ${sig:-}" -H "x-elastic-timestamp: ${ts:-}" \
    "$AGENT_URL/pending")
  code="${resp##*$'\n'}"
  body="${resp%$'\n'*}"
  if [[ "$code" != "200" ]]; then
    # Coercing this to a bare "0" (as this helper used to) would silently read as
    # "no draft queued" to the before/after assertion below — indistinguishable
    # from the SOAR loop actually working. Surface it instead.
    echo "[ERR] GET /pending failed (HTTP $code, is SOC_APPROVER_HMAC_SECRET set in .env?)" >&2
    echo "ERR"
    return
  fi
  printf '%s' "$body" | python3 -c 'import sys,json;print(json.load(sys.stdin)["count"])' 2>/dev/null || echo "ERR"
}
fail=0

echo "[*] WS1.1 intel-match sim — test indicator $TEST_IP, tenant $TENANT"

# Baseline the agent's pending count so we can assert it grows by this alert.
before=$(agent_pending_count)

# Inject a Zeek intel.log-shaped event into the real pipeline (Logstash :5514 is
# mesh-internal, so reach it from a container on soc-mesh-net).
read -r -d '' EVENT <<JSON
{"log":{"file":{"path":"/storage/PCAP/zeek_logs/intel.log"}},"seen.indicator":"$TEST_IP","seen.indicator_type":"Intel::ADDR","seen.where":"Conn::IN_RESP","sources":["suburban-soc/test"],"id.orig_h":"10.0.0.50","id.orig_p":44321,"id.resp_h":"$TEST_IP","id.resp_p":443,"tenant":{"id":"$TENANT"}}
JSON
code=$(docker exec "$MESH_CONTAINER" curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -X POST http://logstash:5514 -H 'Content-Type: application/json' -d "$EVENT")
echo "[*] injected intel event -> Logstash HTTP $code"
[[ "$code" == "200" ]] || { echo "[FAIL] injection not accepted"; fail=1; }

echo "[*] waiting for pipeline + agent..."
sleep 12

# 1. ES: the latest zeek.intel doc carries threat.indicator.ip == TEST_IP.
#    Query by event.dataset (robust) and read the mapped value from _source rather
#    than term-querying an ip/keyword field with a quoted query_string.
es "$ES_URL/logstash-security-${TENANT}/_refresh" >/dev/null 2>&1
hit=$(es "$ES_URL/logstash-security-${TENANT}/_search?size=1&sort=@timestamp:desc&q=event.dataset:zeek.intel" \
  | python3 -c "import sys,json;h=json.load(sys.stdin).get('hits',{}).get('hits',[]);print(h[0]['_source'].get('threat',{}).get('indicator',{}).get('ip','') if h else '')" 2>/dev/null)
if [[ "$hit" == "$TEST_IP" ]]; then
  echo "[PASS] ES: zeek.intel doc mapped threat.indicator.ip=$TEST_IP"
else
  echo "[FAIL] ES: zeek.intel doc missing/mismatched threat.indicator.ip (got '$hit')"; fail=1
fi

# 2. Agent: /alert drafted a response (pending count grew)
after=$(agent_pending_count)
if [[ "$before" == "ERR" || "$after" == "ERR" ]]; then
  echo "[FAIL] SOAR: cannot confirm a draft was queued — GET /pending failed (see [ERR] above)"; fail=1
elif [[ "$after" -gt "$before" ]]; then
  echo "[PASS] SOAR: /alert fired and drafted a response (pending $before -> $after)"
else
  echo "[FAIL] SOAR: no new draft (pending $before -> $after) — did /alert fire/200?"; fail=1
fi

echo
if [[ "$fail" -eq 0 ]]; then
  echo "[=] WS1.1 PASS — intel match drove the detection->response loop end-to-end."
  exit 0
else
  echo "[=] WS1.1 FAIL — see [FAIL] lines above."
  exit 1
fi
