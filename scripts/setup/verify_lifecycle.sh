#!/usr/bin/env bash
# =============================================================================
# verify_lifecycle.sh — prove the WS0.5 data lifecycle is live (acceptance check).
#
# Verifies, against a running stack:
#   1. ILM policies exist                       (logstash-security-ilm, soar-actions-ilm)
#   2. data-stream templates are data streams   (data_stream:{} present)
#   3. the snapshot repository is registered + healthy
#   4. the SLM policy is installed
#   5. ROLLOVER OBSERVED — seeds a doc, forces a manual rollover on a security
#      data stream, and shows generation 1 -> 2 with a fresh backing index.
#   6. SNAPSHOT — triggers an SLM snapshot and confirms it reaches SUCCESS, so the
#      ILM delete phase's wait_for_snapshot has something to gate on.
#
# Non-destructive: it only writes to a throwaway tenant data stream
# (logstash-security-_verify) and deletes that stream at the end.
#
# Usage (env auto-loaded from scripts/setup/.env):
#   ./verify_lifecycle.sh
#   ./verify_lifecycle.sh --keep        # keep the _verify data stream for inspection
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$HERE/.env" ]] && { set -a; . "$HERE/.env"; set +a; }

# Shared ES creds + TLS + es/esj/es_bulk helpers (issue #156).
source "$HERE/lib/es_common.sh"

KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

REPO="suburban-soc-snapshots"
SLM="suburban-soc-daily-snapshots"
VERIFY_DS="logstash-security-_verify"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

es() { esj "$@"; }   # json content-type; es_bulk (x-ndjson) is from the shared helper (issue #156)
jget() { python3 -c "import sys,json;d=json.load(sys.stdin);print(eval('d$1'))" 2>/dev/null | tr -d '\r'; }

FAIL=0
pass() { green "    PASS: $*"; }
warn() { red   "    FAIL: $*"; FAIL=1; }

blue "==> [1/6] ILM policies present"
for p in logstash-security-ilm soar-actions-ilm; do
  code=$(es -o /dev/null -w '%{http_code}' "$ES_URL/_ilm/policy/$p")
  [[ "$code" == "200" ]] && pass "$p installed" || warn "$p missing (HTTP $code) — run apply-lifecycle.sh"
done

blue "==> [2/6] Index templates are data streams"
for t in logstash-security-template soar-actions-template; do
  has_ds=$(es "$ES_URL/_index_template/$t" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('yes' if d.get('index_templates',[{}])[0].get('index_template',{}).get('data_stream') is not None else 'no')" 2>/dev/null | tr -d '\r')
  [[ "$has_ds" == "yes" ]] && pass "$t has data_stream:{}" || warn "$t is NOT a data-stream template — run apply-templates.sh"
done
# #257 (security-auditor review of #245, acceptance criterion): the INVERSE
# assertion for agent-checkpoints-template — it must NOT be a data stream.
# #245 deliberately reverted this template's data_stream config: the index
# is a single, always-growing, upsert-by-id store (checkpoints.py does
# PUT/GET _doc/{id}), which a data stream (append-only, no GET-by-id)
# structurally cannot serve. If a future template edit silently reintroduced
# data_stream:{} here, every checkpoint/claim write would start failing
# (data streams only accept op_type=create, and write_checkpoint()'s PUT is
# a full-document upsert) — this would surface as #276's manage_stuck_claims.py
# filling up with claims that never got a paired phase checkpoint, a
# confusing failure mode to debug from that symptom alone.
# code-reviewer catch: gate on HTTP status FIRST — a missing template (404,
# e.g. apply-templates.sh never ran) has no "index_templates" key, and the
# same jq-style fallback the loop above relies on resolves that to "no" too,
# which is this check's PASS condition. Left ungated, a template that's
# absent entirely — arguably the worse regression — would false-PASS as
# "correctly has NO data_stream:{}".
code=$(es -o /dev/null -w '%{http_code}' "$ES_URL/_index_template/agent-checkpoints-template")
if [[ "$code" != "200" ]]; then
  warn "agent-checkpoints-template missing (HTTP $code) — run apply-templates.sh"
else
  has_ds_checkpoints=$(es "$ES_URL/_index_template/agent-checkpoints-template" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('yes' if d.get('index_templates',[{}])[0].get('index_template',{}).get('data_stream') is not None else 'no')" 2>/dev/null | tr -d '\r')
  [[ "$has_ds_checkpoints" == "no" ]] && pass "agent-checkpoints-template correctly has NO data_stream:{} (#245)" \
    || warn "agent-checkpoints-template unexpectedly HAS data_stream:{} — this would break checkpoints.py's upsert-by-id writes (#245 regression)"
fi

blue "==> [3/6] Snapshot repository registered + healthy"
verify=$(es "$ES_URL/_snapshot/$REPO/_verify" -X POST)
if echo "$verify" | grep -q '"nodes"'; then
  pass "repository '$REPO' verified"
else
  warn "repository '$REPO' not healthy: $(echo "$verify" | head -c 200) (check path.repo + snapshots volume)"
fi

blue "==> [4/6] SLM policy installed"
code=$(es -o /dev/null -w '%{http_code}' "$ES_URL/_slm/policy/$SLM")
[[ "$code" == "200" ]] && pass "SLM '$SLM' installed" || warn "SLM '$SLM' missing (HTTP $code)"

blue "==> [5/6] ROLLOVER OBSERVED (seed -> manual rollover on $VERIFY_DS)"
es_bulk -o /dev/null -X POST "$ES_URL/$VERIFY_DS/_bulk" \
  --data-binary $'{"create":{}}\n{"@timestamp":"2026-01-01T00:00:00Z","tenant":{"id":"_verify"},"message":"ws0.5 verify seed"}\n'
gen_before=$(es "$ES_URL/_data_stream/$VERIFY_DS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
ds=d.get('data_streams',[])
print(ds[0].get('generation') if ds else 'none')" 2>/dev/null | tr -d '\r')
es -o /dev/null -X POST "$ES_URL/$VERIFY_DS/_rollover"
gen_after=$(es "$ES_URL/_data_stream/$VERIFY_DS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
ds=d.get('data_streams',[])
print(ds[0].get('generation') if ds else 'none')" 2>/dev/null | tr -d '\r')
n_backing=$(es "$ES_URL/_data_stream/$VERIFY_DS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
ds=d.get('data_streams',[])
print(len(ds[0].get('indices',[])) if ds else 0)" 2>/dev/null | tr -d '\r')
if [[ "$gen_before" =~ ^[0-9]+$ && "$gen_after" =~ ^[0-9]+$ && "$gen_after" -gt "$gen_before" ]]; then
  pass "rollover observed: generation $gen_before -> $gen_after ($n_backing backing indices)"
else
  warn "rollover not observed (gen $gen_before -> $gen_after) — is the data_stream template installed?"
fi

blue "==> [6/6] SNAPSHOT (trigger SLM, confirm SUCCESS)"
snap=$(es -X POST "$ES_URL/_slm/policy/$SLM/_execute")
snap_name=$(echo "$snap" | python3 -c "import sys,json;print(json.load(sys.stdin).get('snapshot_name',''))" 2>/dev/null | tr -d '\r')
if [[ -n "$snap_name" ]]; then
  state=""
  for _ in $(seq 1 30); do
    state=$(es "$ES_URL/_snapshot/$REPO/$snap_name" | python3 -c "
import sys,json
try: print(json.load(sys.stdin)['snapshots'][0]['state'])
except Exception: print('PENDING')" 2>/dev/null | tr -d '\r')
    [[ "$state" == "SUCCESS" || "$state" == "PARTIAL" || "$state" == "FAILED" ]] && break
    sleep 2
  done
  [[ "$state" == "SUCCESS" ]] && pass "snapshot '$snap_name' -> SUCCESS" || warn "snapshot '$snap_name' state=$state"
else
  warn "SLM execute did not return a snapshot name: $(echo "$snap" | head -c 200)"
fi

# Cleanup the throwaway verify stream unless --keep.
if [[ $KEEP -eq 0 ]]; then
  es -o /dev/null -X DELETE "$ES_URL/_data_stream/$VERIFY_DS" || true
fi

echo
if [[ $FAIL -eq 0 ]]; then
  green "===== WS0.5 lifecycle verified: ILM attached, rollover observed, snapshot-before-delete in place ====="
  exit 0
else
  red "===== WS0.5 verification had failures (see FAIL lines above) ====="
  exit 1
fi
