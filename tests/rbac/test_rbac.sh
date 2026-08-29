#!/usr/bin/env bash
# =============================================================================
# test_rbac.sh — WS3.2 negative tests: each account can do its job, and ONLY its job.
#
# Creates throwaway users for the key roles and asserts the allowed operations
# succeed and the forbidden ones are denied (403) — proving least privilege.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVF="$HERE/../../scripts/setup/.env"
# shellcheck disable=SC1090  # .env is gitignored, no static file to point at
[[ -f "$ENVF" ]] && { set -a; . "$ENVF"; set +a; }
# Shared ES creds + TLS + es() (issue #156).
# shellcheck source=../../scripts/setup/lib/es_common.sh
source "$HERE/../../scripts/setup/lib/es_common.sh"

PW="RbacTest123!"; fails=0
admin() { es "$@"; }   # admin uses the shared es() helper (issue #156)
# audit #166: reuse the shared helper's TLS args instead of hardcoded -sk.
as() { local u="$1"; shift; curl -s "${ES_TLS[@]}" -o /dev/null -w '%{http_code}' -u "$u:$PW" "$@"; }
mkuser() { admin -o /dev/null -X PUT "$ES_URL/_security/user/$1" -H 'Content-Type: application/json' -d "{\"password\":\"$PW\",\"roles\":[\"$2\"]}"; }
rmuser() { admin -o /dev/null -X DELETE "$ES_URL/_security/user/$1"; }
expect() { # $1=label $2=actual $3=expected
  if [[ "$2" == "$3" ]]; then echo "  [PASS] $1 -> $2"; else echo "  [FAIL] $1 -> $2 (expected $3)"; fails=$((fails+1)); fi
}

admin -o /dev/null -X POST "$ES_URL/logstash-security-rbactest/_doc?refresh=true" -H 'Content-Type: application/json' -d '{"x":1}'
admin -o /dev/null -X PUT "$ES_URL/agent-checkpoints-rbactest/_doc/rbactest1?refresh=true" -H 'Content-Type: application/json' -d '{"alert_id":"rbactest1","phase":"PENDING_APPROVAL","tenant":{"id":"rbactest"}}'
mkuser t_analyst soc_analyst
mkuser t_logstash logstash_writer
mkuser t_agent_checkpoints agent_checkpoints
mkuser t_logstash_enrich logstash_enrich_reader

echo "== soc_analyst: read-only on SOC data, no admin =="
expect "analyst reads logstash-*"           "$(as t_analyst "$ES_URL/logstash-security-*/_search?size=0")" 200
expect "analyst CANNOT delete an index"     "$(as t_analyst -X DELETE "$ES_URL/logstash-security-rbactest")" 403
expect "analyst CANNOT create a role"       "$(as t_analyst -X PUT "$ES_URL/_security/role/evil" -H 'Content-Type: application/json' -d '{}')" 403

echo "== logstash_writer: write SOC indices only, no alerts read, no security mgmt =="
# Write to asset-inventory-* (a regular index the role covers; logstash-security-* is
# a WS0.5 data stream whose _doc auto-id returns 400 regardless of privilege).
expect "logstash_writer writes asset-inventory-*" "$(as t_logstash -X POST "$ES_URL/asset-inventory-rbactest/_doc" -H 'Content-Type: application/json' -d '{"y":2}')" 201
expect "logstash_writer writes soc-agent-health-*" "$(as t_logstash -X POST "$ES_URL/soc-agent-health-rbactest/_doc" -H 'Content-Type: application/json' -d '{"y":3}')" 201
# #306: `manage` (which includes delete) was dropped from asset-inventory-*/
# soc-agent-health-* -- logstash_internal (shared with the real Logstash
# pipeline) must not be able to erase either of these audit-adjacent
# indices outright, only create/write new documents into them.
expect "logstash_writer CANNOT delete asset-inventory-*" "$(as t_logstash -X DELETE "$ES_URL/asset-inventory-rbactest")" 403
expect "logstash_writer CANNOT delete soc-agent-health-*" "$(as t_logstash -X DELETE "$ES_URL/soc-agent-health-rbactest")" 403
expect "logstash_writer CANNOT read alerts" "$(as t_logstash "$ES_URL/.alerts-security.alerts-default/_search?size=0")" 403
expect "logstash_writer CANNOT create user" "$(as t_logstash -X PUT "$ES_URL/_security/user/evil" -H 'Content-Type: application/json' -d "{\"password\":\"$PW\",\"roles\":[]}")" 403
# #245: logstash_internal must NOT be able to reach agent-checkpoints-* - that
# credential is shared with the real Logstash pipeline, which has no business
# touching agent checkpoints (and it's the exact gap #245 fixed).
expect "logstash_writer CANNOT write agent-checkpoints-*" "$(as t_logstash -X PUT "$ES_URL/agent-checkpoints-rbactest/_doc/evil" -H 'Content-Type: application/json' -d '{"x":1}')" 403
expect "logstash_writer CANNOT read agent-checkpoints-*"  "$(as t_logstash "$ES_URL/agent-checkpoints-rbactest/_search?size=0")" 403

echo "== agent_checkpoints: read/write its own index only, no delete, no other indices =="
expect "agent_checkpoints reads agent-checkpoints-*"        "$(as t_agent_checkpoints "$ES_URL/agent-checkpoints-rbactest/_doc/rbactest1")" 200
expect "agent_checkpoints writes agent-checkpoints-*"       "$(as t_agent_checkpoints -X PUT "$ES_URL/agent-checkpoints-rbactest/_doc/rbactest2" -H 'Content-Type: application/json' -d '{"alert_id":"rbactest2","phase":"PERCEIVING","tenant":{"id":"rbactest"}}')" 201
# The whole point of #245's fix: index (not write) - a holder of this credential
# must not be able to erase a .claim doc and re-open the at-most-once gate.
expect "agent_checkpoints CANNOT delete a checkpoint doc"   "$(as t_agent_checkpoints -X DELETE "$ES_URL/agent-checkpoints-rbactest/_doc/rbactest1")" 403
# A wildcard search against indices the user can't see returns 200/empty, not
# 403 (ES resolves the pattern to zero visible indices rather than leaking
# their existence) - assert against the explicit named index instead, which
# does 403, to actually test the boundary.
expect "agent_checkpoints CANNOT read logstash-security-*"  "$(as t_agent_checkpoints "$ES_URL/logstash-security-default/_search?size=0")" 403

echo "== logstash_enrich_reader: #286 MAC-correlation lookup, read-only on logstash-security-*, nothing else =="
expect "logstash_enrich_reader reads logstash-security-*"        "$(as t_logstash_enrich "$ES_URL/logstash-security-rbactest/_search?size=0")" 200
# The whole point of #286's CRITICAL fix: this credential must NEVER be able
# to write — a compromised correlation lookup must not become a write primitive.
expect "logstash_enrich_reader CANNOT write logstash-security-*" "$(as t_logstash_enrich -X POST "$ES_URL/logstash-security-rbactest/_doc" -H 'Content-Type: application/json' -d '{"x":1}')" 403
expect "logstash_enrich_reader CANNOT read agent-checkpoints-*"  "$(as t_logstash_enrich "$ES_URL/agent-checkpoints-rbactest/_search?size=0")" 403

rmuser t_analyst; rmuser t_logstash; rmuser t_agent_checkpoints; rmuser t_logstash_enrich
admin -o /dev/null -X DELETE "$ES_URL/logstash-security-rbactest"
admin -o /dev/null -X DELETE "$ES_URL/asset-inventory-rbactest"
admin -o /dev/null -X DELETE "$ES_URL/soc-agent-health-rbactest"
admin -o /dev/null -X DELETE "$ES_URL/agent-checkpoints-rbactest"
echo
if [[ $fails -eq 0 ]]; then echo "[=] RBAC least-privilege verified."; exit 0; else echo "[=] $fails RBAC check(s) FAILED."; exit 1; fi
