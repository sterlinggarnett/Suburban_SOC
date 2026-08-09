#!/usr/bin/env bash
# =============================================================================
# erase_tenant.sh — WS3.4 right-to-erasure (GDPR Art.17 / CCPA deletion).
#
# Permanently removes ALL data for one tenant slug:
#   * data streams      logstash-security-<tenant>, soar-actions-<tenant>
#   * plain indices     soc-audit-<tenant>, agent-checkpoints-<tenant> (#245 —
#                       this holds each alert's raw payload, source IP/MAC,
#                       for as long as the checkpoint is unresolved; not a
#                       data stream, so it's deleted directly, not rolled over)
#   * shared indices    delete_by_query on tenant.id == <tenant>
#                       (.alerts-security.*, asset-inventory-*, soar-actions-dynamic-*)
#   * access artifacts  tenant role + user + Kibana space + data view
#
# The deletion is logged to the tamper-evident audit trail (WS3.3) of the tenant
# being erased BEFORE its audit index is dropped, and to soc-audit-unassigned, so
# the erasure itself leaves an evidentiary record (who ran it, when). See SOP-012.
#
# Usage:
#   cd ~/projects/Suburban-SOC/scripts/setup
#   ./erase_tenant.sh <tenant-slug>            # prompts for confirmation
#   ./erase_tenant.sh <tenant-slug> --yes      # non-interactive (runbook/automation)
#   ./erase_tenant.sh <tenant-slug> --dry-run  # show what WOULD be deleted
#
# Env (auto-loaded from ./.env): ES_URL, KIBANA_URL (default https://localhost:5601
# — #177: Kibana is TLS-only now, same stack CA as ES), ES_USER/ES_PASS, ES_CA.
# =============================================================================
set -euo pipefail
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

TENANT="${1:-}"; MODE="${2:-}"
if [[ -z "$TENANT" ]]; then red "Usage: $0 <tenant-slug> [--yes|--dry-run]"; exit 1; fi
if ! [[ "$TENANT" =~ ^[a-z0-9][a-z0-9-]{1,38}$ ]]; then
  red "ERROR: tenant slug must be lowercase [a-z0-9-], 2-39 chars (got '$TENANT')."; exit 1
fi
if [[ "$TENANT" == "unassigned" ]]; then
  red "ERROR: refusing to erase the shared 'unassigned' tenant."; exit 1
fi
DRY=0; ASSUME_YES=0
[[ "$MODE" == "--dry-run" ]] && DRY=1
[[ "$MODE" == "--yes" ]] && ASSUME_YES=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/.env" ]] && { set -a; . "$SCRIPT_DIR/.env"; set +a; }
KIBANA_URL="${KIBANA_URL:-https://localhost:5601}"
# Shared ES creds + TLS + es()/es_code() (issue #156).
source "$SCRIPT_DIR/lib/es_common.sh"

ROLE="tenant_${TENANT//-/_}_viewer"
USER="tenant_${TENANT//-/_}"
ACTOR="${SUDO_USER:-${USER_NAME:-$(whoami 2>/dev/null || echo operator)}}"
# #286 security-auditor MEDIUM: logstash-security-quarantine-<tenant> (the
# _grokparsefailure/_jsonparsefailure destination, configs/logstash.conf's
# output{} block) is a separate data stream matching the SAME
# logstash-security-* index_patterns template — omitting it here left
# quarantined events (which carry the full ECS payload, including MAC
# fields since #286) surviving a completed, signed "erasure done" receipt.
STREAMS=("logstash-security-${TENANT}" "logstash-security-quarantine-${TENANT}" "soar-actions-${TENANT}")
AUDIT_IDX="soc-audit-${TENANT}"
CHECKPOINTS_IDX="agent-checkpoints-${TENANT}"
SHARED=(".alerts-security.alerts-default" "asset-inventory-*" "soar-actions-dynamic-*")

blue "==> Right-to-erasure target: tenant '${TENANT}'"
echo "    Data streams : ${STREAMS[*]}"
echo "    Plain indices: ${AUDIT_IDX} ${CHECKPOINTS_IDX}"
echo "    Shared (by tenant.id) : ${SHARED[*]}"
echo "    Access       : role=${ROLE} user=${USER} space=${TENANT}"

# Pre-count so the operator/runbook sees the scope and the audit record has totals.
total=0
for s in "${STREAMS[@]}" "$AUDIT_IDX" "$CHECKPOINTS_IDX"; do
  c=$(es "${ES_URL}/${s}/_count" 2>/dev/null | grep -oE '"count":[0-9]+' | cut -d: -f2 || true); c=${c:-0}
  echo "    docs in ${s}: ${c}"; total=$((total + c))
done
echo "    ~${total} docs in dedicated stores (+ matched shared docs)"

if [[ $DRY -eq 1 ]]; then green "[dry-run] No changes made."; exit 0; fi

if [[ $ASSUME_YES -ne 1 ]]; then
  red "This PERMANENTLY deletes the above. Type the tenant slug to confirm:"
  read -r CONFIRM
  [[ "$CONFIRM" == "$TENANT" ]] || { red "Confirmation mismatch — aborted."; exit 1; }
fi

# Audit the erasure FIRST (append-only, WS3.3) — into the tenant's own audit index
# (about to be dropped, but the off-cluster SLM snapshot already captured prior days)
# AND into the shared unassigned audit so the record survives this index deletion.
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
for idx in "$AUDIT_IDX" "soc-audit-unassigned"; do
  # Pipe the ndjson in: $(printf) strips the trailing newline that _bulk requires.
  printf '{"create":{}}\n{"@timestamp":"%s","event.action":"tenant_erasure","actor":"%s","tenant.id":"%s","event.outcome":"in_progress","detail":"right-to-erasure run"}\n' "$TS" "$ACTOR" "$TENANT" \
    | es -X POST "${ES_URL}/${idx}/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @- >/dev/null || true
done

blue "==> [1/5] Deleting per-tenant data streams"
for s in "${STREAMS[@]}"; do
  echo "    DELETE _data_stream/${s} -> HTTP $(es_code -X DELETE "${ES_URL}/_data_stream/${s}")"
done

blue "==> [2/5] Purging tenant docs from shared indices (delete_by_query)"
for idx in "${SHARED[@]}"; do
  r=$(es -X POST "${ES_URL}/${idx}/_delete_by_query?conflicts=proceed&refresh=true" \
        -H 'Content-Type: application/json' \
        -d "{\"query\":{\"term\":{\"tenant.id\":\"${TENANT}\"}}}" 2>/dev/null)
  del=$(echo "$r" | grep -oE '"deleted":[0-9]+' | head -1 | cut -d: -f2 || true)
  echo "    ${idx}: deleted ${del:-0}"
done

blue "==> [3/5] Deleting the tenant audit index"
echo "    DELETE ${AUDIT_IDX} -> HTTP $(es_code -X DELETE "${ES_URL}/${AUDIT_IDX}")"

blue "==> [4/5] Deleting the tenant agent-checkpoints index (#245)"
echo "    DELETE ${CHECKPOINTS_IDX} -> HTTP $(es_code -X DELETE "${ES_URL}/${CHECKPOINTS_IDX}")"

blue "==> [5/5] Removing access artifacts (role / user / space / data view)"
echo "    user  -> HTTP $(es_code -X DELETE "${ES_URL}/_security/user/${USER}")"
echo "    role  -> HTTP $(es_code -X DELETE "${ES_URL}/_security/role/${ROLE}")"
# #177: Kibana now serves TLS on the same stack CA as ES — add ES_TLS[@], not just auth.
KARGS=(-s -H 'kbn-xsrf: true' "${ES_AUTH[@]}" "${ES_TLS[@]}")
echo "    space -> HTTP $(curl "${KARGS[@]}" -o /dev/null -w '%{http_code}' -X DELETE "${KIBANA_URL}/api/spaces/space/${TENANT}" || echo "n/a")"

# Final erasure receipt to the shared audit trail.
printf '{"create":{}}\n{"@timestamp":"%s","event.action":"tenant_erasure","actor":"%s","tenant.id":"%s","event.outcome":"completed","detail":"erased %s docs + access artifacts"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ACTOR" "$TENANT" "$total" \
  | es -X POST "${ES_URL}/soc-audit-unassigned/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @- >/dev/null || true

echo
green "=================== TENANT ERASED ==================="
printf '  Tenant  : %s\n' "$TENANT"
printf '  Receipt : soc-audit-unassigned (event.action=tenant_erasure, outcome=completed)\n'
green "====================================================="
