"""
agent_app.py — Suburban-SOC AI agent / SOAR webhook listener.
"""

from weekly_ciso_report import run_reporting_pipeline
import re
import logging
import threading
from flask import Flask, request, jsonify


# Import everything else from our new core module
from agent import (
    verify_signature, _require_signature, HMAC_HEADER, HMAC_TS_HEADER,
    APPROVER_HMAC_SECRET, APPROVER_IDENTITY,
    _read_queue, safe_tenant, Agent, _RESOLVED_STATUSES
)

# generate_dedup_key() (checkpoints.py) always produces a 64-char sha256 hex
# digest. alert_id is interpolated unquoted into Elasticsearch REST paths in
# checkpoints.py (e.g. _create/{alert_id}.claim), so an id that doesn't match
# this shape is rejected here — at the untrusted-input boundary — rather than
# risk it being used to target another ES API entirely.
_ALERT_ID_RE = re.compile(r"^[0-9a-f]{64}$")

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# Initialize the Agent
soc_agent = Agent()

@app.route("/alert", methods=["POST"])
def handle_kibana_webhook():
    """Phase 1: Perceive -> Think -> Act."""
    raw_body = request.get_data()
    if not verify_signature(raw_body, request.headers.get(HMAC_HEADER), request.headers.get(HMAC_TS_HEADER)):
        app.logger.warning("Rejected /alert: missing/invalid/replayed HMAC signature.")
        return jsonify({"status": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    result = soc_agent.run(data)
    
    return jsonify(result.response), result.status_code

@app.route("/pending", methods=["GET"])
def list_pending():
    # #246: gated on APPROVER_HMAC_SECRET, not /alert's HMAC_SECRET — Logstash
    # holds the latter and has no business enumerating drafted containment actions.
    auth_err = _require_signature(APPROVER_HMAC_SECRET, "SOC_APPROVER_HMAC_SECRET")
    if auth_err:
        return auth_err

    try:
        # The queue is append-only (compact_agent_approval_queue.py archives
        # resolved history separately) — an id can have multiple rows over its
        # lifecycle (pending -> claimed -> approved/isolation_failed). Show
        # every id whose LATEST row is NOT a true terminal state (#247:
        # "claimed" and "isolation_failed" both stay visible here on purpose —
        # a stuck-mid-execution or failed-but-retryable id must not silently
        # disappear the moment it's claimed, only once it actually resolves).
        latest_status = {}
        for action in _read_queue():
            latest_status[action.get("id")] = action
        pending = [a for a in latest_status.values() if a.get("status") not in _RESOLVED_STATUSES]
        return jsonify({"status": "ok", "count": len(pending), "pending": pending}), 200
    except Exception as e:
        app.logger.error("Failed to read approval queue: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/approve", methods=["POST"])
def approve_action():
    # #246: /approve executes a real isolation action, so it is gated on
    # APPROVER_HMAC_SECRET — a credential that signs /alert (Logstash's, the
    # stack's largest untrusted-input surface) must NOT be sufficient to also
    # authorize its execution.
    auth_err = _require_signature(APPROVER_HMAC_SECRET, "SOC_APPROVER_HMAC_SECRET")
    if auth_err:
        return auth_err

    data = request.get_json(silent=True) or {}
    # "id", not "action_id" — matches the broker's own /approve-equivalent
    # (hive-mind-broker/app.py) and its test suite.
    action_id = data.get("id")
    # #246: the approver of record is the trusted, operator-configured identity
    # bound to APPROVER_HMAC_SECRET — NOT this unauthenticated request-body field.
    # A caller could put anything here; only the signature above is proof of who
    # (or what) actually authorized the action.
    approver = APPROVER_IDENTITY
    tenant = safe_tenant(data.get("tenant_id"))

    if not action_id:
        return jsonify({"status": "error", "message": "Missing id"}), 400
    if not _ALERT_ID_RE.fullmatch(action_id):
        app.logger.warning("Rejected /approve: malformed id (not a dedup-key hash).")
        return jsonify({"status": "error", "message": "Malformed id"}), 400

    result = soc_agent.execute_approved(tenant, action_id, approver)
    
    return jsonify(result.response), result.status_code

# 5. CISO REPORTING ENDPOINTS
# =============================================================================
@app.route("/weekly-report", methods=["POST"])
def trigger_weekly_report():
    """
    Triggers the full CISO reporting pipeline asynchronously.
    Responds immediately with 202 Accepted; the PDF is generated and
    delivered to Slack + ntfy in the background thread.

    Authenticated (HMAC) — the trigger spawns ES + hosted-LLM + Slack work, so an
    open endpoint is a cost/DoS amplifier; the caller signs the request body
    (empty body is fine) with SOC_AGENT_HMAC_SECRET.

    Invoke manually (replay-protected: sign "<timestamp>." + empty body, send both
    the signature and the timestamp header — audit P1-1):
        TS=$(date +%s)
        SIG="sha256=$(printf '%s.' "$TS" | openssl dgst -sha256 -hmac "$SOC_AGENT_HMAC_SECRET" | awk '{print $2}')"
        curl -s -X POST -H "x-elastic-signature: $SIG" -H "x-elastic-timestamp: $TS" \
             http://localhost:5000/weekly-report
    Or schedule via cron with the same signed headers (freshly per run).
    """
    auth_error = _require_signature()
    if auth_error:
        return auth_error

    def _run():
        try:
            result = run_reporting_pipeline()
            app.logger.info("CISO report pipeline finished: %s", result)
        except Exception as exc:
            app.logger.error("CISO report pipeline error: %s", exc)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return jsonify({
        "status":  "accepted",
        "message": "Weekly CISO report pipeline started in background. "
                   "PDF will be delivered to Slack and ntfy when ready.",
    }), 202


@app.route("/weekly-report/status", methods=["GET"])
def report_status():
    """Health check — confirms the report endpoint is reachable."""
    return jsonify({"status": "ready", "endpoint": "POST /weekly-report"}), 200


# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    # Binds to 0.0.0.0 so Kibana can reach it across the Docker network
    app.run(host="0.0.0.0", port=5000, debug=False)

