import os
import threading
import requests
import subprocess
import logging
from flask import Flask, request, jsonify

# Import the CISO reporting pipeline (Task 4.1-4.5, Issue #51)
from weekly_ciso_report import run_reporting_pipeline

app = Flask(__name__)
logger = logging.getLogger(__name__)

# --- Configuration ---
NTFY_TOPIC  = os.environ.get("NTFY_TOPIC",    "uiw_lab_soc_alerts_tjlam_99")
LLM_API_KEY = os.environ.get("LLM_API_KEY",   "your_api_key_here")
LLM_API_URL = os.environ.get("LLM_API_URL",   "https://api.openai.com/v1/chat/completions")
LLM_MODEL   = os.environ.get("LLM_MODEL",     "gpt-4")


# =============================================================================
# 1. AI ANALYST — Level 1 SOC triage
# =============================================================================
def analyze_alert_with_ai(raw_log_data):
    """
    Acts as the Level 1 SOC Analyst. Takes the raw JSON log from Kibana
    and asks the LLM to summarize the threat and map it to MITRE ATT&CK.
    """
    system_prompt = (
        "You are an expert SOC Analyst. Analyze the following SIEM alert JSON data. "
        "Provide a 2-sentence summary of the attack, identify the likely MITRE ATT&CK tactic, "
        "and recommend a specific remediation step. Be concise."
    )
    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type":  "application/json",
    }
    payload = {
        "model":    LLM_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": str(raw_log_data)},
        ],
        "temperature": 0.2,
    }
    try:
        response = requests.post(LLM_API_URL, json=payload, headers=headers, timeout=30)
        if response.status_code == 200:
        feat/offline-integration-patch
            return response.json()["choices"][0]["message"]["content"]
        return "AI Analysis failed. Manual review required."
    except Exception as e:
        return f"AI Integration Error: {e}"
    
            return response.json()['choices'][0]['message']['content']
        else:
            return "AI Analysis failed. Manual review required."
    except Exception:
        logger.exception("AI integration failed during alert analysis.")
        return "AI Analysis failed. Manual review required."
main


# =============================================================================
# 2. NOTIFICATION ENGINE — ntfy push
# =============================================================================
def send_soc_alert(title, message, priority=3, tags="rotating_light"):
    """Pushes formatted alerts to the analyst's mobile device via ntfy."""
    url = f"https://ntfy.sh/{NTFY_TOPIC}"
    headers = {
        "Title":    title,
        "Priority": str(priority),
        "Tags":     tags,
    }
    try:
        requests.post(url, data=message.encode("utf-8"), headers=headers, timeout=10)
    except Exception as e:
        app.logger.error("ntfy delivery failed: %s", e)


# =============================================================================
# 3. WEBHOOK LISTENER — real-time alert triage
# =============================================================================
@app.route("/alert", methods=["POST"])
def handle_kibana_webhook():
    """Receives Kibana alert payload and orchestrates AI triage + response."""
    data       = request.json or {}
    severity   = data.get("severity",   "medium")
    target_ip  = data.get("source_ip",  "unknown")
    raw_details = data.get("raw_log",   "No log data provided")

    # Step 1: AI triage
    ai_summary = analyze_alert_with_ai(raw_details)

    # Step 2: Automated response
    if severity == "critical":
        subprocess.run(["sudo", "./isolate.sh", target_ip], check=False)
        alert_body = f"NODE ISOLATED: {target_ip}\n\nAI Analysis:\n{ai_summary}"
        send_soc_alert(
            title="CRITICAL: Autonomous Isolation",
            message=alert_body,
            priority=5,
            tags="skull,lock,robot",
        )
    else:
        alert_body = (
            f"Suspicious Activity from {target_ip}\n\n"
            f"AI Analysis:\n{ai_summary}\n\n"
            "Review required for isolation."
        )
        send_soc_alert(
            title="MEDIUM: Analyst Review Requested",
            message=alert_body,
            priority=3,
            tags="warning,mag,robot",
        )

    return jsonify({"status": "Alert Processed", "ai_analysis": ai_summary}), 200


# =============================================================================
# 4. WEEKLY CISO REPORT ENDPOINT  (Issue #51 — wired from weekly_ciso_report.py)
# =============================================================================
@app.route("/weekly-report", methods=["POST"])
def trigger_weekly_report():
    """
    Triggers the full CISO reporting pipeline asynchronously.
    Responds immediately with 202 Accepted; the PDF is generated and
    delivered to Slack + ntfy in the background thread.

    Invoke manually:
        curl -s -X POST http://localhost:5000/weekly-report
    Or schedule via cron:
        0 8 * * 1  curl -s -X POST http://localhost:5000/weekly-report
    """
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
