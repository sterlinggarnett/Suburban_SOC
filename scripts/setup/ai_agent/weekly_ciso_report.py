"""
weekly_ciso_report.py
Automated CISO Reporting Pipeline — Suburban-SOC
-------------------------------------------------
Satisfies Issue #51 Tasks 4.1–4.5:
  4.1  NIST CSF tagging (reads NIST:<func> tags from Elasticsearch alerts)
  4.2  MTTD calculation (kibana.alert.start - @timestamp, per incident)
  4.3  LLM executive summary (OpenAI-compatible; same key as agent_app.py)
  4.4  PDF generation via Jinja2 + WeasyPrint
  4.5  Auto-delivery: Slack (2024 three-step API) + ntfy push notification

Triggered:
  • Standalone:  python weekly_ciso_report.py
  • Via Flask:   POST /weekly-report  (wired into agent_app.py)
"""

import os
import json
import logging
from datetime import datetime, timedelta, timezone

import requests
from jinja2 import Template
from weasyprint import HTML
from elasticsearch import Elasticsearch

# ---------------------------------------------------------------------------
# 0. CONFIGURATION — mirrors agent_app.py env-var conventions
# ---------------------------------------------------------------------------
ES_HOST         = os.getenv("ES_HOST",          "https://localhost:9200")
ES_API_KEY      = os.getenv("ES_API_KEY",        "your_es_api_key")
LLM_API_KEY     = os.getenv("LLM_API_KEY",       "your_api_key_here")   # shared with agent_app
LLM_API_URL     = os.getenv("LLM_API_URL",       "https://api.openai.com/v1/chat/completions")
LLM_MODEL       = os.getenv("LLM_MODEL",         "gpt-4")
NTFY_TOPIC      = os.getenv("NTFY_TOPIC",        "uiw_lab_soc_alerts_tjlam_99")  # shared with agent_app
SLACK_TOKEN     = os.getenv("SLACK_BOT_TOKEN",   "")
SLACK_CHANNEL   = os.getenv("SLACK_CHANNEL_ID",  "")
PDF_OUTPUT_DIR  = os.getenv("PDF_OUTPUT_DIR",    "/tmp")
PDF_FILENAME    = os.path.join(PDF_OUTPUT_DIR, "Weekly_NIST_Security_Report.pdf")

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. FETCH DATA & CALCULATE METRICS  (Tasks 4.1 & 4.2)
# ---------------------------------------------------------------------------

# Task 4.1 — NIST CSF function mapping
NIST_FUNCTIONS = {"Identify", "Protect", "Detect", "Respond", "Recover"}


def _tag_to_nist(tags: list) -> list[str]:
    """
    Extracts NIST CSF function labels from Kibana alert tags.
    Expected tag format: 'NIST:Detect', 'NIST:Respond', etc.
    Returns a list of matched function names.
    """
    matched = []
    for tag in tags:
        tag_str = str(tag).strip()
        if tag_str.upper().startswith("NIST:"):
            func = tag_str.split(":", 1)[1].capitalize()
            if func in NIST_FUNCTIONS:
                matched.append(func)
    return matched


def fetch_and_calculate_metrics() -> dict:
    """
    Queries Elasticsearch .alerts-security.alerts-* for the last 7 days.
    Computes:
      - Total alert count
      - Average MTTD (Mean Time to Detect) in minutes  [Task 4.2]
      - NIST CSF function distribution                  [Task 4.1]
    Falls back to hardcoded demo data if ES is unreachable.
    """
    log.info("Fetching alerts from Elasticsearch (%s)...", ES_HOST)
    seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()

    query = {
        "query": {
            "range": {
                "kibana.alert.start": {"gte": seven_days_ago}
            }
        },
        "_source": ["@timestamp", "kibana.alert.start", "tags"],
        "size": 10000,
    }

    try:
        es = Elasticsearch(ES_HOST, api_key=ES_API_KEY, verify_certs=False)
        res = es.search(index=".alerts-security.alerts-*", body=query)
        hits = res["hits"]["hits"]
        log.info("Retrieved %d alerts from ES.", len(hits))
    except Exception as exc:
        log.warning("ES connection failed (%s). Using demo fallback data.", exc)
        return {
            "total_alerts": 342,
            "average_mttd_minutes": 18.5,
            "nist_breakdown": {
                "Identify": 12, "Protect": 85,
                "Detect": 190, "Respond": 45, "Recover": 10,
            },
            "demo_mode": True,
        }

    total_alerts = len(hits)
    mttd_samples = []
    nist_counts = {f: 0 for f in NIST_FUNCTIONS}

    for hit in hits:
        src = hit["_source"]

        # Task 4.2 — MTTD per incident
        try:
            event_ts = src.get("@timestamp", "").replace("Z", "+00:00")
            alert_ts = (
                src.get("kibana", {})
                   .get("alert", {})
                   .get("start", "")
                   .replace("Z", "+00:00")
            )
            if event_ts and alert_ts:
                event_time = datetime.fromisoformat(event_ts)
                alert_time = datetime.fromisoformat(alert_ts)
                mttd_minutes = (alert_time - event_time).total_seconds() / 60
                if mttd_minutes >= 0:          # ignore negative (clock skew)
                    mttd_samples.append(mttd_minutes)
        except (ValueError, TypeError, AttributeError):
            pass

        # Task 4.1 — NIST CSF tagging
        for func in _tag_to_nist(src.get("tags", [])):
            nist_counts[func] += 1

    avg_mttd = round(sum(mttd_samples) / len(mttd_samples), 2) if mttd_samples else 0

    return {
        "total_alerts": total_alerts,
        "average_mttd_minutes": avg_mttd,
        "nist_breakdown": nist_counts,
        "demo_mode": False,
    }


# ---------------------------------------------------------------------------
# 2. LLM EXECUTIVE SUMMARY  (Task 4.3)
#    Uses the same LLM_API_KEY / LLM_API_URL as agent_app.py
# ---------------------------------------------------------------------------

def generate_executive_summary(metrics: dict) -> str:
    """
    Calls the OpenAI-compatible LLM endpoint (shared with agent_app.py)
    to produce a 3-paragraph board-ready CISO narrative.
    """
    log.info("Generating executive summary via LLM (%s)...", LLM_MODEL)

    system_prompt = (
        "You are an expert Chief Information Security Officer (CISO). "
        "Generate a 3-paragraph executive summary for the board based on this week's metrics.\n\n"
        "Paragraph 1: Summarize total alert volume and the threat landscape.\n"
        "Paragraph 2: Analyze Mean Time to Detect (MTTD). Under 30 minutes is a success.\n"
        "Paragraph 3: Break down alerts by NIST CSF function. Highlight the dominant detection area.\n\n"
        "Tone: Professional, concise, business-risk focused. No markdown formatting. "
        "Separate paragraphs with a blank line."
    )

    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": json.dumps(metrics)},
        ],
        "temperature": 0.2,
    }
    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type":  "application/json",
    }

    try:
        resp = requests.post(LLM_API_URL, json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        log.error("LLM call failed: %s", exc)
        return "Executive summary could not be generated at this time. Manual review required."


# ---------------------------------------------------------------------------
# 3. PDF GENERATION  (Task 4.4)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <style>
    body  { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            margin: 48px; color: #222; }
    h1    { color: #1a252f; border-bottom: 3px solid #2c3e50;
            padding-bottom: 8px; font-size: 22px; }
    h2    { color: #2980b9; margin-top: 28px; font-size: 16px; }
    .meta { font-size: 12px; color: #666; margin-bottom: 24px; }
    .kpi  { display: flex; gap: 32px; background: #eaf0fb;
            padding: 20px; border-radius: 6px; margin: 20px 0; }
    .kpi-item { text-align: center; }
    .kpi-val  { font-size: 28px; font-weight: bold; color: #c0392b; }
    .kpi-lbl  { font-size: 11px; color: #555; text-transform: uppercase; }
    .narrative { font-size: 13px; line-height: 1.7; text-align: justify; }
    .narrative p { margin: 0 0 12px; }
    .demo-banner { background: #f39c12; color: #fff; padding: 8px 16px;
                   border-radius: 4px; font-size: 12px; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
    th, td { border: 1px solid #ccc; padding: 9px 12px; text-align: left; }
    th     { background: #ecf0f1; font-weight: bold; }
    tr:nth-child(even) { background: #f9f9f9; }
    .footer { margin-top: 40px; font-size: 10px; color: #aaa;
              border-top: 1px solid #ddd; padding-top: 8px; }
  </style>
</head>
<body>
  <h1>Weekly CISO Security Posture Report</h1>
  <p class="meta">
    <strong>Suburban-SOC</strong> &nbsp;|&nbsp;
    Generated: {{ date }} &nbsp;|&nbsp;
    Period: Last 7 Days
    {% if metrics.demo_mode %} &nbsp;|&nbsp;
      <span style="color:#e74c3c;font-weight:bold;">⚠ DEMO DATA</span>
    {% endif %}
  </p>

  {% if metrics.demo_mode %}
  <div class="demo-banner">
    ⚠ Elasticsearch unreachable — report generated from demo data for validation purposes.
  </div>
  {% endif %}

  <div class="kpi">
    <div class="kpi-item">
      <div class="kpi-val">{{ metrics.total_alerts }}</div>
      <div class="kpi-lbl">Total Alerts</div>
    </div>
    <div class="kpi-item">
      <div class="kpi-val">{{ metrics.average_mttd_minutes }} min</div>
      <div class="kpi-lbl">Avg MTTD</div>
    </div>
    <div class="kpi-item">
      <div class="kpi-val">{{ metrics.nist_breakdown.values() | sum }}</div>
      <div class="kpi-lbl">NIST-Tagged Alerts</div>
    </div>
  </div>

  <h2>Executive Summary</h2>
  <div class="narrative">
    {% for para in narrative.split('\n\n') if para.strip() %}
      <p>{{ para.strip() }}</p>
    {% endfor %}
  </div>

  <h2>NIST CSF Alert Distribution</h2>
  <table>
    <tr><th>Framework Function</th><th>Alert Count</th><th>% of Tagged</th></tr>
    {% set total_tagged = metrics.nist_breakdown.values() | sum %}
    {% for func, count in metrics.nist_breakdown.items() %}
    <tr>
      <td>{{ func }}</td>
      <td>{{ count }}</td>
      <td>{% if total_tagged > 0 %}{{ ((count / total_tagged) * 100) | round(1) }}%{% else %}—{% endif %}</td>
    </tr>
    {% endfor %}
  </table>

  <p class="footer">
    Suburban-SOC Automated Reporting Pipeline &nbsp;|&nbsp;
    Suburban-SOC &copy; {{ year }} &nbsp;|&nbsp;
    Confidential — For Internal Use Only
  </p>
</body>
</html>
"""


def create_pdf_report(metrics: dict, narrative: str) -> str:
    """
    Renders the Jinja2 HTML template and converts to PDF via WeasyPrint.
    Returns the absolute path to the saved PDF.
    """
    log.info("Compiling PDF report -> %s", PDF_FILENAME)
    rendered = Template(_HTML_TEMPLATE).render(
        date=datetime.now().strftime("%B %d, %Y"),
        year=datetime.now().year,
        metrics=metrics,
        narrative=narrative,
    )
    HTML(string=rendered).write_pdf(PDF_FILENAME)
    log.info("PDF saved: %s", PDF_FILENAME)
    return PDF_FILENAME


# ---------------------------------------------------------------------------
# 4. DISTRIBUTE  (Task 4.5)
#    a) Slack — fixed 2024 three-step files.getUploadURLExternal API
#    b) ntfy  — push notification (same topic as agent_app.py)
# ---------------------------------------------------------------------------

def send_to_slack(pdf_path: str) -> bool:
    """
    Uploads the PDF to Slack using the 2024 three-step upload API:
      1. files.getUploadURLExternal  → upload_url + file_id
      2. PUT file bytes to upload_url
      3. files.completeUploadExternal → publish to channel
    Returns True on success.
    """
    if not SLACK_TOKEN or not SLACK_CHANNEL:
        log.warning("Slack credentials not configured — skipping Slack delivery.")
        return False

    log.info("Uploading report to Slack channel %s...", SLACK_CHANNEL)
    headers_auth = {"Authorization": f"Bearer {SLACK_TOKEN}"}
    file_size = os.path.getsize(pdf_path)

    # Step 1 — request an upload URL
    url_resp = requests.get(
        "https://slack.com/api/files.getUploadURLExternal",
        headers=headers_auth,
        params={"filename": os.path.basename(pdf_path), "length": file_size},
        timeout=15,
    )
    url_data = url_resp.json()
    if not url_data.get("ok"):
        log.error("Slack getUploadURLExternal failed: %s", url_data)
        return False

    upload_url = url_data["upload_url"]
    file_id    = url_data["file_id"]

    # Step 2 — PUT the binary PDF to the pre-signed URL
    with open(pdf_path, "rb") as fh:
        put_resp = requests.put(upload_url, data=fh,
                                headers={"Content-Type": "application/pdf"},
                                timeout=60)
    if put_resp.status_code not in (200, 201):
        log.error("Slack binary upload failed: HTTP %s", put_resp.status_code)
        return False

    # Step 3 — complete the upload and post to channel
    complete_resp = requests.post(
        "https://slack.com/api/files.completeUploadExternal",
        headers={**headers_auth, "Content-Type": "application/json"},
        json={
            "files": [{"id": file_id}],
            "channel_id": SLACK_CHANNEL,
            "initial_comment": (
                "📊 *Weekly Security Metrics & NIST Alignment Report* is ready for review."
            ),
        },
        timeout=15,
    )
    result = complete_resp.json()
    if result.get("ok"):
        log.info("Report successfully delivered to Slack.")
        return True
    else:
        log.error("Slack completeUploadExternal failed: %s", result)
        return False


def send_ntfy_notification(metrics: dict, pdf_delivered: bool) -> None:
    """
    Pushes a summary push notification via ntfy (same topic as agent_app.py).
    """
    status = "✅ Delivered to Slack" if pdf_delivered else "⚠ Slack skipped — check credentials"
    message = (
        f"Weekly CISO Report Generated\n"
        f"Alerts: {metrics['total_alerts']} | "
        f"MTTD: {metrics['average_mttd_minutes']} min\n"
        f"{status}"
    )
    try:
        requests.post(
            f"https://ntfy.sh/{NTFY_TOPIC}",
            data=message.encode("utf-8"),
            headers={
                "Title":    "📊 Weekly Security Report Ready",
                "Priority": "3",
                "Tags":     "bar_chart,lock",
            },
            timeout=10,
        )
        log.info("ntfy notification sent.")
    except Exception as exc:
        log.warning("ntfy notification failed: %s", exc)


# ---------------------------------------------------------------------------
# PIPELINE ORCHESTRATOR — callable from agent_app.py or standalone
# ---------------------------------------------------------------------------

def run_reporting_pipeline() -> dict:
    """
    Full pipeline:  ES query → NIST/MTTD → LLM narrative → PDF → Slack + ntfy
    Returns a summary dict suitable for a Flask JSON response.
    """
    log.info("=== Automated CISO Reporting Pipeline — START ===")

    metrics   = fetch_and_calculate_metrics()
    narrative = generate_executive_summary(metrics)
    pdf_path  = create_pdf_report(metrics, narrative)
    delivered = send_to_slack(pdf_path)
    send_ntfy_notification(metrics, delivered)

    log.info("=== Automated CISO Reporting Pipeline — COMPLETE ===")
    return {
        "status":               "complete",
        "pdf":                  pdf_path,
        "total_alerts":         metrics["total_alerts"],
        "average_mttd_minutes": metrics["average_mttd_minutes"],
        "slack_delivered":      delivered,
        "demo_mode":            metrics.get("demo_mode", False),
    }


# ---------------------------------------------------------------------------
# STANDALONE ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    result = run_reporting_pipeline()
    print(json.dumps(result, indent=2))
