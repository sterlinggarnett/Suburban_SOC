import os
import requests
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- Configuration ---
NTFY_TOPIC = "uiw_lab_soc_alerts_tjlam_99"
# In a real environment, pass this via Docker environment variables, never hardcode it!
LLM_API_KEY = os.environ.get("LLM_API_KEY", "your_api_key_here") 
LLM_API_URL = "https://api.openai.com/v1/chat/completions" # Or your local university LLM endpoint

# --- 1. The AI Analyst Function ---
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
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "gpt-4", # Or whichever model UIW provisions for you
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": str(raw_log_data)}
        ],
        "temperature": 0.2 # Low temperature for factual, analytical responses
    }

    try:
        response = requests.post(LLM_API_URL, json=payload, headers=headers)
        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content']
        else:
            return "AI Analysis failed. Manual review required."
    except Exception as e:
        return f"AI Integration Error: {e}"

# --- 2. The Notification Engine ---
def send_soc_alert(title, message, priority=3, tags="rotating_light"):
    """Pushes formatted alerts to your mobile device via ntfy."""
    url = f"https://ntfy.sh/{NTFY_TOPIC}"
    headers = {
        "Title": title,
        "Priority": str(priority),
        "Tags": tags
    }
    requests.post(url, data=message.encode('utf-8'), headers=headers)

# --- 3. The Webhook Listener & Decision Engine ---
@app.route('/alert', methods=['POST'])
def handle_kibana_webhook():
    """Receives the payload from Kibana and orchestrates the response."""
    data = request.json
    
    # Extract key variables from the Kibana payload
    severity = data.get('severity', 'medium')
    target_ip = data.get('source_ip', 'unknown')
    raw_details = data.get('raw_log', 'No log data provided')

    # Step 1: AI Analyst Triage
    # The agent processes the raw log before any human sees it
    ai_summary = analyze_alert_with_ai(raw_details)
    
    # Step 2: Automated Responder Action
    if severity == 'critical':
        # Execute Bash Isolation Script
        # Note: The Docker container must have privileges to modify host iptables for this to work natively
        subprocess.run(["sudo", "./isolate.sh", target_ip])
        
        # Notify the lead analyst of the autonomous action + AI summary
        alert_body = f"NODE ISOLATED: {target_ip}\n\nAI Analysis:\n{ai_summary}"
        send_soc_alert(
            title="CRITICAL: Autonomous Isolation", 
            message=alert_body, 
            priority=5, 
            tags="skull,lock,robot"
        )
        
    else:
        # Medium alerts get a human-in-the-loop prompt
        alert_body = f"Suspicious Activity from {target_ip}\n\nAI Analysis:\n{ai_summary}\n\nReview required for isolation."
        send_soc_alert(
            title="MEDIUM: Analyst Review Requested", 
            message=alert_body, 
            priority=3, 
            tags="warning,mag,robot"
        )

    return jsonify({"status": "Alert Processed", "ai_analysis": ai_summary}), 200

if __name__ == '__main__':
    # Binds to 0.0.0.0 so Kibana can reach it across the Docker network
    app.run(host='0.0.0.0', port=5000)
