import pytest
from fastapi.testclient import TestClient
import hmac
import hashlib
import json
import os

# Set environment variable before importing app
os.environ["HIVE_MIND_SECRET"] = "test_secret"

from app import app, HMAC_SECRET

client = TestClient(app)

def test_webhook_alert_missing_signature():
    response = client.post("/webhook/alert", json={"attacker_ip": "1.2.3.4"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Missing signature header"

def test_webhook_alert_invalid_signature():
    response = client.post(
        "/webhook/alert",
        json={"attacker_ip": "1.2.3.4"},
        headers={"x-elastic-signature": "invalid_sig"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid signature"

def test_webhook_alert_valid_signature():
    payload = {"attacker_ip": "10.10.10.10"}
    body = json.dumps(payload).encode('utf-8')
    valid_mac = hmac.new(HMAC_SECRET, body, hashlib.sha256).hexdigest()
    
    response = client.post(
        "/webhook/alert",
        data=body,
        headers={"x-elastic-signature": f"sha256={valid_mac}"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "10.10.10.10" in response.json()["message"]

def test_webhook_alert_missing_ip():
    payload = {"some_other_field": "test"}
    body = json.dumps(payload).encode('utf-8')
    valid_mac = hmac.new(HMAC_SECRET, body, hashlib.sha256).hexdigest()
    
    response = client.post(
        "/webhook/alert",
        data=body,
        headers={"x-elastic-signature": f"sha256={valid_mac}"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Payload missing attacker_ip"
