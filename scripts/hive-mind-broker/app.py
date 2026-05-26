from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
import uvicorn
import hmac
import hashlib
import os

from inventory import Inventory
from dispatcher import dispatch_block_to_all

app = FastAPI(title="Hive-Mind Broker")

# Load the router inventory on startup
inv = Inventory("inventory.yaml")

# The secret used for HMAC validation. In production, load from environment variable.
HMAC_SECRET = os.getenv("HIVE_MIND_SECRET", "default_dev_secret").encode('utf-8')

@app.post("/webhook/alert")
async def receive_alert(request: Request, background_tasks: BackgroundTasks):
    """
    Receives webhook payloads from Kibana when a critical alert fires.
    """
    # Verify HMAC signature
    signature_header = request.headers.get("x-elastic-signature")
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing signature header")
    
    # Read the raw body for HMAC verification
    body = await request.body()
    
    # Calculate expected signature
    expected_mac = hmac.new(HMAC_SECRET, body, hashlib.sha256).hexdigest()
    
    # Use hmac.compare_digest to prevent timing attacks
    if not hmac.compare_digest(f"sha256={expected_mac}", signature_header):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse JSON payload
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Extract the attacker IP from the Kibana alert payload
    # Payload structure depends on the specific Kibana Watcher/Alert action
    # For this MVP, we assume {"attacker_ip": "x.x.x.x"} is sent by the webhook
    attacker_ip = payload.get("attacker_ip")
    if not attacker_ip:
        raise HTTPException(status_code=400, detail="Payload missing attacker_ip")

    # Trigger dispatcher in the background so we return a fast 200 OK to Kibana
    routers = inv.get_routers()
    background_tasks.add_task(dispatch_block_to_all, routers, attacker_ip)
    
    print(f"[*] Valid alert received! Attacker IP to block: {attacker_ip}")
    
    return {"status": "success", "message": f"IP {attacker_ip} queued for block across {len(routers)} routers."}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
