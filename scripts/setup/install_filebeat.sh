#!/bin/bash
# Install Filebeat 9.x — matches ELK stack version (9.3.2)
# Run with: sudo bash scripts/setup/install_filebeat.sh

set -e

echo "[INFO] Installing Filebeat 9.x..."

# Import Elastic GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg

# Install prerequisite
sudo apt-get install -y apt-transport-https

# Add Elastic 9.x APT repository
echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/elastic-9.x.list

# Install Filebeat
sudo apt-get update && sudo apt-get install -y filebeat

echo "[PASS] Filebeat installed: $(filebeat version 2>/dev/null | head -1)"
echo "[INFO] Next: apply config and start with soc_pipeline.sh -> [6] SOP-002"
