"""
inventory.py — loads the per-tenant router inventory (inventory.yaml).

WS0.3 tenant isolation: get_routers_for_tenant() returns only a given
tenant's routers, so the broker never broadcasts a block across tenants.
"""

import yaml
import os
import logging

logger = logging.getLogger(__name__)


class Inventory:
    def __init__(self, filepath="inventory.yaml"):
        if filepath == "inventory.yaml" and not os.path.exists(filepath):
            alt = os.path.join(os.path.dirname(__file__), filepath)
            if os.path.exists(alt):
                filepath = alt
        self.filepath = filepath
        self.routers = []
        self.load()

    def load(self):
        if not os.path.exists(self.filepath):
            logger.warning("Inventory file not found: %s", self.filepath)
            return

        with open(self.filepath, 'r') as f:
            data = yaml.safe_load(f)
            if data and 'routers' in data:
                self.routers = data['routers']

        logger.info("Loaded %d routers from inventory.", len(self.routers))

    def get_routers(self):
        return self.routers

    def get_routers_for_tenant(self, tenant):
        """Return only the routers belonging to *tenant* (WS0.3).

        Tenant isolation: a block must never reach another tenant's router. An
        unknown tenant — or routers with no `tenant` field — yields an empty list,
        so the caller dispatches to nothing rather than broadcasting.
        """
        if not tenant:
            return []
        return [r for r in self.routers if r.get("tenant") == tenant]

# Quick test if run directly
if __name__ == "__main__":
    inv = Inventory()
    for r in inv.get_routers():
        print(f"Router ID: {r['id']}, Tenant: {r.get('tenant')}, IP: {r['ip_address']}")
