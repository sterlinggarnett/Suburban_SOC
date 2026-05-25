import yaml
import os

class Inventory:
    def __init__(self, filepath="inventory.yaml"):
        self.filepath = filepath
        self.routers = []
        self.load()

    def load(self):
        if not os.path.exists(self.filepath):
            print(f"[!] Inventory file not found: {self.filepath}")
            return
        
        with open(self.filepath, 'r') as f:
            data = yaml.safe_load(f)
            if data and 'routers' in data:
                self.routers = data['routers']
        
        print(f"[*] Loaded {len(self.routers)} routers from inventory.")

    def get_routers(self):
        return self.routers

# Quick test if run directly
if __name__ == "__main__":
    inv = Inventory()
    for r in inv.get_routers():
        print(f"Router ID: {r['id']}, IP: {r['ip_address']}")
