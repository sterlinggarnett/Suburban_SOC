import asyncio
import asyncssh
import sys
import os

# Formulate the nftables drop command (Task 2.2.1)
# Drops traffic from the specified IP on the OpenWrt input chain.
# Note: For OpenWrt 22.03+, we assume 'inet fw4 input' is the default target chain.
def build_nft_command(attacker_ip: str) -> str:
    return f"nft add rule inet fw4 input ip saddr {attacker_ip} drop"

async def block_ip_on_router(router: dict, attacker_ip: str):
    """
    Connects to a single router and executes the block command. (Task 2.1.1 & 2.2.2)
    """
    ip = router.get("ip_address")
    username = router.get("username", "root")
    key_path = os.path.expanduser(router.get("ssh_key_path", "~/.ssh/id_ed25519_hivemind"))
    
    command = build_nft_command(attacker_ip)
    
    try:
        # Connect asynchronously
        async with asyncssh.connect(
            host=ip,
            username=username,
            client_keys=[key_path],
            known_hosts=None  # In production, configure strict host key checking!
        ) as conn:
            
            # Execute command
            result = await conn.run(command, check=True)
            print(f"[+] Successfully blocked {attacker_ip} on {ip}")
            return True
            
    except asyncssh.Error as exc:
        print(f"[-] SSH connection failed to {ip}: {str(exc)}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[-] Error executing on {ip}: {str(e)}", file=sys.stderr)
        return False

async def dispatch_block_to_all(routers: list, attacker_ip: str):
    """
    Loops through the inventory and fires concurrent SSH block commands. (Task 2.1.2)
    """
    print(f"[*] Dispatching block for {attacker_ip} to {len(routers)} routers...")
    
    # Create a list of async tasks for all routers
    tasks = [block_ip_on_router(r, attacker_ip) for r in routers]
    
    # Run them concurrently (acting as a parallel connection pool)
    results = await asyncio.gather(*tasks)
    
    success_count = sum(1 for r in results if r)
    print(f"[*] Immunization complete: {success_count}/{len(routers)} routers updated.")
    return success_count
