"""
Stage 1 — Discovery Module
==========================
Goal: Find every device that is currently ONLINE on your local network,
      along with its IP address and MAC address.

How? We use ARP (Address Resolution Protocol).

  WHAT IS ARP?
  ------------
  On a local network (LAN), computers talk to each other using MAC addresses
  (the physical hardware address of a network card), NOT IP addresses.
  ARP is the "translator" that maps an IP address -> a MAC address.

  The trick we use for discovery:
    1. We broadcast an ARP request to EVERY possible IP in our subnet,
       basically shouting: "Who has IP x.x.x.x? Tell me your MAC!"
    2. Only devices that are ONLINE will reply with their MAC address.
    3. Every reply = one live device. That's our discovery list.

Note: sends raw packets via Npcap. Works without admin if Npcap was installed
in non-restricted mode; otherwise run as Administrator.
"""

import socket
import ipaddress

# scapy.all give us the tools to craft and send raw packets.
# Ether -> builds the Ethernet frame (Layer 2)
# ARP -> builds the ARP request (Layer 3)
# srp -> sends the packet and receives the response at layer 2

from scapy.all import Ether, ARP, srp


def get_local_subnet():
    """
    Figure out which network WE are on, e.g. '192.168.1.0/24'.

    We open a dummy UDP socket to a public IP (we don't actually send data)
    just so the OS tells us which local IP address it would use. From that
    local IP we assume a standard /24 home subnet (256 addresses).

    NOTE: assumes a /24 subnet (true for most home networks).
          TODO: detect the real subnet mask for non-/24 networks.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 8.8.8.8 is Google's public DNS. We never send anything — this just
        # makes the OS pick the interface / local IP it would route through.
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]  # e.g. '192.168.1.42'
    finally:
        s.close()

    # Build a /24 network from our IP. strict=False lets us pass a host IP
    # (like .42) and get back the network address (.0) automatically.
    network = ipaddress.ip_network(local_ip + "/24", strict=False)
    return str(network)   # e.g. '192.168.1.0/24'


def discover_devices(subnet=None):
    """
    Perform the ARP scan and return a list of live devices.

    Returns a list of dicts:  [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff"}, ...]
    """

    if subnet is None:
        subnet = get_local_subnet()

    print(f"[*] Scanning subnet: {subnet}")

    # --- Build the packet we will broadcast ---

    # Layer 2 (Ethernet): destination "ff:ff:ff:ff:ff:ff" = BROADCAST,
    # meaning "send this to EVERY device on the LAN".
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Layer 3 (ARP): pdst = the target IP range we're asking about.
    # op=1 means this is an ARP *request* (the question), not a reply.
    arp = ARP(pdst=subnet)

    # Stack them together into one packet: Ethernet frame carrying an ARP request.
    packet = ether / arp

    # --- Send it and collect the answers ---
    # srp() sends at Layer 2 and waits for replies.
    # iface selects the VirtualBox host-only network adapter.
    # timeout=2 -> wait 2 seconds for devices to answer
    # verbose=0 -> keep scapy quiet (we print our own output)
    # It returns two lists: (answered, unanswered). We only care about answered

    # Wrap the scan so a Npcap/permission failure gives a clean message
    # instead of crashing the whole program with an ugly traceback.
    try:
        answered, _ = srp(
            packet,
            iface="VirtualBox Host-Only Ethernet Adapter",
            timeout=2,
            verbose=0
        )
    except PermissionError:
        # Most common real failure: Npcap in restricted mode / no admin rights.
        print("[!] Permission denied. Try running as Administrator, or check your Npcap install.")
        return []
    except Exception as e:
        # Safety net for anything else (interface down, network unreachable, etc.)
        print(f"[!] Error running ARP scan: {e}")
        return []

    devices = []

    for _sent, received in answered:
        # received.psrc  = the IP that replied
        # received.hwsrc = the MAC address of that device
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
        })

    return devices


def main():
    """Run discovery on its own and print a simple table. Good for testing Stage 1."""
    devices = discover_devices()

    print("\n=== Discovered Devices ===")
    if not devices:
        print("No devices found. Is Npcap installed / are permissions OK?")
        return

    print(f"{'IP Address':<18} {'MAC Address':<20}")
    print("-" * 40)
    for d in devices:
        print(f"{d['ip']:<18} {d['mac']}")
    print(f"\nTotal devices found: {len(devices)}")


# This block only runs when you execute the file directly:
#   python scanner/discovery.py
# It does NOT run when another module imports discover_devices().
if __name__ == "__main__":
    main()