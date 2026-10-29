"""
Stage 2 - Port Scanner Module
=============================

Goal: For each device we discovered in Stage 1, find out which TCP ports are OPEN, 
      and which SERVICE is running behind each open port.

    WHAT IS A PORT?
    -----------------
    A port is a "door" into a device. Each service (like a web server, SSH server, etc.)
    PORTS are its numbered doors (0-65535).

    Each open door usually means a running service:
        22 -> SSH (remote login)
        80 -> HTTP (web server)
        443 -> HTTPS (secure web server)
        445 -> SMB (file sharing)
        3389 -> RDP (remote desktop)
    Open ports tell us WHAT a device does, and which doors might be risky.

    We don't scan ports by hand. We AUTOMATE Nmap, the world's most popular port scanner through the python-nmap library. 
    Nmap is a powerful tool that can scan ports, detect services, and even identify operating systems.

    AUTHORIZATION: Only run this against devices YOU OWN (Your home Network).
    Port scanning other people's devices without permission is illegal and unethical.
"""

import nmap  # the python-nmap library is a wrapper for the Nmap tool

def scan_ports(ip, arguments="-T4 --top-ports 100"):
    """
    Scan one device (by IP) and return its open TCP ports + the services on them.

    Arguments explained:
      -T4             : timing/speed (0=slow/stealthy ... 5=insanely fast). 4 = fast, reliable.
      --top-ports 100 : scan the 100 most common ports (instead of all 65,535).

    Returns a list of dicts:
        [{"port": 80, "state": "open", "service": "http"}, ...]
    """
    scanner = nmap.PortScanner()  # this object talks to the installed Nmap program
    print(f"[*] Scanning {ip} for open ports...")

    try:
        # Kick off the actual Nmap scan. This blocks until Nmap finishes.
        scanner.scan(hosts=ip, arguments=arguments)
    except nmap.PortScannerError as e:
        # Usually means Nmap isn't installed or isn't on PATH.
        print(f"[!] Nmap error scanning {ip}: {e}")
        return []
    except Exception as e:
        print(f"[!] Unexpected error scanning {ip}: {e}")
        return []

    # If the host didn't respond at all, it won't be in the scan results.
    if ip not in scanner.all_hosts():
        return []

    host = scanner[ip]
    open_ports = []

    # The 'tcp' key only exists if Nmap probed any TCP ports on this host.
    if "tcp" in host:
        # host["tcp"] is a dict: { port_number: {info...}, ... }
        for port, info in host["tcp"].items():
            if info["state"] == "open":
                open_ports.append({
                    "port": port,
                    "state": info["state"],
                    "service": info.get("name") or "unknown",  # e.g. 'http', 'ssh'
                })

    # Sort by port number so the output is easier to read.
    open_ports.sort(key=lambda p: p["port"])
    return open_ports

def scan_devices(devices, arguments=None):
    """
    Take the device list from Stage 1 (discovery) and add open-port info to each.

    arguments: optional Nmap args (e.g. "-T4 --top-ports 100"). If None, each
               device is scanned with scan_ports' own default.

    Input : [{"ip": ..., "mac": ...}, ...]
    Output: same list, but each device gains a "ports" key:
            [{"ip":..., "mac":..., "ports":[{port,state,service}, ...]}, ...]
    """
    for device in devices:
        if arguments:
            device["ports"] = scan_ports(device["ip"], arguments)
        else:
            device["ports"] = scan_ports(device["ip"])
    return devices


def main():
    """
    Test Stage 2 on its own. Scans a single device (default: the router).
    Change 'target' to any device IP from your discovery scan.
    Only scan devices you own.
    """
    target = "192.168.0.1"  # your home router

    ports = scan_ports(target)

    print(f"\n=== Open Ports on {target} ===\n")
    if not ports:
        print("No open ports found. Is Nmap installed and on your PATH? (or host did not respond)")
        return

    print(f"{'Port':<8} {'State':<10} {'Service'}")
    print("-" * 30)
    for p in ports:
        print(f"{p['port']:<8} {p['state']:<10} {p['service']}")


if __name__ == "__main__":
    main()