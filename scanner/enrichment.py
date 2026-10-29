"""
Stage 3 — Enrichment Module
===========================
Goal: Take the raw devices from earlier stages (IP + MAC) and ENRICH them
      with human-readable info about WHAT each device actually is.

Enrichment adds three things to each device:
    1. Hostname  — a readable name, via REVERSE DNS
    2. Vendor    — manufacturer, from the MAC address (DIY OUI lookup)
    3. OS        — operating system, via Nmap -O (optional; needs admin)

  REVERSE DNS (hostname):
  -----------------------
  Every device *can* have a name (e.g. "Johns-iPhone", "router.local").
  We ask the network "what name belongs to this IP?" using reverse DNS.
    Normal DNS:  name -> IP   (google.com -> 142.250.x.x)
    Reverse DNS: IP   -> name (192.168.0.1 -> router.asus.com)
  Not every device answers — many home devices have no name, and that's OK.
"""

import os
import sys
import socket

import nmap   # drives real Nmap for OS detection (-O)

# --- Import our DIY vendor lookup from the utils/ folder ---
# When you run this file directly (python scanner/enrichment.py), Python only
# knows about the scanner/ folder — not the project root. So we add the project
# root to the path so "from utils.vendor_lookup import ..." works.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from utils.vendor_lookup import lookup_vendor


def get_hostname(ip):
    """
    Ask the network "what name belongs to this IP?" using REVERSE DNS.

    Return the hostname string, or "unknown" if the device has no name or does not respond.
    """

    try:
        # gethostbyaddr returns a tuple: (hostname, aliaslist, ipaddrlist)
        # We only want the first item - the hostname.
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    
    except (socket.herror, socket.gaierror):
        # herror/gaierror = no reverse DNS record exists for this IP, or the device didn't respond.
        # Totally normal for phones, IoT devices, etc.
        return "Unknown"
    
    except Exception:
        # Safety net for anything unexpected.
        return "Unknown"


def detect_os(ip):
    """
    Detect the operating system of a device using Nmap's -O flag.

    ⚠️ Requires Administrator privileges (raw packets). Without admin,
       Nmap can't fingerprint the OS and this returns "Unknown".

    Returns a best-guess OS string with confidence %, or "Unknown".
    """
    scanner = nmap.PortScanner()

    try:
        # -O = OS detection. Nmap analyzes how the device responds to crafted
        # packets and guesses the OS, ranking guesses by confidence.
        scanner.scan(hosts=ip, arguments="-O")
    except Exception as e:
        print(f"[!] OS detection failed for {ip}: {e}")
        return "Unknown"

    if ip not in scanner.all_hosts():
        return "Unknown"

    host = scanner[ip]

    # 'osmatch' is a list of guesses, best first. Empty if Nmap couldn't tell.
    if "osmatch" in host and len(host["osmatch"]) > 0:
        best = host["osmatch"][0]           # highest-confidence guess
        return f"{best['name']} ({best['accuracy']}%)"

    return "Unknown"


def enrich_devices(devices, os_detect=False):
    """
    Add "hostname" and "vendor" to each device. Optionally add "os".

    os_detect=False (default) -> hostname + vendor only. Works WITHOUT admin.
    os_detect=True            -> also runs Nmap -O for OS detection.
                                 Slow, and needs Administrator privileges.

    Input : [{"ip": ..., "mac": ...}, ...]
    Output: each device gains "hostname", "vendor" (and "os" if os_detect=True).
    """
    for device in devices:
        device["hostname"] = get_hostname(device["ip"])
        device["vendor"] = lookup_vendor(device["mac"])
        # OS detection is opt-in because it's slow and requires admin.
        if os_detect:
            device["os"] = detect_os(device["ip"])
    return devices


def main():
    """
    Test Stage 3 (hostname part) on its own.

    We fake a small device list here so we can test enrichment without
    running a full discovery scan. Change these IPs to real ones from
    your own discovery output.
    """
    # Sample devices — replace IPs with real ones from YOUR network.
    devices = [
        {"ip": "192.168.0.1",   "mac": "9c:a2:f4:87:67:66"},
        {"ip": "192.168.0.107", "mac": "bc:f4:d4:72:d0:65"},
    ]

    # os_detect=True runs Nmap -O. Requires Administrator PowerShell!
    # Set it to False to test hostname + vendor only (no admin needed).
    devices = enrich_devices(devices, os_detect=True)

    print("\n=== Enriched Devices ===\n")
    print(f"{'IP Address':<16}{'Hostname':<20}{'Vendor':<40}{'OS'}")
    print("-" * 110)
    for d in devices:
        os_info = d.get("os", "not scanned")
        vendor = d["vendor"][:38]   # trim long vendor names so columns stay aligned
        print(f"{d['ip']:<16}{d['hostname']:<20}{vendor:<40}{os_info}")


if __name__ == "__main__":
    main()