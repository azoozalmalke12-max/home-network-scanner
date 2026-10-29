"""
Stage 4 — Analyzer Module
=========================
Goal: Turn raw scan data into INSIGHT. Two jobs:

  1. KNOWN vs NEW  (auto-baseline / "first-seen" detection)
     Instead of making you hand-type every device's MAC, the scanner LEARNS
     your network automatically:
        - First scan  -> save every device as the BASELINE ("this is normal").
                         Nothing is flagged; we're just recording what's here.
        - Later scans -> compare against the baseline.
                         Seen before -> "known".  Brand new -> "NEW" (alert!).
     New devices are then added to the baseline, so you're alerted ONCE when
     something first appears. This makes "alert on unknown devices" actually
     useful — you don't need to know any MAC addresses up front.

  2. RISK FLAGS
     Look at each device's open ports and flag the risky ones (Telnet sends
     passwords in plaintext, RDP is a ransomware target, etc.).

The baseline is stored in data/known_devices.json (auto-managed).
"""

import os
import json
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KNOWN_FILE = os.path.join(PROJECT_ROOT, "data", "known_devices.json")


# --- Risk knowledge base: which ports are risky, and why ---
# severity: "CRITICAL" > "HIGH" > "MEDIUM" > "LOW"
RISKY_PORTS = {
    23:   ("CRITICAL", "Telnet — sends passwords in PLAINTEXT. Should be disabled."),
    21:   ("HIGH",     "FTP — often unencrypted file transfer."),
    3389: ("HIGH",     "RDP — #1 target for ransomware brute-force attacks."),
    5900: ("HIGH",     "VNC — remote screen, often left unprotected."),
    445:  ("MEDIUM",   "SMB — file sharing; exploited by WannaCry (EternalBlue)."),
    139:  ("MEDIUM",   "NetBIOS — legacy Windows networking, info leak risk."),
    1900: ("MEDIUM",   "UPnP — can auto-open ports; common attack vector."),
    80:   ("LOW",      "HTTP — unencrypted web (login credentials exposed)."),
    22:   ("LOW",      "SSH — powerful remote access; ensure strong auth."),
}


def _load_baseline_data(path=KNOWN_FILE):
    """Read the baseline file, returning the parsed dict (or a fresh one)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Missing or empty/blank file -> treat as a fresh baseline (first run).
        return {"known_devices": []}


def load_baseline(path=KNOWN_FILE):
    """Return the set of MAC addresses already in the baseline (lowercased)."""
    data = _load_baseline_data(path)
    return {d["mac"].lower() for d in data.get("known_devices", [])}


def update_baseline(devices, path=KNOWN_FILE):
    """
    Add any devices NOT already in the baseline to it (with a first-seen time),
    then save. Returns how many new devices were added.
    """
    data = _load_baseline_data(path)
    known = data.get("known_devices", [])
    existing = {d["mac"].lower() for d in known}

    added = 0
    for device in devices:
        mac = device["mac"].lower()
        if mac not in existing:
            hostname = device.get("hostname", "")
            known.append({
                "mac": mac,
                "name": hostname if hostname and hostname != "Unknown" else "",
                "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
            existing.add(mac)
            added += 1

    with open(path, "w", encoding="utf-8") as f:
        json.dump({"known_devices": known}, f, indent=2)

    return added


def assess_risks(device):
    """
    Look at a device's open ports and return a list of risk findings.
    Each finding: {"port": 23, "severity": "CRITICAL", "reason": "..."}
    """
    findings = []
    # device may not have "ports" if the port scan wasn't run — default to [].
    for p in device.get("ports", []):
        port = p["port"]
        if port in RISKY_PORTS:
            severity, reason = RISKY_PORTS[port]
            findings.append({
                "port": port,
                "severity": severity,
                "reason": reason,
            })
    return findings


def analyze_devices(devices, baseline_path=KNOWN_FILE):
    """
    Classify each device (known vs NEW) using the auto-baseline, and attach
    risk findings. Then update the baseline with any newly-seen devices.

    Adds to each device:
        "status" -> "known" or "NEW"
        "risks"  -> list of risk findings
    """
    baseline = load_baseline(baseline_path)
    first_run = len(baseline) == 0   # empty baseline => this is the learning run

    for device in devices:
        mac = device["mac"].lower()
        # On the first run we baseline everything (no false alarms). After that,
        # anything not already known is a genuinely NEW arrival.
        if first_run or mac in baseline:
            device["status"] = "known"
        else:
            device["status"] = "NEW"
        device["risks"] = assess_risks(device)

    # Remember what we saw for next time.
    added = update_baseline(devices, baseline_path)
    if first_run:
        print(f"[*] First run: baseline created with {added} device(s). All marked 'known'.")
    elif added:
        print(f"[*] {added} NEW device(s) detected and added to the baseline.")

    return devices


def main():
    """
    Test Stage 4 with sample devices. Run twice to see auto-baseline in action:
    the first run baselines everyone; a second run with a new MAC flags it NEW.
    """
    devices = [
        {
            "ip": "192.168.0.1", "mac": "9c:a2:f4:87:67:66",
            "hostname": "Unknown", "vendor": "TP-Link",
            "ports": [
                {"port": 22, "state": "open", "service": "ssh"},
                {"port": 80, "state": "open", "service": "http"},
                {"port": 1900, "state": "open", "service": "upnp"},
            ],
        },
        {
            "ip": "192.168.0.55", "mac": "de:ad:be:ef:00:99",
            "hostname": "Unknown", "vendor": "Unknown",
            "ports": [{"port": 23, "state": "open", "service": "telnet"}],
        },
    ]

    devices = analyze_devices(devices)

    print("\n=== Analysis Report ===\n")
    for d in devices:
        flag = "🚨" if d["status"] == "NEW" else "✅"
        print(f"{flag} {d['ip']:<15} [{d['status']}]  {d['vendor']}")
        for r in d["risks"]:
            print(f"     ⚠️  {r['severity']:<9} port {r['port']}: {r['reason']}")
        print()


if __name__ == "__main__":
    main()
