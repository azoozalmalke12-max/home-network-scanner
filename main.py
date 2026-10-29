"""
Home Network Scanner — main.py
==============================
The ORCHESTRATOR. This ties all five stages into one pipeline:

    1. Discovery   -> find devices (IP + MAC)          [scanner/discovery.py]
    2. Port scan   -> open ports per device            [scanner/portscan.py]
    3. Enrichment  -> hostname + vendor + (OS)         [scanner/enrichment.py]
    4. Analyzer    -> known/unknown + risk flags       [scanner/analyzer.py]
    5. Report      -> HTML dashboard                   [report/html_report.py]  (added last)

Run from the project root:
    python main.py

⚠️ AUTHORIZATION: Only run against your OWN network (your home). Scanning other
   people's devices without permission can be illegal.
"""

import os
import sys
import json
from datetime import datetime

# Make Unicode output (emojis, box chars, "—") safe on ANY Windows console,
# not just UTF-8 terminals. Must run BEFORE colorama wraps stdout below.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Because main.py lives in the project root, Python can find the scanner/ and
# utils/ packages directly. Each stage exposes one simple function we call here.
from scanner.discovery import discover_devices
from scanner.portscan import scan_devices
from scanner.enrichment import enrich_devices
from scanner.analyzer import analyze_devices
from report.html_report import generate_html_report
from utils.logger import get_logger, LOG_FILE
from utils.colors import red, green, cyan, grey, bold, severity_color

# One shared logger for the whole scan. Writes to console + logs/scan.log.
log = get_logger()

# Where the config file lives.
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "settings.json")

# Sensible defaults, used if settings.json is missing or a key is absent.
DEFAULT_SETTINGS = {
    "subnet": None,       # None = auto-detect your local subnet
    "top_ports": 100,     # how many top ports to scan per device
    "timing": "T4",       # Nmap timing template (T0 slow ... T5 fastest)
    "os_detect": False,   # OS detection (needs admin, slower)
}


def load_settings():
    """
    Load scan settings from config/settings.json, falling back to defaults
    for any missing file or key. This lets you change scan behavior WITHOUT
    editing code.
    """
    settings = dict(DEFAULT_SETTINGS)   # start from defaults
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            user_settings = json.load(f)
        settings.update(user_settings)  # override defaults with file values
    except FileNotFoundError:
        log.warning("settings.json not found — using default settings.")
    except json.JSONDecodeError as e:
        log.warning(f"settings.json is invalid ({e}) — using default settings.")
    return settings


BAR = "=" * 70          # heavy separator
SUB = "-" * 70          # light separator

# Order risk findings most-severe first.
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def ip_key(ip):
    """Turn '192.168.0.10' into (192,168,0,10) so IPs sort NUMERICALLY, not as text."""
    return tuple(int(o) for o in ip.split("."))


def print_banner():
    """Framed box with a BIG ASCII-art title inside + a small tagline beneath."""
    subtitle = "Discover · Enumerate · Analyze · Report"

    # Build the big title as ASCII art (fall back to plain text if unavailable).
    try:
        from pyfiglet import Figlet
        fig = Figlet(font="small")
        art = (fig.renderText("HOME NETWORK") + fig.renderText("SCANNER")).rstrip("\n")
        title_lines = art.split("\n")
    except Exception:
        title_lines = ["HOME NETWORK SCANNER"]

    # Size the box to fit the widest line, with padding.
    inner = max(max(len(l) for l in title_lines), len(subtitle)) + 6
    edge = "═" * inner

    print(cyan("╔" + edge + "╗"))
    print(cyan("║") + " " * inner + cyan("║"))
    for ln in title_lines:                              # big block-letter title
        print(cyan("║") + bold(cyan(ln.center(inner))) + cyan("║"))
    print(cyan("║") + " " * inner + cyan("║"))
    print(cyan("║") + grey(subtitle.center(inner)) + cyan("║"))   # small tagline
    print(cyan("║") + " " * inner + cyan("║"))
    print(cyan("╚" + edge + "╝"))


def print_inventory(devices):
    """
    Stage 3 output — the DEVICE INVENTORY: what devices are on the network and
    what each one IS (hostname, vendor, how many open ports). No security
    judgment yet — that's Stage 4's job.
    """
    print(bold(cyan(f"\nDEVICE INVENTORY ({len(devices)} found)")))
    print(grey(SUB))
    print(bold(f"{'IP':<15} {'MAC':<19} {'HOSTNAME':<17} {'PORTS':<6} VENDOR"))
    for d in sorted(devices, key=lambda x: ip_key(x["ip"])):
        host = d["hostname"] if d["hostname"] != "Unknown" else "-"
        vendor = d["vendor"] if d["vendor"] != "Unknown" else "-"
        n_ports = len(d.get("ports", []))
        print(f"{d['ip']:<15} {d['mac']:<19} {host:<17} {n_ports:<6} {vendor[:24]}")


def print_analysis(devices):
    """
    Stage 4 output — the SECURITY ANALYSIS: classify known vs unknown, list the
    unknown devices (the alert), and show risk findings worst-first.
    """
    total = len(devices)
    new_devices = [d for d in devices if d["status"] == "NEW"]
    known = total - len(new_devices)
    all_risks = [(d, r) for d in devices for r in d["risks"]]

    print(bold(cyan("\nSECURITY ANALYSIS")))
    print(grey(SUB))
    # Plain-language explanation so a first-time user understands the labels.
    print(grey("  known = seen on a previous scan (already in your baseline)"))
    print(grey("  NEW   = first time this device has appeared — worth checking!"))
    print()
    new_label = red(f"{len(new_devices)} new") if new_devices else green("0 new")
    print(f"Classification : {green(str(known) + ' known')} | {new_label}")

    # List the NEW devices — this is the "alert on new devices" feature.
    if new_devices:
        print(red(f"\n⚠  NEW devices detected ({len(new_devices)}):"))
        for d in sorted(new_devices, key=lambda x: ip_key(x["ip"])):
            vendor = d["vendor"] if d["vendor"] != "Unknown" else "vendor unknown"
            print(red(f"   {d['ip']:<15} {d['mac']:<19} {vendor[:24]}"))

    # Risk findings, GROUPED by severity (Critical -> High -> Medium -> Low).
    print(bold(cyan(f"\nRISK FINDINGS ({len(all_risks)})")))
    print(grey(SUB))
    if not all_risks:
        print(green("None — no risky ports detected. ✅"))
    else:
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            group = [dr for dr in all_risks if dr[1]["severity"] == severity]
            group.sort(key=lambda dr: ip_key(dr[0]["ip"]))
            # Color the severity header; grey it out when the group is empty.
            header = f"{severity} ({len(group)})"
            print("\n" + (severity_color(severity, header) if group else grey(header)))
            if not group:
                print(grey("   (none)"))
            else:
                for d, r in group:
                    print(severity_color(severity, f"   {d['ip']:<15} :{r['port']:<5} {r['reason']}"))

    # Final summary line.
    print(grey("\n" + SUB))
    summary = f"SUMMARY: {total} devices | {len(new_devices)} new | {len(all_risks)} risk findings"
    print(bold(summary))
    print(cyan(BAR))


def main():
    print_banner()
    print(grey(f"Scan started: {datetime.now():%Y-%m-%d %H:%M:%S}"))
    log.info("=== Scan started ===")

    # Load config (subnet, top_ports, timing, os_detect) from settings.json.
    settings = load_settings()
    os_detect = settings["os_detect"]
    # Build the Nmap arguments string from the config, e.g. "-T4 --top-ports 100".
    scan_args = f"-{settings['timing']} --top-ports {settings['top_ports']}"

    # Stage 1 — Discovery
    print(bold("\n[Stage 1] Discovering devices (ARP scan)..."))
    devices = discover_devices(subnet=settings["subnet"])
    if not devices:
        log.warning("No devices found. Exiting.")
        return
    log.info(f"Discovery complete: {len(devices)} devices found.")

    # Stage 2 — Port scan
    print(bold("\n[Stage 2] Scanning ports on each device..."))
    devices = scan_devices(devices, arguments=scan_args)

    # Stage 3 — Enrichment (hostname + vendor + optional OS)
    print(bold("\n[Stage 3] Enriching devices (hostname + vendor" +
          (" + OS" if os_detect else "") + ")..."))
    devices = enrich_devices(devices, os_detect=os_detect)
    print_inventory(devices)   # show WHAT was found

    # Stage 4 — Analysis (known/unknown + risk flags)
    print(bold("\n[Stage 4] Analyzing (known/unknown + risks)..."))
    devices = analyze_devices(devices)

    # Log the security-relevant findings so they're saved in scan.log.
    for d in devices:
        if d["status"] == "NEW":
            log.warning(f"NEW device: {d['ip']} ({d['mac']}) vendor={d['vendor']}")
        for r in d["risks"]:
            log.warning(f"RISK [{r['severity']}] {d['ip']} port {r['port']}: {r['reason']}")

    print_analysis(devices)    # show the SECURITY verdict
    log.info("=== Scan finished ===")

    # Stage 5 — HTML dashboard
    report_path = generate_html_report(devices)
    log.info(f"HTML report generated: {report_path}")

    # --- Clean output footer ---
    print(bold(green("\n✅ Scan complete")))
    print(grey("   HTML report : ") + report_path)
    print(grey("   Scan log    : ") + LOG_FILE)
    print(grey("   Open the HTML report in your browser to view the dashboard."))


if __name__ == "__main__":
    main()
