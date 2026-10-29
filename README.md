# 🛡️ Home Network Scanner

A Python-based network security scanner that discovers devices on your local network, checks for risky open ports, alerts you when a new device appears, and generates an HTML dashboard report.

> ⚠️ **Authorized use only.** Run this against networks you own or have permission to test. Scanning networks or devices without permission may be illegal. See [Legal & Ethical Use](#-legal--ethical-use).

---

## ✨ Features

- **Device discovery** — ARP scan of the local subnet to find live hosts and their IP and MAC addresses.
- **Port scanning** — automated Nmap scan of the selected top ports on each device.
- **Device enrichment** — attempts to identify each device's hostname and vendor; optional Nmap OS detection is available.
- **Risk analysis** — flags selected open ports, such as Telnet, RDP, SMB, and UPnP, by severity.
- **New-device alerts** — saves a baseline on the first scan, then flags devices that appear for the first time on later scans.
- **Reports** — colored command-line output and an HTML dashboard.
- **Audit logging** — saves timestamped scan logs in `logs/`.
- **Configuration** — scan behavior can be changed through `config/settings.json`.

---

## 🧱 How It Works — the Pipeline

The scanner runs in five stages:

1. **Discovery** — finds online devices using ARP and records their IP and MAC addresses.
2. **Port Scan** — checks selected ports using Nmap.
3. **Enrichment** — attempts to find hostnames and vendor details; OS detection is optional.
4. **Analysis** — compares devices against the saved baseline and reports configured risk findings.
5. **Report** — displays the results in the terminal and creates an HTML dashboard.

---

## 🖼️ Screenshots

Add screenshots here, such as the command-line results and the HTML dashboard.

Example command-line output:

```text
SECURITY ANALYSIS
Classification: 1 known | 0 new

RISK FINDINGS
LOW
192.168.56.101 :22 SSH — ensure strong authentication.
```

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| **Python 3** | Core language |
| **Scapy** | Creates and sends ARP packets for device discovery |
| **python-nmap** | Runs Nmap port scans and optional OS detection |
| **Jinja2** | Generates the HTML dashboard |
| **colorama** | Adds colored terminal output |
| **pyfiglet** | Displays the command-line banner |
| **Nmap + Npcap** | System-level scanning tools and packet capture support |

---

## 📦 Installation

**Prerequisite:** Install Nmap and Npcap. They are system tools and cannot be installed with `pip`. The Nmap Windows installer includes Npcap.

### Option A — Setup script (Windows)

```powershell
git clone <your-repo-url>
cd <repository-folder>
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

The setup script creates a virtual environment and installs the Python dependencies. If Nmap or Npcap is missing, it may open the Nmap installer.

During Npcap installation, keep **Npcap** and **WinPcap API-Compatible Mode** selected.

### Option B — Manual setup

```powershell
# Install Nmap and Npcap from:
# https://nmap.org/download.html

git clone <your-repo-url>
cd <repository-folder>

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

On macOS or Linux, activate the virtual environment with:

```bash
source .venv/bin/activate
```

---

## ▶️ Usage

With the virtual environment activated, run:

```powershell
python main.py
```

The scan runs through the available stages and saves an HTML report in `report/`.

> **First scan:** discovered devices are saved as the baseline.  
> **Later scans:** devices not seen in the baseline are marked as **NEW**.

---

## ⚙️ Configuration

Edit `config/settings.json` to change the scan settings:

```json
{
  "subnet": null,
  "top_ports": 100,
  "timing": "T4",
  "os_detect": false
}
```

- `"subnet": null` attempts to detect a subnet automatically. You can set a specific range, such as `"192.168.0.0/24"`.
- `"top_ports"` sets how many common ports to scan on each device.
- `"timing"` sets the Nmap timing profile, from `T0` (slowest) to `T5` (fastest).
- `"os_detect": true` enables Nmap OS detection. It can take longer and may require Administrator privileges.

---

## 🩺 Troubleshooting

### `WARNING: No libpcap provider available!`

Npcap may not be installed or may not be in WinPcap-compatible mode. Install Nmap and Npcap, make sure **Install Npcap in WinPcap API-Compatible Mode** is selected, then restart PowerShell.

### No devices found

Check that Npcap is installed and that the configured subnet matches the network adapter connected to the devices. Some guest or public Wi-Fi networks isolate connected devices.

### Vendor information is unknown

The vendor lookup may not have a local OUI database, or its download may have failed. The scan can still discover devices and scan their ports without vendor information.

### OS detection shows “not scanned” or fails

Set `"os_detect": true` in `config/settings.json`. Nmap OS detection may require running PowerShell as Administrator and can take longer.

### PowerShell says running scripts is disabled

For the current PowerShell window, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate the virtual environment again:

```powershell
.\.venv\Scripts\Activate.ps1
```

---

## 📁 Project Structure

```text
Home-Network-Scanner/
├── main.py                  # Runs the five-stage pipeline
├── scanner/
│   ├── discovery.py         # Stage 1 — ARP device discovery
│   ├── portscan.py          # Stage 2 — Nmap port scanning
│   ├── enrichment.py        # Stage 3 — hostname, vendor, and optional OS details
│   └── analyzer.py          # Stage 4 — baseline comparison and risk analysis
├── report/
│   └── html_report.py       # Stage 5 — HTML dashboard
├── utils/
│   ├── vendor_lookup.py     # MAC address vendor lookup
│   ├── logger.py            # Timestamped scan logging
│   └── colors.py            # Colored terminal output
├── config/
│   └── settings.json        # Scan settings
├── data/
│   └── known_devices.json   # Saved device baseline
├── logs/                    # Scan logs
├── requirements.txt
└── setup.ps1
```

---

## ⚖️ Legal & Ethical Use

This tool is for authorized security testing and education.

- ✅ Run it on networks and devices you own or have explicit permission to test.
- ❌ Do not scan networks or devices without permission, including public or shared Wi-Fi in cafés, hotels, or offices.

The same scanning techniques can be legitimate on your own network and unauthorized on someone else's.

---

## 🎓 Skills Demonstrated

- Networking fundamentals: **TCP/IP, ARP, MAC addresses, ports, and services**
- Nmap automation and port scanning
- Raw packet creation and transmission with Scapy
- Modular Python development
- Error handling, configuration, and structured logging
- Security concepts: **attack surface, risk analysis, baseline tracking, authorization, and ethics**