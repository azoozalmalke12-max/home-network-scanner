"""
Stage 5 — HTML Report Generator
===============================
Goal: Turn the analyzed device data into a styled HTML dashboard you can
      open in a browser (and screenshot for your portfolio).

We use Jinja2 — a templating engine. The idea:
    - We write an HTML "template" with placeholders + loops ({{ }} and {% %}).
    - We feed it our device data.
    - Jinja2 fills in the placeholders -> finished HTML.

The result is saved to report/report.html.
"""

import os
from datetime import datetime

from jinja2 import Template

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(PROJECT_ROOT, "report")


# --- The HTML template (dark "security dashboard" theme, self-contained CSS) ---
TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Home Network Scan Report</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 24px; }
  h1 { margin: 0 0 4px; font-size: 26px; }
  .subtitle { color: #8b949e; margin-bottom: 24px; }
  .cards { display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 18px 24px; min-width: 140px; }
  .card .num { font-size: 32px; font-weight: 700; }
  .card .label { color: #8b949e; font-size: 13px; text-transform: uppercase; letter-spacing: .5px; }
  .num.red { color: #f85149; }
  .num.orange { color: #d29922; }
  .num.green { color: #3fb950; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 10px; overflow: hidden; }
  th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid #30363d; font-size: 14px; vertical-align: top; }
  th { background: #21262d; color: #c9d1d9; text-transform: uppercase; font-size: 12px; letter-spacing: .5px; }
  tr:hover td { background: #1c2128; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 12px; font-weight: 600; }
  .known { background: #1f6f3f; color: #d5ffe0; }
  .unknown { background: #8b1a1a; color: #ffd7d7; }
  .risk { display: block; margin: 3px 0; padding: 3px 8px; border-radius: 5px; font-size: 12px; }
  .CRITICAL { background: #8b1a1a; color: #ffd7d7; }
  .HIGH { background: #a94400; color: #ffe0c7; }
  .MEDIUM { background: #7a6000; color: #fff3c7; }
  .LOW { background: #22343f; color: #c7e2ff; }
  .muted { color: #6e7681; }
  .footer { margin-top: 24px; color: #6e7681; font-size: 12px; }
  code { color: #79c0ff; }
</style>
</head>
<body>
  <h1>🛡️ Home Network Scan Report</h1>
  <div class="subtitle">Generated {{ timestamp }}</div>

  <div class="cards">
    <div class="card"><div class="num">{{ total }}</div><div class="label">Devices</div></div>
    <div class="card"><div class="num red">{{ new_count }}</div><div class="label">New</div></div>
    <div class="card"><div class="num orange">{{ total_risks }}</div><div class="label">Risk Findings</div></div>
    <div class="card"><div class="num green">{{ known }}</div><div class="label">Known</div></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Status</th><th>IP</th><th>MAC</th><th>Hostname</th>
        <th>Vendor</th><th>OS</th><th>Open Ports</th><th>Risks</th>
      </tr>
    </thead>
    <tbody>
    {% for d in devices %}
      <tr>
        <td>
          {% if d.status == "NEW" %}
            <span class="badge unknown">NEW</span>
          {% else %}
            <span class="badge known">known</span>
          {% endif %}
        </td>
        <td><code>{{ d.ip }}</code></td>
        <td><code>{{ d.mac }}</code></td>
        <td>{{ d.hostname }}</td>
        <td>{{ d.vendor }}</td>
        <td>{{ d.os | default("not scanned") }}</td>
        <td>
          {% if d.ports %}
            {% for p in d.ports %}{{ p.port }}/{{ p.service }}{% if not loop.last %}, {% endif %}{% endfor %}
          {% else %}
            <span class="muted">none</span>
          {% endif %}
        </td>
        <td>
          {% if d.risks %}
            {% for r in d.risks %}
              <span class="risk {{ r.severity }}">{{ r.severity }} · port {{ r.port }}: {{ r.reason }}</span>
            {% endfor %}
          {% else %}
            <span class="muted">—</span>
          {% endif %}
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>

  <div class="footer">Home Network Scanner · authorized use on your own network only.</div>
</body>
</html>
"""


def generate_html_report(devices, output=None):
    """
    Render the analyzed devices into an HTML dashboard and save it.

    output=None -> a fresh timestamped file per run, e.g.
                   report/report_2026-07-01_21-30-00.html
    Pass an explicit path to override.

    Returns the path to the written HTML file.
    """
    # Each run gets its own report file, named with the current time.
    if output is None:
        output = os.path.join(REPORT_DIR, f"report_{datetime.now():%Y-%m-%d_%H-%M-%S}.html")

    # Compute the summary numbers shown in the cards.
    total = len(devices)
    new_count = sum(1 for d in devices if d.get("status") == "NEW")
    known = total - new_count
    total_risks = sum(len(d.get("risks", [])) for d in devices)

    html = Template(TEMPLATE).render(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        devices=devices,
        total=total,
        new_count=new_count,
        known=known,
        total_risks=total_risks,
    )

    # Make sure the report/ folder exists, then write the file.
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        f.write(html)

    return output


def main():
    """Test the report with sample data (mimics analyzed devices)."""
    devices = [
        {
            "ip": "192.168.0.1", "mac": "9c:a2:f4:87:67:66",
            "hostname": "Unknown", "vendor": "TP-Link Systems Inc",
            "os": "not scanned", "status": "known",
            "ports": [
                {"port": 22, "state": "open", "service": "ssh"},
                {"port": 80, "state": "open", "service": "http"},
                {"port": 1900, "state": "open", "service": "upnp"},
            ],
            "risks": [
                {"port": 80, "severity": "LOW", "reason": "HTTP — unencrypted web."},
                {"port": 1900, "severity": "MEDIUM", "reason": "UPnP — can auto-open ports."},
            ],
        },
        {
            "ip": "192.168.0.55", "mac": "de:ad:be:ef:00:99",
            "hostname": "Unknown", "vendor": "Unknown",
            "os": "not scanned", "status": "NEW",
            "ports": [{"port": 23, "state": "open", "service": "telnet"}],
            "risks": [{"port": 23, "severity": "CRITICAL", "reason": "Telnet — plaintext passwords."}],
        },
    ]

    path = generate_html_report(devices)
    print(f"Open it in your browser:\n  {path}")


if __name__ == "__main__":
    main()
