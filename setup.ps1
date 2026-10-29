# ==========================================================================
#  Home Network Scanner - one-step setup (Windows / PowerShell)
# --------------------------------------------------------------------------
#  This sets up everything it can automatically:
#    1. Creates a Python virtual environment (venv)
#    2. Installs all Python dependencies
#    3. Checks for Nmap/Npcap and, if missing, downloads + launches the
#       Nmap installer (which bundles the Npcap driver Scapy needs).
#
#  NOTE: The Npcap DRIVER cannot be installed silently — it needs admin
#  rights and license acceptance. So the installer will open and you must
#  click through it (keep "Npcap" + "WinPcap API-Compatible Mode" checked).
#
#  Run it with:
#     powershell -ExecutionPolicy Bypass -File .\setup.ps1
# ==========================================================================

$ErrorActionPreference = "Stop"

# The Nmap installer to fetch if Nmap isn't found. Bump this if a newer
# version is released (see https://nmap.org/download.html).
$NmapUrl = "https://nmap.org/dist/nmap-7.99-setup.exe"

Write-Host "=== Home Network Scanner setup ===" -ForegroundColor Cyan

# --- 1. Check Python is available -----------------------------------------
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[X] Python not found. Install Python 3 from https://python.org and re-run." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Python found." -ForegroundColor Green

# --- 2. Create the virtual environment ------------------------------------
if (-not (Test-Path ".\venv")) {
    Write-Host "[*] Creating virtual environment (venv)..." -ForegroundColor Cyan
    python -m venv venv
} else {
    Write-Host "[OK] venv already exists." -ForegroundColor Green
}

# --- 3. Install Python dependencies ---------------------------------------
Write-Host "[*] Installing Python dependencies..." -ForegroundColor Cyan
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt
Write-Host "[OK] Python dependencies installed." -ForegroundColor Green

# --- 4. Check Nmap / Npcap ------------------------------------------------
if (Get-Command nmap -ErrorAction SilentlyContinue) {
    Write-Host "[OK] Nmap/Npcap already installed." -ForegroundColor Green
} else {
    Write-Host "[!] Nmap/Npcap not found (needed for scanning + raw packets)." -ForegroundColor Yellow
    $out = Join-Path $env:TEMP "nmap-setup.exe"
    Write-Host "[*] Downloading Nmap installer..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $NmapUrl -OutFile $out
        Write-Host "[*] Launching installer. IMPORTANT: keep 'Npcap' checked, and in the" -ForegroundColor Cyan
        Write-Host "    Npcap step tick 'Install Npcap in WinPcap API-Compatible Mode'." -ForegroundColor Cyan
        Start-Process $out -Wait
        Write-Host "[OK] Installer finished." -ForegroundColor Green
    } catch {
        Write-Host "[X] Could not download the installer automatically." -ForegroundColor Red
        Write-Host "    Please install Nmap manually from https://nmap.org/download.html" -ForegroundColor Red
    }
}

# --- 5. Done --------------------------------------------------------------
Write-Host ""
Write-Host "=== Setup complete ===" -ForegroundColor Green
Write-Host "To run the scanner:" -ForegroundColor Cyan
Write-Host "    .\venv\Scripts\Activate"
Write-Host "    python main.py"
Write-Host ""
Write-Host "(Only scan networks you own. See README for details.)" -ForegroundColor Yellow
