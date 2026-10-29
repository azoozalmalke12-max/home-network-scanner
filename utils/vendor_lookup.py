"""
utils/vendor_lookup.py
======================
DIY vendor lookup: map a MAC address to its manufacturer using the
official IEEE OUI database (no external library — we parse it ourselves).

  HOW IT WORKS
  ------------
  A MAC address:      9C:A2:F4:87:67:66
                      └──────┘
                      OUI (first 3 bytes) = manufacturer ID assigned by IEEE

  IEEE publishes a public text file mapping every OUI -> company name.
  We download it once, cache it locally, parse it into a dictionary,
  and then look up the first 3 bytes of any MAC to find the vendor.
"""

import os
import urllib.request

# IEEE's official OUI database (public, free). ~4-5 MB text file.
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

# Where we cache the downloaded file. We build an absolute path so it works
# no matter which folder you run the script from.
#   __file__ = .../utils/vendor_lookup.py
#   dirname(__file__) = .../utils
#   go up one level (..) to the project root, then into data/
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUI_FILE = os.path.join(PROJECT_ROOT, "data", "oui.txt")

# Module-level cache so we only parse the big file ONCE per program run.
_oui_map = None


def _download_oui_file():
    """Download the IEEE OUI file to data/oui.txt (only if we don't have it)."""
    print("[*] OUI database not found locally. Downloading from IEEE (one-time)...")
    try:
        # IEEE's server blocks requests with no User-Agent (returns HTTP 418).
        # We add a browser-like User-Agent header so the download is accepted.
        req = urllib.request.Request(
            OUI_URL,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read()

        # Make sure the data/ folder exists, then write the file.
        os.makedirs(os.path.dirname(OUI_FILE), exist_ok=True)
        with open(OUI_FILE, "wb") as f:
            f.write(data)

        print("[*] Download complete.")
    except Exception as e:
        print(f"[!] Could not download OUI file: {e}")


def _load_oui_map():
    """
    Parse data/oui.txt into a dict:  { "9CA2F4": "ASUSTek COMPUTER INC.", ... }

    The IEEE file has lines that look like:
        9C-A2-F4   (hex)		ASUSTek COMPUTER INC.
    We only care about the lines containing "(hex)".
    """
    oui_map = {}

    # Download the file the first time if it's missing.
    if not os.path.exists(OUI_FILE):
        _download_oui_file()

    if not os.path.exists(OUI_FILE):
        # Download failed — return empty map so lookups just say "Unknown".
        return oui_map

    # Read and parse. encoding/errors set to survive odd characters.
    with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" in line:
                # Example line: "9C-A2-F4   (hex)\t\tASUSTek COMPUTER INC."
                parts = line.split("(hex)")
                prefix = parts[0].strip()              # "9C-A2-F4"
                vendor = parts[1].strip()              # "ASUSTek COMPUTER INC."
                # Normalize the prefix: remove dashes, uppercase -> "9CA2F4"
                key = prefix.replace("-", "").upper()
                oui_map[key] = vendor

    return oui_map


def lookup_vendor(mac):
    """
    Given a MAC address, return the manufacturer name (or "Unknown").

    Example: lookup_vendor("9c:a2:f4:87:67:66") -> "ASUSTek COMPUTER INC."
    """
    global _oui_map

    # Load & parse the file only once, then reuse it for every lookup.
    if _oui_map is None:
        _oui_map = _load_oui_map()

    # Take the first 3 bytes of the MAC and normalize to match our keys.
    # "9c:a2:f4:87:67:66" -> remove ":" -> "9CA2F4876766" -> first 6 chars -> "9CA2F4"
    clean = mac.replace(":", "").replace("-", "").upper()
    oui_key = clean[:6]

    return _oui_map.get(oui_key, "Unknown")


def main():
    """Quick test of the vendor lookup on a few sample MACs."""
    test_macs = [
        "9c:a2:f4:87:67:66",   # a real MAC from your router
        "bc:f4:d4:72:d0:65",   # a randomized phone MAC (likely "Unknown")
        "00:1a:11:00:00:00",   # Google
    ]

    print("\n=== Vendor Lookup Test ===")
    for mac in test_macs:
        print(f"{mac}  ->  {lookup_vendor(mac)}")


if __name__ == "__main__":
    main()