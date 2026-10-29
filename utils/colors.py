"""
utils/colors.py — tiny color helper for clean, professional CLI output.
=======================================================================
We use `colorama` so ANSI colors work on Windows terminals too (it also
resets colors automatically so they don't "bleed" into later text).

Usage:
    from utils.colors import red, green, cyan, bold, severity_color
    print(red("danger"))
    print(bold(cyan("A HEADER")))
"""

from colorama import Fore, Style, init

# init() enables ANSI color handling on Windows (no-op on Linux/macOS).
init()


def _wrap(text, code):
    """Wrap text in a color code and always reset afterwards."""
    return f"{code}{text}{Style.RESET_ALL}"


# --- Basic colors ---
def red(t):     return _wrap(t, Fore.RED + Style.BRIGHT)
def green(t):   return _wrap(t, Fore.GREEN)
def yellow(t):  return _wrap(t, Fore.YELLOW)
def cyan(t):    return _wrap(t, Fore.CYAN)
def magenta(t): return _wrap(t, Fore.MAGENTA)
def grey(t):    return _wrap(t, Style.DIM)
def bold(t):    return _wrap(t, Style.BRIGHT)


# --- Severity -> color, so risk levels are instantly readable ---
_SEVERITY = {
    "CRITICAL": lambda t: _wrap(t, Fore.RED + Style.BRIGHT),
    "HIGH":     magenta,
    "MEDIUM":   yellow,
    "LOW":      cyan,
}


def severity_color(severity, text=None):
    """Colorize text by risk severity. If text is None, colorize the label itself."""
    fn = _SEVERITY.get(severity, lambda t: t)
    return fn(text if text is not None else severity)


def main():
    """Preview all the colors — run this to check your terminal supports them."""
    print(bold(cyan("=== Color Preview ===")))
    print(green("known device (green)"))
    print(red("NEW device (red)"))
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(severity_color(sev, f"{sev} — example risk line"))
    print(grey("dim/secondary text"))
    print(bold("bold header text"))


if __name__ == "__main__":
    main()
