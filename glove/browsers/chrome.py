"""Headed-Chrome discovery for the host browser providers.

Leaf module: it depends on neither ``base`` nor ``host_mcp``, so both can import
it at top level without an import cycle. The headed browser glove drives on the
host is discovered here (a system Google Chrome / Chromium, then Playwright's
Chrome for Testing) so the browser feature works on macOS, Linux and Windows
without a hardcoded path.
"""

from __future__ import annotations

import glob
import os

# Well-known system Google Chrome / Chromium install locations, by platform.
SYSTEM_CHROME = (
    # macOS
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    # Linux
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/opt/google/chrome/chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
    # Windows
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "C:/Program Files/Chromium/Application/chrome.exe",
)

# The well-formed fallback path when nothing is discovered on this host, so the
# tmux `chrome` command is still valid (doctor will have warned separately).
DEFAULT_CHROME = SYSTEM_CHROME[0]

# The Chrome for Testing binary (Playwright's managed Chromium build) shipped in
# the ms-playwright cache; the standard headed browser for a no-system-Chrome host.
_CFT_GLOBS = (
    # macOS (chrome-mac / chrome-mac-arm64)
    "~/Library/Caches/ms-playwright/chromium-*/chrome-mac*/*.app/Contents/MacOS/Google Chrome for Testing",
    # Linux
    "~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome",
    # Windows (%USERPROFILE%\AppData\Local\ms-playwright)
    "~/AppData/Local/ms-playwright/chromium-*/chrome-win*/chrome.exe",
)


def chrome_for_testing_path() -> str | None:
    """Newest Playwright-managed Chrome for Testing binary on this host, or None."""
    hits: list[str] = []
    for pat in _CFT_GLOBS:
        hits += glob.glob(os.path.expanduser(pat))
    return sorted(hits)[-1] if hits else None


def discover_chrome() -> tuple[str | None, str]:
    """``(path, kind)`` for the best headed browser on this host.

    ``kind`` is ``"system"`` (a system Google Chrome / Chromium), ``"cft"``
    (Playwright's Chrome for Testing) or ``"none"``. All of them speak CDP on
    ``--remote-debugging-port``, which is what both browser providers attach to.
    Single discovery point, so callers that only need the path and callers that
    need to word a message about *which* backend was found don't rescan.
    """
    for path in SYSTEM_CHROME:
        if os.path.exists(path):
            return path, "system"
    cft = chrome_for_testing_path()
    if cft:
        return cft, "cft"
    return None, "none"


def chrome_executable() -> str | None:
    """Best headed browser on this host, or None."""
    return discover_chrome()[0]
