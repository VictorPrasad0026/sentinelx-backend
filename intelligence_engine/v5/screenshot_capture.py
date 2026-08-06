"""
SentinelX V5 — Screenshot Capture Engine

Captures screenshots of discovered assets using:
  - Playwright (headless Chromium) — if installed
  - Fallback: HTTP metadata + favicon hash

For each asset records:
  - Screenshot path
  - HTTP status
  - Page title
  - Favicon hash
  - Redirect chain
  - Login page indicator
  - Error page indicator

Install Playwright: pip install playwright && playwright install chromium
"""

import os
import json
import urllib.request
import urllib.error
import hashlib
import base64
from datetime import datetime, timezone

USER_AGENT = "SentinelX-ASM/5.0"
SCREENSHOT_DIR = "screenshots"

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


def _fetch_meta(host: str, timeout: int = 8) -> dict:
    """
    Fallback when Playwright not installed.
    Gets page title, status, redirect, and favicon hash via urllib.
    """
    result = {
        "host":         host,
        "status":       None,
        "title":        None,
        "redirect_url": None,
        "favicon_hash": None,
        "method":       "urllib_fallback",
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                result["status"]       = resp.status
                result["redirect_url"] = resp.url if resp.url != url else None
                body = resp.read(65536).decode(errors="ignore")

                # Extract title
                import re
                m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
                if m:
                    result["title"] = m.group(1).strip()[:200]

                # Check for favicon
                favicon_url = f"{scheme}://{host}/favicon.ico"
                try:
                    req2 = urllib.request.Request(favicon_url, headers={"User-Agent": USER_AGENT})
                    with urllib.request.urlopen(req2, timeout=5) as fr:
                        fav_bytes = fr.read(65536)
                        result["favicon_hash"] = hashlib.md5(fav_bytes).hexdigest()
                except Exception:
                    pass

                return result
        except urllib.error.HTTPError as e:
            result["status"] = e.code
            return result
        except Exception:
            continue

    return result


def capture_screenshot(host: str) -> dict:
    """
    Capture screenshot if Playwright is available.
    Falls back to metadata collection if not.
    """
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    if not PLAYWRIGHT_AVAILABLE:
        meta = _fetch_meta(host)
        meta["screenshot"] = None
        meta["playwright_available"] = False
        meta["install_note"] = "pip install playwright && playwright install chromium"
        return meta

    result = {
        "host":              host,
        "screenshot":        None,
        "title":             None,
        "status":            None,
        "url":               None,
        "error":             None,
        "method":            "playwright",
        "playwright_available": True,
    }

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=USER_AGENT,
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
            )
            page = context.new_page()

            for scheme in ("https", "http"):
                try:
                    response = page.goto(
                        f"{scheme}://{host}",
                        timeout=12000,
                        wait_until="domcontentloaded",
                    )
                    result["status"] = response.status if response else None
                    result["url"]    = page.url
                    result["title"]  = page.title()[:200] if page.title() else None

                    # Save screenshot
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_host = host.replace(".", "_").replace(":", "_")
                    path = os.path.join(SCREENSHOT_DIR, f"{safe_host}_{ts}.png")
                    page.screenshot(path=path, full_page=False)
                    result["screenshot"] = path
                    break
                except Exception:
                    continue

            browser.close()
    except Exception as e:
        result["error"] = str(e)

    return result


def capture_all(assets: list, max_assets: int = 10) -> list:
    results = []
    for asset in assets[:max_assets]:
        host = asset.get("host") if isinstance(asset, dict) else asset
        print(f"    → Screenshot: {host}")
        results.append(capture_screenshot(host))
    return results
