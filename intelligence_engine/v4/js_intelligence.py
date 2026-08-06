"""
SentinelX V4 — JavaScript Intelligence Engine

Downloads JS files from discovered assets and extracts:
  - Hidden API endpoints
  - Hardcoded secrets / tokens / keys
  - Internal domain references
  - Cloud bucket references
  - Version strings
"""

import re
import urllib.request
import urllib.error
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed

USER_AGENT = "SentinelX-ASM/4.0"

# Secret patterns — ordered from most to least specific
SECRET_PATTERNS = {
    "AWS_ACCESS_KEY":      r"AKIA[0-9A-Z]{16}",
    "AWS_SECRET_KEY":      r"aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key['\"\s:=]+([A-Za-z0-9/+=]{40})",
    "GOOGLE_API_KEY":      r"AIza[0-9A-Za-z\\-_]{35}",
    "FIREBASE_KEY":        r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "STRIPE_KEY":          r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24}",
    "GITHUB_TOKEN":        r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "SLACK_TOKEN":         r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
    "SENDGRID_KEY":        r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "BASIC_AUTH_URL":      r"https?://[a-zA-Z0-9_\-]+:[^@\s]{6,}@",
    "PRIVATE_KEY_HEADER":  r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "JWT_TOKEN":           r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "GENERIC_API_KEY":     r"['\"]?api[_\-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
    "GENERIC_SECRET":      r"['\"]?secret['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{10,})['\"]",
    "GENERIC_TOKEN":       r"['\"]?token['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
    "S3_BUCKET":           r"[a-z0-9\-]+\.s3\.amazonaws\.com",
    "GCS_BUCKET":          r"storage\.googleapis\.com/[a-z0-9\-]+",
    "INTERNAL_IP":         r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
}

ENDPOINT_PATTERNS = [
    r"""(?:url|endpoint|api|path|route)\s*[:=]\s*['"`]([/][a-zA-Z0-9_/\-\.]+)['"`]""",
    r"""fetch\(['"`]([/][a-zA-Z0-9_/\-\.?=&]+)['"`]\)""",
    r"""axios\.(get|post|put|delete)\(['"`]([/][a-zA-Z0-9_/\-\.?=&]+)['"`]\)""",
    r"""['"`](/api/[a-zA-Z0-9_/\-\.?=&]+)['"`]""",
]


class ScriptTagParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.script_srcs = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            for name, val in attrs:
                if name == "src" and val:
                    self.script_srcs.append(val)


def fetch_text(url: str, max_bytes: int = 500_000) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read(max_bytes).decode(errors="ignore")
    except Exception:
        return ""


def extract_js_urls(html: str, base_url: str) -> list:
    parser = ScriptTagParser()
    parser.feed(html)
    urls = []
    for src in parser.script_srcs:
        if src.startswith("http"):
            urls.append(src)
        elif src.startswith("//"):
            urls.append("https:" + src)
        elif src.startswith("/"):
            urls.append(base_url.rstrip("/") + src)
    return urls[:20]   # cap at 20 JS files


def scan_js_content(js_content: str) -> dict:
    secrets = []
    endpoints = []
    internal_ips = []

    for name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches[:3]:   # max 3 per type
            value = match if isinstance(match, str) else match[0] if match else ""
            if len(value) > 6:
                secrets.append({
                    "type":     name,
                    "snippet":  value[:60] + "..." if len(value) > 60 else value,
                    "severity": "CRITICAL" if name in (
                        "AWS_ACCESS_KEY", "PRIVATE_KEY_HEADER", "STRIPE_KEY",
                        "GITHUB_TOKEN", "BASIC_AUTH_URL"
                    ) else "HIGH",
                })
                if name == "INTERNAL_IP":
                    internal_ips.append(value)

    for pattern in ENDPOINT_PATTERNS:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches[:10]:
            ep = match[-1] if isinstance(match, tuple) else match
            if len(ep) > 2 and ep not in endpoints:
                endpoints.append(ep)

    return {
        "secrets":      secrets,
        "endpoints":    endpoints[:30],
        "internal_ips": list(set(internal_ips)),
    }


def analyze_asset_js(host: str) -> dict:
    base_url = f"https://{host}"
    html = fetch_text(base_url)
    if not html:
        html = fetch_text(f"http://{host}")

    js_urls = extract_js_urls(html, base_url)

    all_secrets   = []
    all_endpoints = []
    all_ips       = []

    def scan_url(url):
        content = fetch_text(url)
        if content:
            return url, scan_js_content(content)
        return url, None

    with ThreadPoolExecutor(max_workers=5) as ex:
        jobs = {ex.submit(scan_url, url): url for url in js_urls}
        for future in as_completed(jobs):
            url, result = future.result()
            if result:
                all_secrets.extend(result["secrets"])
                all_endpoints.extend(result["endpoints"])
                all_ips.extend(result["internal_ips"])

    all_endpoints = list(set(all_endpoints))
    all_ips       = list(set(all_ips))

    findings = []
    for secret in all_secrets:
        findings.append({
            "issue":    f"Secret in JavaScript: {secret['type']}",
            "severity": secret["severity"],
            "evidence": secret["snippet"],
        })
    if all_ips:
        findings.append({
            "issue":    f"Internal IPs exposed in JS: {all_ips}",
            "severity": "HIGH",
            "evidence": f"Private IP ranges found in client-side code",
        })

    return {
        "host":            host,
        "js_files_found":  len(js_urls),
        "js_files":        js_urls,
        "secrets":         all_secrets,
        "endpoints":       all_endpoints,
        "internal_ips":    all_ips,
        "findings":        findings,
        "secret_count":    len(all_secrets),
        "endpoint_count":  len(all_endpoints),
    }
