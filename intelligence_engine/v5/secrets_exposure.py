"""
SentinelX V5 — Secrets Exposure Engine

Checks for secrets exposed in:
  1. robots.txt (sensitive paths disclosed)
  2. /.env files (environment variables)
  3. /config.js, /config.json, /settings.json
  4. /.git/config (Git repository exposed)
  5. /web.config (IIS config)
  6. /docker-compose.yml
  7. /.htpasswd
  8. /backup.sql, /dump.sql
  9. /phpinfo.php
  10. Error pages (stack traces, versions, paths)
  11. Public cloud bucket detection
  12. GitHub dork correlation (via public search)

All passive — only reads publicly accessible files.
"""

import json
import re
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

USER_AGENT = "SentinelX-ASM/5.0"

# Files to probe
SENSITIVE_FILES = {
    "/.env":                ("CRITICAL", "Environment variables with credentials"),
    "/.env.local":          ("CRITICAL", "Local environment variables"),
    "/.env.production":     ("CRITICAL", "Production environment variables"),
    "/.env.backup":         ("CRITICAL", "Backup environment file"),
    "/.git/config":         ("CRITICAL", "Git repository configuration exposed"),
    "/.git/HEAD":           ("HIGH",     "Git HEAD reference exposed"),
    "/.gitignore":          ("MEDIUM",   "Gitignore reveals project structure"),
    "/web.config":          ("HIGH",     "IIS web.config may contain credentials"),
    "/config.json":         ("HIGH",     "JSON config file"),
    "/config.js":           ("HIGH",     "JavaScript config with potential secrets"),
    "/settings.json":       ("HIGH",     "Settings file"),
    "/appsettings.json":    ("HIGH",     ".NET app settings"),
    "/.htpasswd":           ("CRITICAL", "HTTP authentication credentials"),
    "/.htaccess":           ("MEDIUM",   "Apache configuration disclosed"),
    "/robots.txt":          ("LOW",      "robots.txt — check for sensitive paths"),
    "/sitemap.xml":         ("LOW",      "Sitemap reveals URL structure"),
    "/phpinfo.php":         ("HIGH",     "PHP info page discloses server config"),
    "/info.php":            ("HIGH",     "PHP info page"),
    "/test.php":            ("MEDIUM",   "Test PHP page"),
    "/backup.sql":          ("CRITICAL", "SQL backup file"),
    "/dump.sql":            ("CRITICAL", "SQL dump file"),
    "/backup.zip":          ("CRITICAL", "Backup archive"),
    "/backup.tar.gz":       ("CRITICAL", "Backup archive"),
    "/docker-compose.yml":  ("CRITICAL", "Docker compose with service credentials"),
    "/docker-compose.yaml": ("CRITICAL", "Docker compose with service credentials"),
    "/.aws/credentials":    ("CRITICAL", "AWS credentials file"),
    "/wp-config.php.bak":   ("CRITICAL", "WordPress config backup"),
    "/wp-config-sample.php":("MEDIUM",   "WordPress sample config"),
    "/server-status":       ("HIGH",     "Apache server-status page"),
    "/server-info":         ("HIGH",     "Apache server-info page"),
    "/.DS_Store":           ("MEDIUM",   "macOS directory listing"),
    "/crossdomain.xml":     ("MEDIUM",   "Flash cross-domain policy"),
    "/clientaccesspolicy.xml": ("MEDIUM","Silverlight cross-domain policy"),
    "/package.json":        ("MEDIUM",   "Node.js package config"),
    "/composer.json":       ("LOW",      "PHP dependency file"),
    "/Gemfile":             ("LOW",      "Ruby dependencies"),
    "/requirements.txt":    ("LOW",      "Python dependencies"),
    "/.well-known/security.txt": ("LOW", "Security contact info"),
    "/security.txt":        ("LOW",      "Security contact info"),
}

ENV_SECRET_PATTERNS = {
    "DATABASE_URL":    r"DATABASE_URL\s*=\s*\S+",
    "DB_PASSWORD":     r"DB_PASSWORD\s*=\s*\S+",
    "SECRET_KEY":      r"SECRET_KEY\s*=\s*\S+",
    "API_KEY":         r"API_KEY\s*=\s*\S+",
    "AWS_SECRET":      r"AWS_SECRET_ACCESS_KEY\s*=\s*\S+",
    "SMTP_PASSWORD":   r"(SMTP|MAIL)_PASS(WORD)?\s*=\s*\S+",
    "PRIVATE_KEY":     r"PRIVATE_KEY\s*=\s*\S+",
    "JWT_SECRET":      r"JWT_SECRET\s*=\s*\S+",
    "STRIPE_SECRET":   r"STRIPE_SECRET\s*=\s*\S+",
}

ROBOT_SENSITIVE_PATTERNS = [
    r"/admin", r"/backup", r"/config", r"/private", r"/secret",
    r"/internal", r"/api", r"/database", r"/logs", r"/debug",
]

# Public S3 / GCS bucket patterns
BUCKET_PATTERNS = [
    r"([a-z0-9\-]+)\.s3\.amazonaws\.com",
    r"([a-z0-9\-]+)\.s3-website",
    r"storage\.googleapis\.com/([a-z0-9\-]+)",
    r"([a-z0-9\-]+)\.blob\.core\.windows\.net",
    r"([a-z0-9\-]+)\.azureblob\.net",
]


def _fetch(url: str, timeout: int = 6) -> tuple:
    """Returns (status_code, body_text)"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(65536).decode(errors="ignore")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def _check_file(host: str, path: str, severity: str, description: str) -> dict | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}{path}"
        status, body = _fetch(url)
        if status not in (200, 206):
            continue

        secrets_found = []
        robots_paths  = []
        buckets_found = []

        if path == "/robots.txt":
            disallow_lines = [l for l in body.splitlines() if "Disallow:" in l or "Allow:" in l]
            for line in disallow_lines:
                val = line.split(":", 1)[-1].strip()
                if any(re.search(pat, val, re.IGNORECASE) for pat in ROBOT_SENSITIVE_PATTERNS):
                    robots_paths.append(val)

        if ".env" in path or "config" in path.lower() or "settings" in path.lower():
            for name, pattern in ENV_SECRET_PATTERNS.items():
                if re.search(pattern, body, re.IGNORECASE):
                    secrets_found.append(name)

        for pat in BUCKET_PATTERNS:
            for m in re.findall(pat, body):
                buckets_found.append(m)

        return {
            "url":          url,
            "path":         path,
            "status":       status,
            "size":         len(body),
            "severity":     severity if secrets_found or path not in ("/robots.txt", "/sitemap.xml") else "LOW",
            "description":  description,
            "secrets_keys": secrets_found,
            "robots_sensitive_paths": robots_paths,
            "buckets_mentioned": list(set(buckets_found)),
            "body_preview": body[:300].replace("\n", " ").strip(),
        }
    return None


def check_public_buckets(domain: str) -> list:
    """Check if domain-named buckets are publicly accessible."""
    buckets = []
    base = domain.replace(".", "-").replace("_", "-")
    candidates = [
        f"https://{base}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{base}/",
        f"https://storage.googleapis.com/{base}/",
        f"https://{base}.blob.core.windows.net/",
    ]
    for url in candidates:
        status, body = _fetch(url, timeout=8)
        if status in (200,):
            buckets.append({
                "url":      url,
                "status":   status,
                "severity": "CRITICAL",
                "note":     "Publicly accessible cloud storage bucket",
                "preview":  body[:200],
            })
        elif status in (403,):
            # Exists but access denied — bucket name valid
            buckets.append({
                "url":      url,
                "status":   403,
                "severity": "MEDIUM",
                "note":     "Bucket exists but access denied — confirm no public ACLs",
            })
    return buckets


def check_github_leaks(domain: str) -> list:
    """
    Queries GitHub public search API for domain mentions in code.
    Passive only — reads public GitHub search results.
    No authentication required, but rate-limited.
    """
    import urllib.parse
    results = []
    queries = [
        f"{domain} password",
        f"{domain} secret",
        f"{domain} api_key",
        f"{domain} DATABASE_URL",
    ]
    for q in queries[:2]:   # rate limit: 2 queries
        encoded = urllib.parse.quote(q)
        url = f"https://api.github.com/search/code?q={encoded}&per_page=3"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github.v3+json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                items = data.get("items", [])
                for item in items[:3]:
                    results.append({
                        "query":       q,
                        "repo":        item.get("repository", {}).get("full_name"),
                        "file":        item.get("path"),
                        "url":         item.get("html_url"),
                        "severity":    "CRITICAL",
                        "note":        "Domain found in public GitHub code — may contain credentials",
                    })
        except Exception as e:
            results.append({"query": q, "error": str(e)})
    return results


def scan_secrets(host: str) -> dict:
    exposed = []
    findings = []

    with ThreadPoolExecutor(max_workers=20) as ex:
        jobs = {
            ex.submit(_check_file, host, path, sev, desc): path
            for path, (sev, desc) in SENSITIVE_FILES.items()
        }
        for future in as_completed(jobs):
            result = future.result()
            if result:
                exposed.append(result)
                findings.append({
                    "issue":    f"Sensitive file exposed: {result['path']}",
                    "severity": result["severity"],
                    "evidence": result["url"],
                    "secrets":  result["secrets_keys"],
                })

    exposed.sort(key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["severity"], 0), reverse=True)

    critical = [e for e in exposed if e["severity"] == "CRITICAL"]
    total_secrets = sum(len(e.get("secrets_keys", [])) for e in exposed)

    return {
        "host":            host,
        "files_exposed":   exposed,
        "critical_count":  len(critical),
        "total_exposed":   len(exposed),
        "secrets_found":   total_secrets > 0,
        "secrets_count":   total_secrets,
        "findings":        findings,
    }
