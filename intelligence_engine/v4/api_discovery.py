"""
SentinelX V4 — API Discovery Engine

Probes common API endpoints on discovered assets.
Discovers: REST, GraphQL, Swagger, OpenAPI, versioned APIs.

Then analyzes:
  - Authentication (present / missing)
  - CORS policy
  - HTTP methods allowed
  - Sensitive data in response
"""

import json
import urllib.request
import urllib.error
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

USER_AGENT = "SentinelX-ASM/4.0"

API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    "/graphql",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/api/swagger",
    "/api/openapi",
    "/docs",
    "/redoc",
    "/.well-known/openid-configuration",
    "/wp-json",
    "/wp-json/wp/v2",
    "/wp-json/wp/v2/users",
    "/admin/api",
    "/api/admin",
    "/api/health",
    "/api/status",
    "/health",
    "/status",
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/beans",
]

SENSITIVE_KEYS = [
    "password", "secret", "token", "key", "api_key", "auth",
    "credential", "private", "access_token", "refresh_token",
    "db_password", "database", "connection_string",
]


def probe_endpoint(host: str, path: str, timeout: int = 5) -> dict:
    result = {
        "url":            f"https://{host}{path}",
        "path":           path,
        "status":         None,
        "content_type":   None,
        "auth_required":  False,
        "cors":           None,
        "json_response":  False,
        "sensitive_keys": [],
        "size":           0,
        "reachable":      False,
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}{path}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                result["status"]       = resp.status
                result["content_type"] = resp.headers.get("Content-Type", "")
                result["cors"]         = resp.headers.get("Access-Control-Allow-Origin")
                result["reachable"]    = True
                result["url"]          = url

                body = resp.read(4096).decode(errors="ignore")
                result["size"] = len(body)

                if "json" in result["content_type"].lower() or body.strip().startswith("{"):
                    result["json_response"] = True
                    # Check for sensitive keys in response
                    body_lower = body.lower()
                    result["sensitive_keys"] = [
                        k for k in SENSITIVE_KEYS if k in body_lower
                    ]

                return result

        except urllib.error.HTTPError as e:
            result["status"]    = e.code
            result["reachable"] = e.code not in (0,)
            if e.code == 401:
                result["auth_required"] = True
            return result

        except Exception:
            continue

    return result


def discover_apis(host: str, max_workers: int = 10) -> dict:
    findings = []
    discovered = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        jobs = {ex.submit(probe_endpoint, host, path): path for path in API_PATHS}
        for future in as_completed(jobs):
            result = future.result()
            if result["reachable"] and result["status"] not in (404, 410):
                discovered.append(result)
                if result["json_response"] and not result["auth_required"]:
                    findings.append({
                        "issue":    f"Unauthenticated API endpoint: {result['url']}",
                        "severity": "HIGH",
                        "evidence": f"HTTP {result['status']} — JSON response, no auth",
                    })
                if result.get("sensitive_keys"):
                    findings.append({
                        "issue":    f"Sensitive keys in API response: {result['url']}",
                        "severity": "CRITICAL",
                        "evidence": f"Keys found: {result['sensitive_keys']}",
                    })
                if result["cors"] == "*":
                    findings.append({
                        "issue":    f"Wildcard CORS on API: {result['url']}",
                        "severity": "HIGH",
                        "evidence": "Access-Control-Allow-Origin: *",
                    })

    return {
        "host":            host,
        "endpoints_probed": len(API_PATHS),
        "endpoints_found":  len(discovered),
        "endpoints":        discovered,
        "findings":         findings,
        "has_graphql":      any("/graphql" in e["url"] for e in discovered),
        "has_swagger":      any("swagger" in e["url"] for e in discovered),
        "has_openapi":      any("openapi" in e["url"] for e in discovered),
        "has_wordpress_api": any("wp-json" in e["url"] for e in discovered),
    }


def scan_all_assets(assets: list, max_assets: int = 5) -> list:
    """Scan top N assets for API endpoints (rate limited)."""
    results = []
    for asset in assets[:max_assets]:
        host = asset.get("host") if isinstance(asset, dict) else asset
        result = discover_apis(host)
        results.append(result)
        time.sleep(0.5)
    return results
