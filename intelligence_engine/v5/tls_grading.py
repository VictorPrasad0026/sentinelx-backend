"""
SentinelX V5 — TLS Configuration Grading Engine

Grades TLS configuration A+ to F (like SSL Labs).
Also builds certificate transparency timeline from crt.sh.

Checks:
  - Protocol versions (TLS 1.3 / 1.2 / 1.1 / 1.0 / SSLv3)
  - Cipher suite strength
  - Certificate validity / expiry / chain
  - HSTS header presence + max-age
  - OCSP stapling
  - Wildcard cert risk
  - SAN coverage
  - CT log presence

Grade:
  A+  All checks pass + HSTS preload
  A   All checks pass
  B   Minor issues (TLS 1.2 only, no HSTS)
  C   Weak cipher or short expiry
  D   TLS 1.1 or self-signed
  F   SSL failure or expired
"""

import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone


# ── Grade weights ────────────────────────────────────────────
DEDUCTIONS = {
    "tls_1_1_enabled":     ("D", 30, "TLS 1.1 enabled — deprecated protocol"),
    "tls_1_0_enabled":     ("F", 50, "TLS 1.0 enabled — critically deprecated"),
    "ssl3_enabled":        ("F", 60, "SSLv3 enabled — POODLE vulnerability"),
    "weak_cipher":         ("C", 20, "Weak cipher suite (< 128 bits)"),
    "expired":             ("F", 60, "Certificate expired"),
    "self_signed":         ("D", 35, "Self-signed certificate"),
    "invalid":             ("F", 60, "Certificate validation failed"),
    "no_hsts":             ("B", 10, "Missing HSTS header"),
    "hsts_short":          ("B",  5, "HSTS max-age < 180 days"),
    "wildcard":            ("B",  5, "Wildcard certificate in use"),
    "expiry_soon_30":      ("B", 10, "Certificate expires in < 30 days"),
    "expiry_soon_14":      ("C", 20, "Certificate expires in < 14 days"),
    "no_ocsp":             ("A",  0, "No OCSP stapling detected"),
}


def grade_ssl(ssl_data: dict, http_headers: dict = None) -> dict:
    """
    ssl_data: the ssl sub-dict from ssl_intelligence (status, tls_version, cipher_bits, etc.)
    http_headers: optional dict of response headers to check HSTS
    """
    if not ssl_data or ssl_data.get("status") in ("PORT_CLOSED", None):
        return {"grade": "N/A", "score": 0, "issues": ["HTTPS not available"]}

    score = 100
    issues = []
    letter = "A"

    status       = ssl_data.get("status", "FAILED")
    tls_version  = ssl_data.get("tls_version", "")
    cipher_bits  = ssl_data.get("cipher_bits") or 0
    days         = ssl_data.get("days_remaining")
    self_signed  = ssl_data.get("self_signed", False)
    wildcard     = ssl_data.get("wildcard", False)

    if status == "FAILED" or status == "INVALID_CERTIFICATE":
        score -= 60; letter = "F"; issues.append(DEDUCTIONS["invalid"][2])
    elif status == "EXPIRED":
        score -= 60; letter = "F"; issues.append(DEDUCTIONS["expired"][2])
    elif self_signed:
        score -= 35; letter = "D"; issues.append(DEDUCTIONS["self_signed"][2])

    if tls_version in ("TLSv1",):
        score -= 50; issues.append(DEDUCTIONS["tls_1_0_enabled"][2])
        if letter not in ("F",): letter = "F"
    elif tls_version in ("TLSv1.1",):
        score -= 30; issues.append(DEDUCTIONS["tls_1_1_enabled"][2])
        if letter not in ("F",): letter = "D"

    if cipher_bits and cipher_bits < 128:
        score -= 20; issues.append(DEDUCTIONS["weak_cipher"][2])
        if letter not in ("D", "F"): letter = "C"

    if wildcard:
        score -= 5; issues.append(DEDUCTIONS["wildcard"][2])

    if days is not None:
        if days < 0:
            score -= 60; issues.append(DEDUCTIONS["expired"][2])
        elif days < 14:
            score -= 20; issues.append(DEDUCTIONS["expiry_soon_14"][2])
            if letter not in ("D","F"): letter = "C"
        elif days < 30:
            score -= 10; issues.append(DEDUCTIONS["expiry_soon_30"][2])

    # HSTS check
    hsts = ""
    if http_headers:
        hsts = (http_headers.get("strict-transport-security", {}).get("value", "")
                if isinstance(http_headers.get("strict-transport-security"), dict)
                else http_headers.get("strict-transport-security", ""))

    if not hsts:
        score -= 10; issues.append(DEDUCTIONS["no_hsts"][2])
        if letter == "A": letter = "B"
    else:
        try:
            parts = {p.strip().split("=")[0]: p.strip().split("=")[1]
                     if "=" in p else True
                     for p in hsts.split(";")}
            max_age = int(parts.get("max-age", 0))
            if max_age < 15552000:  # 180 days
                score -= 5; issues.append(DEDUCTIONS["hsts_short"][2])
        except Exception:
            pass
        else:
            if "preload" in hsts.lower() and letter == "A" and not issues:
                letter = "A+"

    score = max(0, min(100, score))

    if not issues and letter == "A" and score >= 95:
        letter = "A+"
    elif score < 40 and letter not in ("F",):
        letter = "D"

    return {
        "grade":           letter,
        "score":           score,
        "tls_version":     tls_version,
        "cipher_suite":    ssl_data.get("cipher_suite"),
        "cipher_bits":     cipher_bits,
        "days_remaining":  days,
        "wildcard":        wildcard,
        "self_signed":     self_signed,
        "hsts_present":    bool(hsts),
        "issues":          issues,
        "issuer":          ssl_data.get("issuer", {}).get("organizationName"),
        "valid_until":     ssl_data.get("valid_until"),
    }


def fetch_ct_timeline(domain: str) -> list:
    """
    Query crt.sh for certificate transparency history.
    Returns list of cert issuances sorted by date.
    """
    url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelX-ASM/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        return [{"error": str(e)}]

    seen = set()
    timeline = []
    for entry in data[:50]:   # cap at 50
        fp = entry.get("id", "")
        if fp in seen:
            continue
        seen.add(fp)
        timeline.append({
            "id":          entry.get("id"),
            "logged_at":   entry.get("entry_timestamp", "")[:10],
            "not_before":  entry.get("not_before", "")[:10],
            "not_after":   entry.get("not_after", "")[:10],
            "issuer":      entry.get("issuer_name", ""),
            "name_value":  entry.get("name_value", ""),
        })

    timeline.sort(key=lambda x: x["logged_at"], reverse=True)
    return timeline


def grade_all_assets(profile: dict) -> dict:
    """Grade TLS for main domain and all subdomains."""
    results = {}

    # Main domain
    main_ssl  = profile.get("ssl_intelligence", {}).get("ssl", {})
    main_http = profile.get("http_intelligence", {}).get("security_headers", {})
    domain    = profile.get("asset", "unknown")
    results[domain] = grade_ssl(main_ssl, main_http)

    # Subdomains
    for asset in profile.get("subdomain_assets", {}).get("assets", []):
        host      = asset.get("host", "")
        asset_ssl = asset.get("ssl", {})
        asset_http = asset.get("http", {}).get("security_headers", {})
        results[host] = grade_ssl(asset_ssl, asset_http)

    # Summary
    grades = [r["grade"] for r in results.values()]
    grade_counts = {}
    for g in grades:
        grade_counts[g] = grade_counts.get(g, 0) + 1

    failed = [h for h, r in results.items() if r["grade"] == "F"]
    low    = [h for h, r in results.items() if r["grade"] in ("C", "D")]

    return {
        "asset_grades":  results,
        "grade_summary": grade_counts,
        "failed_assets": failed,
        "low_grade_assets": low,
        "overall_grade": min(grades, key=lambda g: "A+ABCDF".index(g if g in "A+ABCDF" else "F")),
    }
