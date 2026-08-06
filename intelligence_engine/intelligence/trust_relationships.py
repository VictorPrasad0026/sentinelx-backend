"""
SentinelX Trust Relationship Analyzer

Maps third-party trust relationships discovered from:
  - CSP trusted domains
  - SPF include chains
  - MX provider delegation
  - CDN/WAF providers
  - Certificate issuers

Each trust relationship is a potential supply-chain attack vector.
"""

from urllib.parse import urlparse


def extract_csp_trusts(csp_data: dict) -> list:
    """Extract third-party domains trusted by CSP."""
    trusts = []
    trusted_domains = csp_data.get("third_party_domains", [])
    for domain in trusted_domains:
        trusts.append({
            "type":        "CSP_TRUST",
            "trusted":     domain,
            "source":      "Content-Security-Policy",
            "risk":        _assess_domain_risk(domain),
            "technique":   "T1195",
            "description": f"CSP allows content from {domain} — compromise of this third party affects your users",
        })
    return trusts


def extract_spf_trusts(spf_data: dict) -> list:
    """Extract domains trusted by SPF include chain."""
    trusts = []
    for include in spf_data.get("includes", []):
        trusts.append({
            "type":        "SPF_INCLUDE",
            "trusted":     include,
            "source":      "SPF Record",
            "risk":        "MEDIUM",
            "technique":   "T1566",
            "description": f"SPF includes {include} — emails from this domain are trusted as yours",
        })
    return trusts


def extract_mx_trusts(mx_data: dict) -> list:
    """Email provider delegation trust."""
    trusts = []
    provider = mx_data.get("provider", "Unknown")
    if provider != "Unknown":
        trusts.append({
            "type":        "EMAIL_DELEGATION",
            "trusted":     provider,
            "source":      "MX Record",
            "risk":        "MEDIUM",
            "technique":   "T1114",
            "description": f"Email is handled by {provider} — your email security depends on their controls",
        })
    return trusts


def extract_cdn_waf_trusts(cdn_data: dict, waf_data: dict) -> list:
    """CDN and WAF provider trust."""
    trusts = []
    if isinstance(cdn_data, dict) and cdn_data.get("detected"):
        trusts.append({
            "type":        "CDN_TRUST",
            "trusted":     cdn_data.get("provider"),
            "source":      "CDN Detection",
            "risk":        "LOW",
            "technique":   "T1195.002",
            "description": f"Traffic routed through {cdn_data.get('provider')} — CDN compromise affects your users",
        })
    if isinstance(waf_data, dict) and waf_data.get("detected"):
        trusts.append({
            "type":        "WAF_TRUST",
            "trusted":     waf_data.get("provider"),
            "source":      "WAF Detection",
            "risk":        "LOW",
            "technique":   "T1195.002",
            "description": f"WAF protection via {waf_data.get('provider')} — WAF bypass affects your application",
        })
    return trusts


def _assess_domain_risk(domain: str) -> str:
    known_safe = {"google.com", "googleapis.com", "jquery.com", "cloudflare.com",
                  "jsdelivr.net", "unpkg.com", "bootstrapcdn.com", "cdnjs.cloudflare.com"}
    if any(domain.endswith(s) for s in known_safe):
        return "LOW"
    if domain.count(".") == 0:
        return "HIGH"
    return "MEDIUM"


def analyze_trust_relationships(profile: dict) -> dict:
    trusts = []

    csp   = profile.get("csp_intelligence", {})
    spf   = profile.get("email_intelligence", {}).get("spf", {})
    mx    = profile.get("email_intelligence", {}).get("mx", {})
    cdn   = profile.get("infrastructure_intelligence", {}).get("cdn", {})
    http  = profile.get("http_intelligence", {})
    waf   = http.get("waf", {})

    trusts.extend(extract_csp_trusts(csp))
    trusts.extend(extract_spf_trusts(spf))
    trusts.extend(extract_mx_trusts(mx))
    trusts.extend(extract_cdn_waf_trusts(cdn, waf))

    high_risk = [t for t in trusts if t["risk"] in ("HIGH", "CRITICAL")]

    return {
        "total_trust_relationships": len(trusts),
        "high_risk_trusts":          high_risk,
        "trusts":                    trusts,
        "summary": (
            f"{len(trusts)} third-party trust relationships identified. "
            f"{len(high_risk)} are high risk."
        ),
    }
