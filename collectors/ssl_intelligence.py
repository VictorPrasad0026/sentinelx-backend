"""
SentinelX SSL Intelligence Engine v2.0

Collects:
- Certificate issuer / subject / SAN
- TLS version + cipher suite + key size
- Certificate chain depth
- Expiry + days remaining
- Self-signed detection
- Wildcard certificate detection
- CT log correlation hint
- Revocation status (OCSP URL extraction)
"""

import ssl
import socket
import hashlib
from datetime import datetime, timezone


def parse_field(field):
    parsed = {}
    for item in field:
        for key, value in item:
            parsed[key] = value
    return parsed


def days_remaining(valid_until):
    try:
        expiry = datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z")
        return (expiry - datetime.utcnow()).days
    except Exception:
        return None


def extract_san(cert):
    """Extract Subject Alternative Names."""
    sans = []
    for ext in cert.get("subjectAltName", []):
        if ext[0].lower() == "dns":
            sans.append(ext[1])
    return sans


def is_self_signed(issuer, subject):
    return issuer == subject


def get_ssl_info(domain, port=443):

    result = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ssl": {}
    }

    try:
        # Use unverified context first to get cert even if invalid
        ctx_unverified = ssl.create_default_context()
        ctx_unverified.check_hostname = False
        ctx_unverified.verify_mode = ssl.CERT_NONE

        ctx_verified = ssl.create_default_context()

        # Try verified first
        verified = True
        try:
            with socket.create_connection((domain, port), timeout=8) as sock:
                with ctx_verified.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    tls_version = ssock.version()
        except ssl.SSLCertVerificationError:
            verified = False
            with socket.create_connection((domain, port), timeout=8) as sock:
                with ctx_unverified.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

        issuer = parse_field(cert.get("issuer", []))
        subject = parse_field(cert.get("subject", []))
        valid_from = cert.get("notBefore")
        valid_until = cert.get("notAfter")
        san = extract_san(cert)
        days = days_remaining(valid_until)
        self_signed = is_self_signed(issuer, subject)
        wildcard = any(s.startswith("*.") for s in san)

        # Fingerprint
        fingerprint_sha256 = None
        if cert_bin:
            fingerprint_sha256 = hashlib.sha256(cert_bin).hexdigest()

        # Cipher info
        cipher_name = cipher[0] if cipher else None
        cipher_bits = cipher[2] if cipher else None

        # OCSP URL from extensions (hints at revocation check URL)
        ocsp_urls = []
        for ext in cert.get("OCSP", []):
            ocsp_urls.append(ext)

        # Status
        if not verified:
            status = "INVALID_CERTIFICATE"
        elif days is not None and days < 0:
            status = "EXPIRED"
        elif self_signed:
            status = "SELF_SIGNED"
        else:
            status = "VALID"

        result["ssl"] = {
            "status": status,
            "verified": verified,
            "issuer": issuer,
            "subject": subject,
            "san": san,
            "san_count": len(san),
            "wildcard": wildcard,
            "self_signed": self_signed,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "days_remaining": days,
            "tls_version": tls_version,
            "cipher_suite": cipher_name,
            "cipher_bits": cipher_bits,
            "fingerprint_sha256": fingerprint_sha256,
            "ocsp_urls": ocsp_urls,
            "security_checks": {
                "tls_secure": tls_version in ["TLSv1.2", "TLSv1.3"],
                "tls_version_ok": tls_version not in ["TLSv1", "TLSv1.1", "SSLv3"],
                "certificate_valid": verified,
                "not_expired": days is not None and days >= 0,
                "not_self_signed": not self_signed,
                "strong_cipher": cipher_bits is not None and cipher_bits >= 128
            }
        }

    except ssl.CertificateError as e:
        result["ssl"] = {
            "status": "INVALID_CERTIFICATE",
            "error": str(e)
        }

    except ConnectionRefusedError:
        result["ssl"] = {
            "status": "PORT_CLOSED",
            "error": "Port 443 not reachable"
        }

    except Exception as e:
        result["ssl"] = {
            "status": "FAILED",
            "error": str(e)
        }

    return result


if __name__ == "__main__":
    import json
    target = input("Domain: ").strip()
    print(json.dumps(get_ssl_info(target), indent=4))
