"""
SentinelX Infrastructure Intelligence Engine v3.0

Aggregates:
- IP resolution
- ASN + org + registry
- GeoIP (country, city, coords, timezone)
- Cloud provider detection
- Reverse DNS + provider hint
- CDN detection
- Port scan + service banners
- Exposure score
"""

import socket
import json
from datetime import datetime, timezone

from collectors.asn_intelligence import get_asn_intelligence
from collectors.geoip_intelligence import get_geoip_intelligence
from collectors.reverse_dns import get_reverse_dns
from collectors.cdn_detection import detect_cdn
from collectors.cloud_intelligence import detect_cloud_provider
from collectors.port_intelligence import get_port_intelligence


def resolve_ip(target):
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None


def calculate_exposure(port_data):
    score = 0
    for port in port_data.get("ports", []):
        if port.get("state") != "OPEN":
            continue
        risk = port.get("risk", "LOW")
        if risk == "CRITICAL":
            score += 25
        elif risk == "HIGH":
            score += 15
        elif risk == "MEDIUM":
            score += 8
        else:
            score += 2
    return min(score, 100)


def get_infrastructure_info(target):

    print("[+] Infrastructure Intelligence")

    result = {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": None,
        "asn": {},
        "geoip": {},
        "cloud": {},
        "reverse_dns": {},
        "cdn": {},
        "ports": {},
        "exposure_score": 0
    }

    ip = resolve_ip(target)
    if not ip:
        result["error"] = "DNS resolution failed"
        return result

    result["ip"] = ip

    # ASN
    try:
        asn_data = get_asn_intelligence(ip)
        result["asn"] = asn_data
    except Exception as e:
        result["asn"] = {"error": str(e)}

    # GeoIP
    try:
        result["geoip"] = get_geoip_intelligence(ip)
    except Exception as e:
        result["geoip"] = {"error": str(e)}

    # Reverse DNS
    try:
        result["reverse_dns"] = get_reverse_dns(ip)
    except Exception as e:
        result["reverse_dns"] = {"error": str(e)}

    # Cloud — feed ASN description + reverse DNS hostname
    try:
        asn_desc = result["asn"].get("description") if isinstance(result["asn"], dict) else None
        rdns_host = None
        if isinstance(result["reverse_dns"], dict):
            rdns = result["reverse_dns"].get("reverse_dns", {})
            rdns_host = rdns.get("hostname") if isinstance(rdns, dict) else None

        result["cloud"] = detect_cloud_provider(
            asn=asn_desc,
            reverse_dns=rdns_host,
            hostname=target
        )
    except Exception as e:
        result["cloud"] = {"error": str(e)}

    # CDN
    try:
        result["cdn"] = detect_cdn(target)
    except Exception as e:
        result["cdn"] = {"error": str(e)}

    # Ports
    try:
        ports = get_port_intelligence(target)
        if isinstance(ports, str):
            ports = json.loads(ports)
        result["ports"] = ports
    except Exception as e:
        result["ports"] = {"error": str(e)}

    # Exposure score
    result["exposure_score"] = calculate_exposure(result["ports"])

    return result


if __name__ == "__main__":
    domain = input("Domain/IP: ")
    import json as _json
    print(_json.dumps(get_infrastructure_info(domain), indent=4))
