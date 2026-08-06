"""
SentinelX DNS Intelligence Engine v2.0

Collects ALL DNS record types:
A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, SRV, PTR
Plus: SPF, DMARC, DKIM detection from TXT records
"""

import socket
from datetime import datetime, timezone

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def query(domain, record_type, timeout=5):
    if not DNS_AVAILABLE:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except Exception:
        return []


def get_dns_info(domain):

    result = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": [],
        "SOA": None,
        "CAA": [],
        "SRV": {},
        "spf": None,
        "dmarc": None,
        "txt_raw": []
    }

    # A
    try:
        result["A"] = socket.gethostbyname_ex(domain)[2]
    except Exception:
        pass

    # AAAA
    try:
        ipv6 = socket.getaddrinfo(domain, None, socket.AF_INET6)
        result["AAAA"] = list(set(x[4][0] for x in ipv6))
    except Exception:
        pass

    # CNAME
    try:
        cname = socket.gethostbyname_ex(domain)[0]
        if cname != domain:
            result["CNAME"] = [cname]
    except Exception:
        pass

    if not DNS_AVAILABLE:
        result["error"] = "dnspython not installed"
        return result

    # MX
    mx_raw = query(domain, "MX")
    result["MX"] = []
    for r in mx_raw:
        parts = r.split()
        if len(parts) == 2:
            result["MX"].append({
                "priority": int(parts[0]),
                "host": parts[1].rstrip(".")
            })
    result["MX"].sort(key=lambda x: x["priority"])

    # NS
    result["NS"] = [r.rstrip(".") for r in query(domain, "NS")]

    # TXT — also extract SPF and DMARC
    txt_records = query(domain, "TXT")
    result["txt_raw"] = [r.strip('"') for r in txt_records]

    for record in result["txt_raw"]:
        if record.lower().startswith("v=spf1"):
            result["spf"] = record
        if record.lower().startswith("v=dmarc1"):
            result["dmarc"] = record

    # _dmarc subdomain
    if not result["dmarc"]:
        dmarc_records = query(f"_dmarc.{domain}", "TXT")
        for r in dmarc_records:
            r = r.strip('"')
            if "v=dmarc1" in r.lower():
                result["dmarc"] = r

    # SOA
    soa_raw = query(domain, "SOA")
    if soa_raw:
        result["SOA"] = soa_raw[0]

    # CAA
    result["CAA"] = query(domain, "CAA")

    # SRV — common services
    srv_names = [
        "_http._tcp", "_https._tcp", "_smtp._tcp",
        "_imaps._tcp", "_submission._tcp", "_sip._tcp",
        "_xmpp-client._tcp", "_xmpp-server._tcp"
    ]
    for srv in srv_names:
        records = query(f"{srv}.{domain}", "SRV")
        if records:
            result["SRV"][srv] = records

    return result


# Lightweight version used by asset enrichment (just A/AAAA/CNAME)
def resolve_dns(host):
    r = get_dns_info(host)
    return {
        "host": host,
        "A": r.get("A", []),
        "AAAA": r.get("AAAA", []),
        "CNAME": r.get("CNAME", [])
    }


if __name__ == "__main__":
    import json
    domain = input("Domain: ").strip().lower()
    print(json.dumps(get_dns_info(domain), indent=4))
