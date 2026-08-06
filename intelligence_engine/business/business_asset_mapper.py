"""
SentinelX Business Asset Mapper

Maps technical assets to business functions.
Answers: "What does this server actually DO for the business?"

Uses hostname patterns, open services, and technologies to infer
business function without requiring a CMDB.
"""

BUSINESS_FUNCTION_MAP = [
    {
        "function":  "Customer Portal",
        "keywords":  ["portal", "customer", "client", "self-service", "account"],
        "services":  {80, 443, 8443, 8080},
        "impact":    "Customer-facing — breach affects user trust and data",
        "gdpr_risk": True,
    },
    {
        "function":  "E-commerce / Payment",
        "keywords":  ["shop", "store", "cart", "payment", "checkout", "billing", "invoice"],
        "services":  {80, 443},
        "impact":    "Payment data in scope — PCI DSS applies",
        "gdpr_risk": True,
        "pci_risk":  True,
    },
    {
        "function":  "Email Infrastructure",
        "keywords":  ["mail", "smtp", "imap", "webmail", "exchange"],
        "services":  {25, 465, 587, 993, 143},
        "impact":    "Email compromise enables phishing + data theft",
        "gdpr_risk": True,
    },
    {
        "function":  "Developer / DevOps",
        "keywords":  ["dev", "build", "ci", "jenkins", "gitlab", "github", "repo", "code"],
        "services":  {8080, 8443, 9418, 3690},
        "impact":    "Source code access enables supply chain attacks",
        "gdpr_risk": False,
    },
    {
        "function":  "Identity / Authentication",
        "keywords":  ["auth", "sso", "login", "iam", "identity", "ldap", "oauth", "saml"],
        "services":  {389, 636, 88, 443},
        "impact":    "Identity compromise grants access to all dependent systems",
        "gdpr_risk": True,
    },
    {
        "function":  "Database / Data Store",
        "keywords":  ["db", "database", "data", "sql", "mongo", "redis", "elastic"],
        "services":  {3306, 5432, 1433, 27017, 6379, 9200, 1521},
        "impact":    "Direct data access — highest GDPR / compliance exposure",
        "gdpr_risk": True,
    },
    {
        "function":  "Admin / Operations",
        "keywords":  ["admin", "administrator", "manage", "panel", "dashboard", "ops", "internal"],
        "services":  {8080, 8443, 9090, 9999, 4848},
        "impact":    "Admin access enables full environment control",
        "gdpr_risk": False,
    },
    {
        "function":  "API Gateway",
        "keywords":  ["api", "gateway", "graphql", "rest", "service"],
        "services":  {443, 8080, 8443, 3000},
        "impact":    "API compromise exposes business logic and data",
        "gdpr_risk": True,
    },
    {
        "function":  "VPN / Remote Access",
        "keywords":  ["vpn", "remote", "access", "rdp", "jump"],
        "services":  {1194, 51820, 3389, 1723, 4500},
        "impact":    "VPN compromise provides internal network access",
        "gdpr_risk": False,
    },
    {
        "function":  "Monitoring / Observability",
        "keywords":  ["monitor", "metrics", "grafana", "kibana", "logs", "alert"],
        "services":  {5601, 3000, 9090, 9600},
        "impact":    "Log data may contain credentials and PII",
        "gdpr_risk": True,
    },
]


def map_business_function(host: str, open_ports: list, technologies: list) -> dict:
    host_lower = host.lower()
    port_set   = set(open_ports)
    tech_lower = [t.lower() if isinstance(t, str) else t.get("name", "").lower()
                  for t in technologies]

    matched_functions = []
    for mapping in BUSINESS_FUNCTION_MAP:
        keyword_hit = any(kw in host_lower for kw in mapping["keywords"])
        service_hit = bool(port_set & mapping["services"])
        if keyword_hit or service_hit:
            matched_functions.append({
                "function":  mapping["function"],
                "impact":    mapping["impact"],
                "gdpr_risk": mapping.get("gdpr_risk", False),
                "pci_risk":  mapping.get("pci_risk", False),
                "matched_by": "keyword" if keyword_hit else "service",
            })

    if not matched_functions:
        matched_functions.append({
            "function":  "Web Service",
            "impact":    "Unknown business function — review manually",
            "gdpr_risk": False,
            "pci_risk":  False,
            "matched_by": "default",
        })

    return {
        "host":               host,
        "business_functions": matched_functions,
        "gdpr_in_scope":      any(f["gdpr_risk"] for f in matched_functions),
        "pci_in_scope":       any(f.get("pci_risk") for f in matched_functions),
        "primary_function":   matched_functions[0]["function"] if matched_functions else "Unknown",
    }


def map_all_assets(attack_surface: dict) -> list:
    results = []
    for asset in attack_surface.get("assets", []):
        result = map_business_function(
            asset["host"],
            asset.get("open_ports", []),
            asset.get("technologies", []),
        )
        results.append(result)
    return results
