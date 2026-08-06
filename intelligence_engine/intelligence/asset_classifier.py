"""
SentinelX Asset Classifier

Classifies every asset by type and internet exposure.
Single responsibility: classification only.
"""

SENSITIVE_KEYWORDS = [
    "admin", "administrator", "panel", "portal", "login",
    "auth", "sso", "vpn", "remote", "access",
    "api", "gateway", "internal", "intranet",
    "dev", "development", "test", "staging", "uat", "qa",
    "backup", "old", "legacy", "archive",
    "db", "database", "sql", "mongo", "redis", "elastic",
    "mail", "smtp", "exchange", "webmail",
    "erp", "crm", "jira", "confluence", "gitlab", "jenkins",
    "finance", "billing", "payment", "invoice",
    "hr", "payroll",
]

ADMIN_KEYWORDS   = ["admin", "administrator", "panel", "dashboard", "manage", "control"]
DATABASE_KEYWORDS = ["db", "database", "sql", "mysql", "mongo", "redis", "elastic", "postgres", "oracle"]
AUTH_KEYWORDS    = ["auth", "login", "sso", "oauth", "iam", "identity", "ldap", "kerberos"]
DEV_KEYWORDS     = ["dev", "development", "test", "staging", "uat", "qa", "debug"]
BACKUP_KEYWORDS  = ["backup", "old", "legacy", "archive", "bak"]


def classify_asset(host: str, open_ports: list = None, technologies: list = None) -> dict:
    host_lower = host.lower()
    open_ports = open_ports or []
    technologies = [t.lower() if isinstance(t, str) else t.get("name", "").lower()
                    for t in (technologies or [])]

    asset_types = []
    sensitive_keywords_found = []

    for kw in SENSITIVE_KEYWORDS:
        if kw in host_lower:
            sensitive_keywords_found.append(kw)

    if any(kw in host_lower for kw in ADMIN_KEYWORDS):
        asset_types.append("Admin Panel")
    if any(kw in host_lower for kw in DATABASE_KEYWORDS):
        asset_types.append("Database")
    if any(kw in host_lower for kw in AUTH_KEYWORDS):
        asset_types.append("Authentication System")
    if any(kw in host_lower for kw in DEV_KEYWORDS):
        asset_types.append("Development/Staging")
    if any(kw in host_lower for kw in BACKUP_KEYWORDS):
        asset_types.append("Backup System")

    # Classify by open port services
    db_ports = {3306, 5432, 1433, 27017, 6379, 9200, 1521}
    admin_ports = {8080, 8443, 9090, 4848, 9990, 15672, 8161}
    if any(p in db_ports for p in open_ports):
        asset_types.append("Database (Port)")
    if any(p in admin_ports for p in open_ports):
        asset_types.append("Admin Interface (Port)")

    if not asset_types:
        asset_types.append("Web Asset")

    internet_facing = bool(open_ports) or any(
        p in (80, 443, 8080, 8443) for p in open_ports
    )

    return {
        "host":                    host,
        "asset_types":             list(set(asset_types)),
        "sensitive_keywords":      sensitive_keywords_found,
        "is_sensitive":            bool(sensitive_keywords_found),
        "internet_facing":         internet_facing,
        "open_port_count":         len(open_ports),
        "technology_count":        len(technologies),
    }
