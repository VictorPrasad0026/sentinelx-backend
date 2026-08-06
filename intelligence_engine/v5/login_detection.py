"""
SentinelX V5 — Login Page Detection + Default Credential Detection

Discovers login pages across all assets (non-intrusive).
Does NOT attempt authentication — only identifies:
  - Login page URLs
  - Authentication type (form, basic auth, OAuth, SSO)
  - Technology-specific admin panels
  - Default credential risk (known panels with known defaults)

Never sends credentials. Never modifies target state.
"""

import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser

USER_AGENT = "SentinelX-ASM/5.0"

# Paths that commonly host login pages
LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/admin", "/admin/login", "/administrator", "/wp-admin",
    "/wp-login.php", "/wp-admin/", "/user/login", "/users/sign_in",
    "/account/login", "/portal", "/portal/login", "/dashboard",
    "/panel", "/cpanel", "/webmail", "/mail", "/roundcube",
    "/phpmyadmin", "/pma", "/db", "/database",
    "/console", "/admin/console", "/manage", "/management",
    "/api/auth", "/auth/login", "/oauth/authorize",
    "/.well-known/openid-configuration",
    "/sso", "/saml", "/cas/login",
    "/jenkins", "/gitlab", "/jira", "/confluence", "/grafana",
    "/kibana", "/elastic", "/solr", "/rabbitmq",
    "/actuator", "/jolokia",
]

# Known panels and their default credentials (for RISK reporting only — never tested)
KNOWN_DEFAULTS = {
    "phpMyAdmin":  [("root", ""), ("root", "root"), ("admin", "admin")],
    "Jenkins":     [("admin", "admin"), ("jenkins", "jenkins")],
    "Grafana":     [("admin", "admin")],
    "Kibana":      [("elastic", "changeme"), ("admin", "admin")],
    "RabbitMQ":    [("guest", "guest")],
    "Tomcat":      [("admin", "admin"), ("tomcat", "tomcat"), ("manager", "manager")],
    "cPanel":      [],
    "WordPress":   [("admin", "admin"), ("admin", "password")],
    "WebLogic":    [("weblogic", "weblogic"), ("admin", "admin")],
    "JBoss":       [("admin", "admin")],
    "JIRA":        [("admin", "admin")],
    "Confluence":  [("admin", "admin")],
}

# Keywords that appear in login pages
LOGIN_KEYWORDS = [
    "password", "passwd", "username", "login", "sign in", "signin",
    "log in", "authenticate", "credential", "email", "forgot password",
    "remember me", "type=\"password\"", "input name=\"password\"",
]

PANEL_FINGERPRINTS = {
    "WordPress":   ["wp-login", "wp-admin", "wordpress"],
    "phpMyAdmin":  ["phpmyadmin", "pma_username", "phpMyAdmin"],
    "Jenkins":     ["jenkins", "j_username", "j_password"],
    "Grafana":     ["grafana", "GrafanaBootData"],
    "Kibana":      ["kibana", "kbn-version"],
    "cPanel":      ["cPanel", "cpsess", "cpanel"],
    "Roundcube":   ["roundcube", "rcmloginuser"],
    "Tomcat":      ["tomcat", "Tomcat Web Application Manager"],
    "Jira":        ["jira", "JIRA", "atlassian"],
    "Confluence":  ["confluence", "atlassian"],
    "RabbitMQ":    ["rabbitmq", "RabbitMQ Management"],
}


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.has_password  = False
        self.has_username  = False
        self.form_action   = None
        self.form_method   = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            self.form_action = attrs_dict.get("action")
            self.form_method = attrs_dict.get("method", "get").upper()
        if tag == "input":
            t = attrs_dict.get("type", "").lower()
            n = attrs_dict.get("name", "").lower()
            if t == "password":
                self.has_password = True
            if t in ("text", "email") or any(k in n for k in ("user", "email", "login", "name")):
                self.has_username = True


def probe_login(host: str, path: str, timeout: int = 5) -> dict | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}{path}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": USER_AGENT,
                         "Accept": "text/html,application/xhtml+xml"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status not in (200, 401, 403):
                    return None
                body = resp.read(32768).decode(errors="ignore")
                headers = dict(resp.headers)

                body_lower = body.lower()
                has_login_kw = any(kw in body_lower for kw in LOGIN_KEYWORDS)
                if not has_login_kw and resp.status == 200:
                    return None

                # Detect panel type
                panel_type = None
                for panel, fp_list in PANEL_FINGERPRINTS.items():
                    if any(fp.lower() in body_lower for fp in fp_list):
                        panel_type = panel
                        break

                # Parse form
                parser = FormParser()
                parser.feed(body)

                auth_type = "UNKNOWN"
                if resp.status == 401:
                    auth_type = "HTTP_BASIC_AUTH"
                elif parser.has_password and parser.has_username:
                    auth_type = "FORM"
                elif "oauth" in body_lower or "openid" in body_lower:
                    auth_type = "OAUTH_OIDC"
                elif "saml" in body_lower:
                    auth_type = "SAML_SSO"
                elif has_login_kw:
                    auth_type = "FORM_DETECTED"

                default_creds = KNOWN_DEFAULTS.get(panel_type, []) if panel_type else []

                return {
                    "url":           url,
                    "path":          path,
                    "status":        resp.status,
                    "auth_type":     auth_type,
                    "panel_type":    panel_type,
                    "has_password_field": parser.has_password,
                    "form_action":   parser.form_action,
                    "default_creds_risk": bool(default_creds),
                    "known_defaults": [f"{u}/{p}" for u, p in default_creds[:3]],
                    "severity": "CRITICAL" if default_creds else "HIGH" if auth_type != "OAUTH_OIDC" else "MEDIUM",
                }
        except Exception:
            continue
    return None


def scan_login_pages(host: str, max_workers: int = 15) -> dict:
    logins = []
    findings = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        jobs = {ex.submit(probe_login, host, p): p for p in LOGIN_PATHS}
        for future in as_completed(jobs):
            result = future.result()
            if result:
                logins.append(result)
                panel = result.get("panel_type") or "Login page"
                findings.append({
                    "issue":    f"Login page exposed: {result['url']}",
                    "severity": result["severity"],
                    "evidence": f"Auth type: {result['auth_type']} · Panel: {panel}",
                })
                if result["default_creds_risk"]:
                    findings.append({
                        "issue":    f"Known default credentials exist for {panel}",
                        "severity": "CRITICAL",
                        "evidence": f"Panel {panel} has well-known defaults: {', '.join(result['known_defaults'])}",
                        "note":     "SentinelX detected panel type only — credentials were NOT tested",
                    })

    logins.sort(key=lambda x: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(x.get("severity", "LOW"), 0), reverse=True)
    panels = list({l["panel_type"] for l in logins if l.get("panel_type")})

    return {
        "host":          host,
        "login_pages":   logins,
        "login_count":   len(logins),
        "panels_found":  panels,
        "default_cred_risk_count": sum(1 for l in logins if l.get("default_creds_risk")),
        "findings":      findings,
    }


def scan_all_assets(assets: list, max_assets: int = 8) -> list:
    results = []
    for asset in assets[:max_assets]:
        host = asset.get("host") if isinstance(asset, dict) else asset
        results.append(scan_login_pages(host))
    return results
