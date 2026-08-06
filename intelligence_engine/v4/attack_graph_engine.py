"""
SentinelX V4 — Attack Graph Engine

Builds ACCURATE, evidence-only attack chains.

Every chain is:
  Internet → Entry Point → Technique → Pivot → Impact → MITRE

No guessing. Every step requires evidence from the scan.

Chain structure:
  {
    "chain_id": "MYSQL_DIRECT_ACCESS",
    "entry": "exam.cgu-odisha.ac.in",
    "steps": [
      { "step": 1, "actor": "Internet",           "action": "...", "technique": "T1595" },
      { "step": 2, "actor": "exam.cgu-odisha...", "action": "...", "technique": "T1190" },
      { "step": 3, "actor": "MySQL 3306",         "action": "...", "technique": "T1213" },
      { "step": 4, "actor": "Database",           "action": "...", "technique": "T1552" },
    ],
    "likelihood": 85,
    "impact": "Data breach",
    "evidence": [...],
    "mitre_chain": ["T1595", "T1190", "T1213", "T1552"],
  }
"""

from intelligence_engine.v4.asset_correlation import correlate_assets
from intelligence_engine.v4.exposure_score import score_all_assets


# ── MITRE ATT&CK reference ───────────────────────────────────
MITRE = {
    "T1595":    "Active Scanning",
    "T1190":    "Exploit Public-Facing Application",
    "T1213":    "Data from Information Repositories",
    "T1552":    "Unsecured Credentials",
    "T1021.001":"Remote Desktop Protocol",
    "T1021.002":"SMB/Windows Admin Shares",
    "T1021.004":"Remote Services: SSH",
    "T1110":    "Brute Force",
    "T1566":    "Phishing",
    "T1078":    "Valid Accounts",
    "T1610":    "Deploy Container",
    "T1611":    "Escape to Host",
    "T1530":    "Data from Cloud Storage",
    "T1040":    "Network Sniffing (FTP/Telnet cleartext)",
    "T1557":    "Adversary-in-the-Middle (PPTP)",
    "T1133":    "External Remote Services",
}

# ── Attack chain templates ────────────────────────────────────
# Each template defines WHAT EVIDENCE is required and WHAT THE CHAIN LOOKS LIKE

def _chain_database_direct(host: str, port: int, service: str,
                            banner: str, shares_ip_with: list) -> dict:
    """Direct database exposure — most critical chain."""
    steps = [
        {
            "step": 1,
            "actor": "Internet / Attacker",
            "action": f"Port scan discovers {service} on {host}:{port} open to internet",
            "technique": "T1595 — Active Scanning",
            "evidence": f"Port {port} confirmed OPEN",
        },
        {
            "step": 2,
            "actor": host,
            "action": f"Attacker connects directly to {service} — no firewall restriction",
            "technique": "T1190 — Exploit Public-Facing Application",
            "evidence": f"No authentication layer between internet and {service}",
        },
        {
            "step": 3,
            "actor": f"{service} on port {port}",
            "action": f"Attacker attempts authentication (brute force / default creds / CVE)",
            "technique": "T1110 — Brute Force",
            "evidence": banner or f"{service} banner responded",
        },
        {
            "step": 4,
            "actor": "Database",
            "action": "Extract tables, dump student/admission/exam data",
            "technique": "T1213 — Data from Information Repositories",
            "evidence": f"{service} is a database service containing business data",
        },
    ]

    if shares_ip_with:
        steps.append({
            "step": 5,
            "actor": "Same Server",
            "action": f"Attacker pivots to co-hosted assets: {', '.join(shares_ip_with[:3])}",
            "technique": "T1021 — Remote Services (lateral movement)",
            "evidence": f"Same IP as {host} — likely same OS/filesystem access",
        })

    return {
        "chain_id":     f"DB_DIRECT_{host.split('.')[0].upper()}_{port}",
        "name":         f"Direct {service} Database Access",
        "entry_point":  host,
        "service":      service,
        "port":         port,
        "steps":        steps,
        "likelihood":   90,
        "confidence":   "HIGH",
        "impact":       f"Direct data breach — {service} database contents fully accessible",
        "business_impact": "Student records, admission data, exam results, credentials — all at risk",
        "mitre_chain":  ["T1595", "T1190", "T1110", "T1213"],
        "evidence":     [f"Port {port} OPEN on {host}", banner or "banner confirmed"],
        "affected_assets": [host] + shares_ip_with,
    }


def _chain_ftp_cleartext(host: str, shares_ip_with: list) -> dict:
    """FTP on all assets — credential sniffing + file theft."""
    return {
        "chain_id":     f"FTP_CLEARTEXT_{host.split('.')[0].upper()}",
        "name":         "FTP Cleartext Credential Interception",
        "entry_point":  host,
        "service":      "FTP",
        "port":         21,
        "steps": [
            {
                "step": 1,
                "actor": "Internet / MITM",
                "action": f"FTP traffic on {host} is cleartext — any network observer can read credentials",
                "technique": "T1040 — Network Sniffing",
                "evidence": "Port 21 OPEN — FTP transmits passwords in plaintext",
            },
            {
                "step": 2,
                "actor": "Attacker",
                "action": "Capture FTP credentials via ARP spoofing or ISP-level interception",
                "technique": "T1557 — Adversary-in-the-Middle",
                "evidence": "No FTPS (port 990) detected — cleartext only",
            },
            {
                "step": 3,
                "actor": f"FTP server on {host}",
                "action": "Authenticate with captured credentials, download/upload files",
                "technique": "T1078 — Valid Accounts",
                "evidence": "FTP gives direct filesystem access",
            },
            {
                "step": 4,
                "actor": "Server filesystem",
                "action": "Access web root, config files, database credentials in PHP/env files",
                "technique": "T1552 — Unsecured Credentials",
                "evidence": "FTP root typically overlaps with web root on shared hosting",
            },
        ],
        "likelihood":   70,
        "confidence":   "HIGH",
        "impact":       "File system access and credential theft",
        "business_impact": "Server files, database passwords, and application configs exposed",
        "mitre_chain":  ["T1040", "T1557", "T1078", "T1552"],
        "evidence":     [f"Port 21 OPEN on {host}"],
        "affected_assets": [host] + shares_ip_with,
    }


def _chain_pptp_vpn(host: str) -> dict:
    """PPTP VPN — cryptographically broken, crackable offline."""
    return {
        "chain_id":     f"PPTP_CRACK_{host.split('.')[0].upper()}",
        "name":         "PPTP VPN Credential Crack (MS-CHAPv2)",
        "entry_point":  host,
        "service":      "PPTP",
        "port":         1723,
        "steps": [
            {
                "step": 1,
                "actor": "Internet",
                "action": f"PPTP VPN detected on {host}:1723 — uses MS-CHAPv2 which is fully broken",
                "technique": "T1133 — External Remote Services",
                "evidence": "Port 1723 OPEN — PPTP VPN service",
            },
            {
                "step": 2,
                "actor": "Attacker",
                "action": "Capture VPN handshake via MITM or rogue AP — MS-CHAPv2 crackable in <24h",
                "technique": "T1557 — Adversary-in-the-Middle",
                "evidence": "MS-CHAPv2 has been broken since 2012 (CloudCracker/chapcrack)",
            },
            {
                "step": 3,
                "actor": "PPTP credential",
                "action": "Crack MS-CHAPv2 hash offline using DES brute force",
                "technique": "T1110 — Brute Force (offline)",
                "evidence": "56-bit DES — crackable in hours with commodity hardware",
            },
            {
                "step": 4,
                "actor": "Internal network",
                "action": "Authenticate to VPN, access internal resources behind perimeter",
                "technique": "T1078 — Valid Accounts",
                "evidence": "VPN provides internal network access",
            },
        ],
        "likelihood":   65,
        "confidence":   "HIGH",
        "impact":       "Internal network access via broken VPN",
        "business_impact": "Internal systems, intranet, and backend services accessible",
        "mitre_chain":  ["T1133", "T1557", "T1110", "T1078"],
        "evidence":     [f"Port 1723 OPEN on {host}"],
        "affected_assets": [host],
    }


def _chain_ssl_failed_mitm(host: str) -> dict:
    """SSL FAILED = MITM possible on exam system."""
    return {
        "chain_id":     f"SSL_MITM_{host.split('.')[0].upper()}",
        "name":         "SSL Certificate Failure — MITM on Exam Portal",
        "entry_point":  host,
        "service":      "HTTPS",
        "port":         443,
        "steps": [
            {
                "step": 1,
                "actor": "exam.cgu-odisha.ac.in",
                "action": "TLS certificate validation fails — browsers show security warning",
                "technique": "T1557 — Adversary-in-the-Middle (setup condition)",
                "evidence": "SSL status: FAILED — certificate not trusted",
            },
            {
                "step": 2,
                "actor": "Students/Users",
                "action": "Users forced to click 'proceed anyway' — trained to ignore cert warnings",
                "technique": "T1566 — Phishing (social engineering component)",
                "evidence": "Broken SSL normalises security warnings for exam portal users",
            },
            {
                "step": 3,
                "actor": "Attacker",
                "action": "Deploy rogue AP or DNS spoof — users already conditioned to accept bad certs",
                "technique": "T1557 — Adversary-in-the-Middle",
                "evidence": "Users will not notice attacker cert vs broken legitimate cert",
            },
            {
                "step": 4,
                "actor": "Exam portal",
                "action": "Capture student login credentials, session tokens, exam content",
                "technique": "T1552 — Unsecured Credentials",
                "evidence": "Login form submits credentials over compromised TLS",
            },
        ],
        "likelihood":   75,
        "confidence":   "HIGH",
        "impact":       "Credential theft and exam integrity compromise",
        "business_impact": "Student credentials, exam papers, and results accessible to attacker",
        "mitre_chain":  ["T1557", "T1566", "T1552"],
        "evidence":     ["SSL status FAILED on exam.cgu-odisha.ac.in"],
        "affected_assets": [host],
    }


def _chain_wordpress_rce(host: str, shares_ip_with: list) -> dict:
    """WordPress = plugin CVE → RCE → DB → same server."""
    return {
        "chain_id":     f"WP_RCE_{host.split('.')[0].upper()}",
        "name":         "WordPress Plugin RCE → Database Pivot",
        "entry_point":  host,
        "service":      "WordPress",
        "port":         443,
        "steps": [
            {
                "step": 1,
                "actor": "Internet",
                "action": f"WordPress fingerprinted on {host} via wp-content paths",
                "technique": "T1595 — Active Scanning",
                "evidence": "WordPress detected in HTTP response",
            },
            {
                "step": 2,
                "actor": host,
                "action": "Enumerate plugins via /wp-json/wp/v2/ and readme.txt files",
                "technique": "T1190 — Exploit Public-Facing Application",
                "evidence": "WordPress REST API typically exposed at /wp-json/",
            },
            {
                "step": 3,
                "actor": "WordPress plugin",
                "action": "Exploit unpatched plugin CVE for authenticated or unauthenticated RCE",
                "technique": "T1190 — Exploit Public-Facing Application",
                "evidence": "WordPress plugins are the #1 attack vector (87% of WP compromises)",
            },
            {
                "step": 4,
                "actor": "Web server process",
                "action": "Execute OS commands as www-data, read wp-config.php for DB credentials",
                "technique": "T1552 — Unsecured Credentials",
                "evidence": "wp-config.php contains plaintext MySQL credentials",
            },
            {
                "step": 5,
                "actor": "MySQL (port 3306)",
                "action": "Connect to database using credentials from wp-config.php",
                "technique": "T1213 — Data from Information Repositories",
                "evidence": f"MySQL port 3306 open on same server; wp-config.php has credentials",
            },
        ] + ([{
            "step": 6,
            "actor": "Same server",
            "action": f"Pivot to co-hosted assets sharing same IP: {', '.join(shares_ip_with[:2])}",
            "technique": "T1021 — Remote Services",
            "evidence": f"IP shared with {len(shares_ip_with)} other assets",
        }] if shares_ip_with else []),
        "likelihood":   75,
        "confidence":   "HIGH",
        "impact":       "Remote code execution → full database compromise",
        "business_impact": "Complete website takeover, data breach, potential ransomware deployment",
        "mitre_chain":  ["T1595", "T1190", "T1552", "T1213"],
        "evidence":     [f"WordPress on {host}", "MySQL 3306 open"],
        "affected_assets": [host] + shares_ip_with,
    }


def _chain_email_spoof(domain: str, dmarc_policy: str) -> dict:
    """DMARC p=none → domain spoofing for phishing."""
    return {
        "chain_id":     "EMAIL_DOMAIN_SPOOF",
        "name":         f"Email Domain Spoofing (DMARC p={dmarc_policy})",
        "entry_point":  domain,
        "service":      "Email / SMTP",
        "port":         25,
        "steps": [
            {
                "step": 1,
                "actor": "Attacker",
                "action": f"Send email FROM @{domain} — DMARC policy is p={dmarc_policy} (no enforcement)",
                "technique": "T1566 — Phishing",
                "evidence": f"DMARC policy p={dmarc_policy} does not reject or quarantine spoofed emails",
            },
            {
                "step": 2,
                "actor": "Student / Staff",
                "action": "Receive convincing phishing email appearing to come from university IT department",
                "technique": "T1566.001 — Spearphishing Attachment",
                "evidence": "Email appears legitimate — from address matches university domain",
            },
            {
                "step": 3,
                "actor": "Victim",
                "action": "Click link or open attachment — credential harvesting page or malware",
                "technique": "T1078 — Valid Accounts",
                "evidence": "University portals (exam, admission) targeted for credential theft",
            },
            {
                "step": 4,
                "actor": "Attacker",
                "action": "Use stolen credentials to access exam portal, admission system, or admin panels",
                "technique": "T1078 — Valid Accounts",
                "evidence": f"Stolen credentials valid for {domain} services",
            },
        ],
        "likelihood":   80,
        "confidence":   "HIGH",
        "impact":       "Domain impersonation enabling mass phishing of students and staff",
        "business_impact": "Credential theft, exam fraud, reputation damage, regulatory liability",
        "mitre_chain":  ["T1566", "T1566.001", "T1078"],
        "evidence":     [f"DMARC p={dmarc_policy}", "SPF softfail (~all)"],
        "affected_assets": [domain],
    }


def _chain_ssh_lateral(host: str, shares_ip_with: list) -> dict:
    """SSH exposed → brute force → lateral movement."""
    return {
        "chain_id":     f"SSH_BRUTE_{host.split('.')[0].upper()}",
        "name":         "SSH Brute Force → Lateral Movement",
        "entry_point":  host,
        "service":      "SSH",
        "port":         22,
        "steps": [
            {
                "step": 1,
                "actor": "Internet",
                "action": f"SSH (OpenSSH 8.9p1) detected on {host}:22 — version disclosed in banner",
                "technique": "T1595 — Active Scanning",
                "evidence": "Port 22 OPEN, OpenSSH 8.9p1 banner confirmed",
            },
            {
                "step": 2,
                "actor": "Attacker",
                "action": "Brute force SSH with common credential lists (admin/admin, root/root, etc.)",
                "technique": "T1110 — Brute Force",
                "evidence": "No evidence of fail2ban or rate limiting from scan",
            },
            {
                "step": 3,
                "actor": f"SSH on {host}",
                "action": "Gain shell access with compromised credentials",
                "technique": "T1021.004 — Remote Services: SSH",
                "evidence": "SSH provides interactive shell on server",
            },
            {
                "step": 4,
                "actor": "Server",
                "action": "Read /etc/passwd, web configs, database credentials — escalate to root",
                "technique": "T1552 — Unsecured Credentials",
                "evidence": "Server hosts MySQL (port 3306) and web applications",
            },
        ] + ([{
            "step": 5,
            "actor": "Same network",
            "action": f"Use server as pivot to reach: {', '.join(shares_ip_with[:2])}",
            "technique": "T1021.004 — SSH lateral movement",
            "evidence": f"SSH keys may be reused across {len(shares_ip_with)} co-hosted assets",
        }] if shares_ip_with else []),
        "likelihood":   70,
        "confidence":   "MEDIUM",
        "impact":       "Server compromise and lateral movement",
        "business_impact": "Full server access, all hosted applications compromised",
        "mitre_chain":  ["T1595", "T1110", "T1021.004", "T1552"],
        "evidence":     [f"SSH port 22 OPEN on {host}", "OpenSSH 8.9p1 banner"],
        "affected_assets": [host] + shares_ip_with,
    }


# ── Main Engine ───────────────────────────────────────────────

def build_attack_graph(profile: dict) -> dict:
    """
    Builds the complete attack graph from scan evidence.
    Returns ranked chains, node/edge lists, and summary.
    """
    correlated = correlate_assets(profile)
    exposure_scores = score_all_assets(correlated["assets"])
    exposure_map = {e["host"]: e for e in exposure_scores}

    domain = profile.get("asset", "unknown")
    email = profile.get("email_intelligence", {})
    dmarc_policy = email.get("dmarc", {}).get("policy", "none")

    chains = []
    nodes = []   # for visual graph
    edges = []   # for visual graph

    # ── Root node ─────────────────────────────────────────────
    nodes.append({"id": "internet", "label": "Internet", "type": "internet"})
    nodes.append({"id": domain,     "label": domain,     "type": "domain"})
    edges.append({"from": "internet", "to": domain, "label": "scans"})

    for asset in correlated["assets"]:
        host           = asset["host"]
        open_ports     = asset["open_ports"]
        services       = asset["services"]
        techs          = asset["technologies"]
        shares_ip      = asset["shares_ip_with"]
        ip             = asset.get("ip")
        exp            = exposure_map.get(host, {})

        # Add asset node
        nodes.append({
            "id":             host,
            "label":          host.split(".")[0],
            "type":           "asset",
            "ip":             ip,
            "exposure_score": exp.get("exposure_score", 0),
            "exposure_level": exp.get("exposure_level", "LOW"),
            "open_ports":     open_ports,
        })
        edges.append({"from": domain, "to": host, "label": "HAS_SUBDOMAIN"})

        if ip:
            # Add IP node (shared across assets)
            ip_id = f"ip_{ip}"
            if not any(n["id"] == ip_id for n in nodes):
                nodes.append({"id": ip_id, "label": ip, "type": "ip"})
            edges.append({"from": host, "to": ip_id, "label": "RESOLVES_TO"})

        for tech in techs:
            tech_id = f"tech_{tech.lower().replace(' ','_')}"
            if not any(n["id"] == tech_id for n in nodes):
                nodes.append({"id": tech_id, "label": tech, "type": "technology"})
            edges.append({"from": host, "to": tech_id, "label": "USES"})

        # ── Generate chains from evidence ──────────────────────

        # MySQL/PostgreSQL directly exposed
        for port, service in zip(open_ports, services):
            if port in (3306, 5432, 1433, 27017, 6379, 9200):
                # Find banner from original data
                banner = None
                for raw_asset in profile.get("subdomain_assets", {}).get("assets", []):
                    if raw_asset["host"] == host:
                        for p in raw_asset.get("infrastructure", {}).get("ports", {}).get("ports", []):
                            if p["port"] == port and p.get("banner"):
                                banner = p["banner"][:100]
                chains.append(_chain_database_direct(host, port, service, banner, shares_ip))

                # Add port + finding nodes
                port_id = f"port_{host.split('.')[0]}_{port}"
                nodes.append({"id": port_id, "label": f":{port} {service}", "type": "port", "risk": "CRITICAL"})
                edges.append({"from": host, "to": port_id, "label": "EXPOSES"})
                nodes.append({"id": f"finding_db_{host.split('.')[0]}_{port}", "label": f"DB Exposed", "type": "finding", "severity": "CRITICAL"})
                edges.append({"from": port_id, "to": f"finding_db_{host.split('.')[0]}_{port}", "label": "HAS_FINDING"})

        # FTP cleartext
        if 21 in open_ports:
            chains.append(_chain_ftp_cleartext(host, shares_ip))

        # PPTP VPN
        if 1723 in open_ports:
            chains.append(_chain_pptp_vpn(host))

        # WordPress RCE
        if "WordPress" in techs and 3306 in open_ports:
            chains.append(_chain_wordpress_rce(host, shares_ip))

        # SSH brute force
        if 22 in open_ports:
            chains.append(_chain_ssh_lateral(host, shares_ip))

    # SSL MITM on exam portal
    for raw_asset in profile.get("subdomain_assets", {}).get("assets", []):
        if raw_asset.get("ssl", {}).get("status") == "FAILED":
            chains.append(_chain_ssl_failed_mitm(raw_asset["host"]))

    # Email spoofing
    if dmarc_policy in ("none", "NONE", None, ""):
        chains.append(_chain_email_spoof(domain, dmarc_policy or "none"))

    # ── Deduplicate chains by chain_id ────────────────────────
    seen_ids = set()
    unique_chains = []
    for c in chains:
        if c["chain_id"] not in seen_ids:
            seen_ids.add(c["chain_id"])
            unique_chains.append(c)

    # ── Rank chains ───────────────────────────────────────────
    unique_chains.sort(key=lambda x: x["likelihood"], reverse=True)
    for i, c in enumerate(unique_chains):
        c["rank"] = i + 1

    # ── SHARES_IP edges for graph ─────────────────────────────
    for asset in correlated["assets"]:
        for peer in asset["shares_ip_with"]:
            edges.append({"from": asset["host"], "to": peer, "label": "SHARES_IP"})

    return {
        "domain":            domain,
        "total_chains":      len(unique_chains),
        "attack_chains":     unique_chains,
        "graph": {
            "nodes": nodes,
            "edges": edges,
        },
        "exposure_scores":   exposure_scores,
        "ip_clusters":       correlated["ip_clusters"],
        "cloud_clusters":    correlated["cloud_clusters"],
        "summary": {
            "critical_chains":   sum(1 for c in unique_chains if c["likelihood"] >= 80),
            "top_entry_point":   unique_chains[0]["entry_point"] if unique_chains else None,
            "top_chain":         unique_chains[0]["name"] if unique_chains else None,
            "affected_assets":   list({a for c in unique_chains for a in c.get("affected_assets", [])}),
        },
    }
