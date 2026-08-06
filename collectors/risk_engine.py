from datetime import datetime





# =====================================================
# FINDING CREATOR
# =====================================================

def add_finding(
        findings,
        category,
        issue,
        severity,
        score,
        confidence="MEDIUM",
        impact="TECHNICAL",
        recommendation=""
):

    findings.append({

        "category": category,

        "issue": issue,

        "severity": severity,

        "score": score,

        "confidence": confidence,

        "impact": impact,

        "recommendation": recommendation

    })





# =====================================================
# ASSET CRITICALITY
# =====================================================

def analyze_asset_criticality(profile, findings):

    score = 0


    domain = profile.get(
        "asset",
        ""
    ).lower()


    critical_keywords=[

        "admin",
        "login",
        "portal",
        "api",
        "vpn",
        "mail",
        "erp",
        "cloud"

    ]


    for keyword in critical_keywords:


        if keyword in domain:


            add_finding(

                findings,

                "Asset Criticality",

                f"Critical asset keyword detected: {keyword}",

                "HIGH",

                10,

                "HIGH",

                "BUSINESS",

                "Review exposure and access controls"

            )


            score += 10

            break



    return min(score,15)







# =====================================================
# SSL SECURITY
# =====================================================

def analyze_ssl(profile, findings):


    score=0


    ssl=profile.get(

        "ssl_intelligence",

        {}

    )


    if not ssl:


        add_finding(

            findings,

            "SSL",

            "SSL information unavailable",

            "MEDIUM",

            10

        )


        return 10





    if ssl.get(

        "status"

    )!="VALID":


        add_finding(

            findings,

            "SSL",

            "Invalid SSL certificate",

            "HIGH",

            20,

            "HIGH",

            "TECHNICAL",

            "Renew or fix certificate chain"

        )


        score+=20




    tls=ssl.get(

        "tls_version"

    )


    if tls in [

        "TLSv1",

        "TLSv1.1"

    ]:


        add_finding(

            findings,

            "SSL",

            f"Weak TLS version {tls}",

            "HIGH",

            15,

            "HIGH",

            "TECHNICAL",

            "Upgrade TLS configuration"

        )


        score+=15



    return score







# =====================================================
# CERTIFICATE EXPIRY
# =====================================================

def analyze_certificate_expiry(profile, findings):


    ssl=profile.get(

        "ssl_intelligence",

        {}

    )


    expiry=ssl.get(

        "valid_until"

    )


    if not expiry:

        return 0



    try:


        cert_date=datetime.strptime(

            expiry,

            "%b %d %H:%M:%S %Y %Z"

        )


        days=(cert_date-datetime.utcnow()).days



        if days < 15:


            add_finding(

                findings,

                "SSL",

                f"Certificate expires in {days} days",

                "HIGH",

                15,

                "HIGH",

                "OPERATIONAL",

                "Renew certificate"

            )


            return 15



        elif days < 30:


            add_finding(

                findings,

                "SSL",

                f"Certificate expires soon ({days} days)",

                "MEDIUM",

                8

            )


            return 8



    except Exception:

        pass



    return 0








# =====================================================
# SECURITY HEADERS
# =====================================================

def analyze_headers(profile, findings):


    score=0


    tech=profile.get(

        "technology_intelligence",

        {}

    )


    headers=tech.get(

        "security_headers",

        {}

    )



    security_headers={


        "strict-transport-security":4,

        "content-security-policy":5,

        "x-frame-options":3,

        "x-content-type-options":3,

        "referrer-policy":2,

        "permissions-policy":2

    }



    for header,value in security_headers.items():


        data=headers.get(

            header,

            {}

        )


        if not data.get(

            "present",

            False

        ):



            add_finding(

                findings,

                "Security Headers",

                f"Missing {header}",

                "MEDIUM",

                value,

                "MEDIUM",

                "TECHNICAL",

                f"Implement {header}"

            )


            score+=value



    return min(score,25)









# =====================================================
# CSP SECURITY
# =====================================================

def analyze_csp(profile, findings):


    csp=profile.get(

        "csp_intelligence",

        {}

    )



    if not csp.get(

        "enabled",

        False

    ):


        add_finding(

            findings,

            "CSP",

            "Content Security Policy missing",

            "MEDIUM",

            10,

            "HIGH",

            "TECHNICAL",

            "Deploy restrictive CSP"

        )


        return 10



    if csp.get(

        "risk_level",

        ""

    ).upper()=="HIGH":



        add_finding(

            findings,

            "CSP",

            "Unsafe CSP configuration",

            "HIGH",

            10,

            "MEDIUM",

            "TECHNICAL",

            "Remove unsafe directives"

        )


        return 10



    return 0







# =====================================================
# EMAIL SECURITY
# =====================================================

def analyze_email(profile, findings):


    score=0


    email=profile.get(

        "email_intelligence",

        {}

    )


    if not email:

        return 0




    dmarc=email.get(

        "dmarc",

        {}

    )


    if dmarc.get(

        "policy"

    )=="none":


        add_finding(

            findings,

            "Email Security",

            "DMARC policy monitoring only",

            "MEDIUM",

            8,

            "HIGH",

            "BUSINESS",

            "Move DMARC policy to quarantine/reject"

        )


        score+=8




    dkim=email.get(

        "dkim",

        {}

    )


    if dkim.get(

        "status"

    )=="NOT_FOUND":



        add_finding(

            findings,

            "Email Security",

            "DKIM selector not detected",

            "MEDIUM",

            5,

            "MEDIUM",

            "TECHNICAL",

            "Enable DKIM signing"

        )


        score+=5



    return score








# =====================================================
# SUBDOMAIN EXPOSURE
# =====================================================

def analyze_subdomains(profile, findings):


    score=0


    assets=profile.get(

        "subdomain_assets",

        {}

    ).get(

        "assets",

        []

    )



    sensitive=[

        "admin",

        "dev",

        "test",

        "staging",

        "backup",

        "vpn",

        "internal",

        "api"

    ]



    for asset in assets:


        host=asset.get(

            "host",

            ""

        ).lower()



        for word in sensitive:


            if word in host:


                add_finding(

                    findings,

                    "Attack Surface",

                    f"Sensitive subdomain exposed: {host}",

                    "HIGH",

                    10,

                    "HIGH",

                    "BUSINESS",

                    "Review external exposure"

                )


                score+=10

                break



    return min(score,25)







# =====================================================
# TECHNOLOGY RISK
# =====================================================

def analyze_technology(profile, findings):


    score=0


    tech=profile.get(

        "technology_intelligence",

        {}

    )


    raw_techs = tech.get("technologies", [])

    technologies = [

        (x["name"].lower() if isinstance(x, dict) else x.lower())

        for x in raw_techs

    ]



    for item in [

        "wordpress",

        "apache",

        "nginx"

    ]:


        if item in technologies:


            add_finding(

                findings,

                "Technology",

                f"Technology fingerprint exposed: {item}",

                "LOW",

                3,

                "LOW",

                "TECHNICAL",

                "Review version and vulnerabilities"

            )


            score+=3



    return min(score,10)







# =====================================================
# DNS
# =====================================================

def analyze_dns(profile, findings):


    dns=profile.get(

        "dns_intelligence",

        {}

    )


    if dns.get(

        "error"

    ):


        add_finding(

            findings,

            "DNS",

            "DNS resolution failure",

            "LOW",

            5

        )


        return 5



    return 0







# =====================================================
# MAIN RISK ENGINE
# =====================================================

def calculate_risk(profile):


    findings=[]


    score=0



    modules=[

        analyze_asset_criticality,

        analyze_ssl,

        analyze_certificate_expiry,

        analyze_headers,

        analyze_csp,

        analyze_email,

        analyze_subdomains,

        analyze_technology,

        analyze_dns

    ]



    for module in modules:


        score += module(

            profile,

            findings

        )



    score=min(

        score,

        100

    )





    if score>=75:

        severity="CRITICAL"


    elif score>=50:

        severity="HIGH"


    elif score>=25:

        severity="MEDIUM"


    else:

        severity="LOW"





    return {


        "engine":

        "SentinelX ASM Risk Engine v3",


        "risk_score":

        score,


        "severity":

        severity,


        "total_findings":

        len(findings),


        "scan_time":

        datetime.utcnow().isoformat()+"Z",


        "findings":

        findings,


        "summary":

        {

            "critical_findings":

            len(

                [

                x for x in findings

                if x["severity"]=="HIGH"

                ]

            ),

            "recommendation":

            "Prioritize internet exposed assets and high confidence findings"

        }


    }







if __name__=="__main__":

    print(
        "SentinelX ASM Risk Engine v3 Loaded"
    )