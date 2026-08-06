"""
SentinelX Asset Enrichment Engine v3.0

Phase 1 + Phase 2 Integration

Pipeline:

Domain/Subdomain
        |
        |
        + DNS Intelligence
        |
        + SSL Intelligence
        |
        + HTTP Intelligence
        |
        + Infrastructure Intelligence
                |
                + ASN
                + GeoIP
                + Cloud
                + Reverse DNS
                + CDN
                + Ports
                + Services
                + Exposure Score
        |
        |
        Risk Engine
        |
        |
        Asset Intelligence JSON


SentinelX ASM Platform
"""


import json


from datetime import datetime, timezone


from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed
)



# =====================================================
# SentinelX Collectors
# =====================================================


from collectors.infrastructure_intelligence import (
    get_infrastructure_info
)


from collectors.dns_intelligence import (
    resolve_dns
)


from collectors.ssl_intelligence import (
    get_ssl_info
)


from collectors.http_intelligence import (
    get_http_info
)




# =====================================================
# RISK ENGINE V3
# =====================================================


def calculate_risk(asset):


    score = 0


    findings = []



    # =================================================
    # Infrastructure Risk
    # =================================================


    infrastructure = asset.get(
        "infrastructure",
        {}
    )


    ports_data = infrastructure.get(
        "ports",
        {}
    )


    ports = ports_data.get(
        "ports",
        []
    )



    for item in ports:


        port = item.get(
            "port"
        )


        service = item.get(
            "service",
            "UNKNOWN"
        )


        risk = item.get(
            "risk"
        )



        if risk == "CRITICAL":


            score += 25


            findings.append({

                "category":
                "Infrastructure",


                "issue":
                f"Critical exposed service {service} on port {port}",


                "severity":
                "CRITICAL",


                "port":
                port,


                "recommendation":
                "Restrict external access immediately"

            })



        elif risk == "HIGH":


            score += 15


            findings.append({

                "category":
                "Infrastructure",


                "issue":
                f"High risk service exposed {service} on port {port}",


                "severity":
                "HIGH",


                "port":
                port,


                "recommendation":
                "Restrict access using firewall/VPN"

            })



        elif port in [
            21,
            22,
            3389
        ]:


            score += 10


            findings.append({

                "category":
                "Infrastructure",


                "issue":
                f"Sensitive service exposed {service}",


                "severity":
                "MEDIUM",


                "port":
                port

            })





    # =================================================
    # Exposure Score
    # =================================================


    exposure = infrastructure.get(
        "exposure_score",
        0
    )



    if exposure >= 50:


        score += 20


        findings.append({

            "category":
            "Infrastructure",


            "issue":
            f"High infrastructure exposure score: {exposure}",


            "severity":
            "HIGH",


            "recommendation":
            "Review exposed services"

        })





    # =================================================
    # Cloud Intelligence
    # =================================================


    cloud = infrastructure.get(
        "cloud",
        {}
    )


    if isinstance(cloud, dict):


        provider = cloud.get(
            "provider"
        )


    else:

        provider = cloud



    if provider:


        findings.append({

            "category":
            "Infrastructure",


            "issue":
            f"Cloud hosted asset detected: {provider}",


            "severity":
            "INFO"

        })






    # =================================================
    # SSL Security
    # =================================================


    ssl = asset.get(
        "ssl",
        {}
    )



    ssl_status = ssl.get(
        "ssl",
        {}
    ).get(
        "status"
    )



    if ssl_status != "VALID":


        score +=20


        findings.append({

            "category":
            "SSL",


            "issue":
            "Invalid SSL certificate",


            "severity":
            "HIGH"

        })






    # =================================================
    # HTTP Security Headers
    # =================================================


    http = asset.get(
        "http",
        {}
    )


    headers = http.get(
        "security_headers",
        {}
    )



    if http.get(
        "reachable"
    ):


        if not headers.get(
            "strict-transport-security",
            {}
        ).get(
            "present"
        ):


            score +=10


            findings.append({

                "category":
                "Web Security",


                "issue":
                "Missing HSTS header",


                "severity":
                "LOW"

            })




        if not headers.get(
            "content-security-policy",
            {}
        ).get(
            "present"
        ):


            score +=10


            findings.append({

                "category":
                "Web Security",


                "issue":
                "Missing Content Security Policy",


                "severity":
                "LOW"

            })






    # =================================================
    # WAF / CDN Protection
    # =================================================


    waf = http.get(
        "waf",
        {}
    )


    cdn = infrastructure.get(
        "cdn",
        {}
    )



    waf_detected = waf.get(
        "detected",
        False
    )


    cdn_detected = cdn.get(
        "detected",
        False
    )



    if (
        waf_detected is False
        and
        cdn_detected is False
    ):


        score +=5


        findings.append({

            "category":
            "Web Security",


            "issue":
            "No WAF/CDN protection detected",


            "severity":
            "INFO",


            "recommendation":
            "Deploy WAF protection"

        })






    # =================================================
    # Final Score
    # =================================================


    score = min(
        score,
        100
    )



    if score >=70:

        severity="CRITICAL"


    elif score >=40:

        severity="HIGH"


    elif score >=20:

        severity="MEDIUM"


    else:

        severity="LOW"




    return {


        "score":
        score,


        "severity":
        severity,


        "findings":
        findings


    }






# =====================================================
# SINGLE ASSET ENRICHMENT
# =====================================================


def enrich_subdomain(host):


    print(
        f"[+] Scanning {host}"
    )



    asset = {


        "host":
        host,


        "timestamp":
        datetime.now(
            timezone.utc
        ).isoformat(),


        "dns":
        {},


        "ssl":
        {},


        "http":
        {},


        "infrastructure":
        {},


        "risk":
        {}

    }



    # =================================================
    # DNS
    # =================================================


    try:


        asset["dns"] = resolve_dns(
            host
        )


    except Exception as e:


        asset["dns"]={

            "error":
            str(e)

        }




    # =================================================
    # SSL
    # =================================================


    try:


        asset["ssl"] = get_ssl_info(
            host
        )


    except Exception as e:


        asset["ssl"]={

            "error":
            str(e)

        }




    # =================================================
    # HTTP
    # =================================================


    try:


        asset["http"] = get_http_info(
            host
        )


    except Exception as e:


        asset["http"]={

            "reachable":
            False,

            "error":
            str(e)

        }




    # =================================================
    # INFRASTRUCTURE PHASE 2
    # =================================================


    try:


        asset["infrastructure"] = get_infrastructure_info(
            host
        )



    except Exception as e:


        asset["infrastructure"]={

            "error":
            str(e)

        }





    # =================================================
    # RISK
    # =================================================


    asset["risk"] = calculate_risk(
        asset
    )



    return asset
  # =====================================================
# MULTI SUBDOMAIN ENRICHMENT ENGINE
# =====================================================


def enrich_all_subdomains(subdomain_result):


    assets = []



    hosts = [

        item.get(
            "host"
        )

        for item in subdomain_result.get(
            "subdomains",
            []
        )

        if item.get(
            "host"
        )

    ]



    print(
        f"[+] Starting enrichment for {len(hosts)} assets"
    )



    with ThreadPoolExecutor(
        max_workers=10
    ) as executor:



        futures = {


            executor.submit(
                enrich_subdomain,
                host
            ): host


            for host in hosts


        }



        for future in as_completed(
            futures
        ):



            host = futures[future]



            try:


                result = future.result()


                assets.append(
                    result
                )



            except Exception as e:



                assets.append({

                    "host":
                    host,


                    "status":
                    "FAILED",


                    "error":
                    str(e)

                })







    # Sort alphabetically


    assets.sort(

        key=lambda x:

        x.get(
            "host",
            ""
        )

    )





    return {



        "domain":

        subdomain_result.get(
            "domain"
        ),



        "engine":

        "SentinelX ASM Asset Intelligence Engine v3.0",



        "timestamp":

        datetime.now(
            timezone.utc
        ).isoformat(),



        "total_assets":

        len(assets),



        "assets":

        assets

    }







# =====================================================
# SAVE REPORT
# =====================================================


def save_asset_report(
        data,
        filename="asset_intelligence.json"
):



    with open(

        filename,

        "w",

        encoding="utf-8"

    ) as file:


        json.dump(

            data,

            file,

            indent=4

        )



    print(
        f"[+] Report saved: {filename}"
    )







# =====================================================
# SINGLE DOMAIN TEST
# =====================================================


def scan_domain(target):


    result = enrich_subdomain(
        target
    )


    save_asset_report(
        result
    )


    return result







# =====================================================
# CLI TEST MODE
# =====================================================


if __name__ == "__main__":



    target = input(
        "Enter domain/subdomain: "
    ).strip().lower()



    result = scan_domain(
        target
    )



    print()



    print(
        json.dumps(
            result,
            indent=4
        )
    )