import socket
import ssl
import requests
import time

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collectors.infrastructure_intelligence import (
    get_infrastructure_info
)


USER_AGENT = {
    "User-Agent": "SentinelX-V2-ASM-Engine"
}



# =====================================================
# DNS INTELLIGENCE
# =====================================================

def resolve_dns(host):

    result = {

        "host": host,

        "A": [],

        "AAAA": [],

        "CNAME": []

    }


    # IPv4

    try:

        result["A"] = socket.gethostbyname_ex(host)[2]


    except Exception:

        pass



    # IPv6

    try:

        ipv6 = socket.getaddrinfo(
            host,
            None,
            socket.AF_INET6
        )

        result["AAAA"] = list(
            set(
                x[4][0]
                for x in ipv6
            )
        )


    except Exception:

        pass



    # CNAME

    try:

        cname = socket.gethostbyname_ex(host)[0]

        if cname != host:

            result["CNAME"].append(cname)


    except Exception:

        pass



    return result





# =====================================================
# SSL INTELLIGENCE
# =====================================================


def parse_cert(data):

    output={}


    try:

        for item in data:

            for k,v in item:

                output[k]=v


    except Exception:

        pass


    return output




def get_ssl_info(host):


    result={

        "status":"FAILED"

    }


    try:


        context = ssl.create_default_context()


        start=time.time()


        with socket.create_connection(
            (host,443),
            timeout=5
        ) as sock:


            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as ssock:


                cert=ssock.getpeercert()


                result={

                    "status":"VALID",

                    "issuer":
                    parse_cert(
                        cert.get(
                            "issuer",
                            []
                        )
                    ),


                    "subject":
                    parse_cert(
                        cert.get(
                            "subject",
                            []
                        )
                    ),


                    "valid_from":
                    cert.get(
                        "notBefore"
                    ),


                    "valid_until":
                    cert.get(
                        "notAfter"
                    ),


                    "tls_version":
                    ssock.version(),


                    "response_time":
                    round(
                        time.time()-start,
                        3
                    )

                }



    except Exception as e:


        result={

            "status":"FAILED",

            "error":str(e)

        }



    return result





# =====================================================
# SECURITY HEADERS
# =====================================================


SECURITY_HEADERS=[

    "strict-transport-security",

    "content-security-policy",

    "x-frame-options",

    "x-content-type-options",

    "referrer-policy",

    "permissions-policy"

]




def analyze_headers(headers):


    result={}


    lower={

        k.lower():v

        for k,v in headers.items()

    }



    for h in SECURITY_HEADERS:


        result[h]={

            "present":
            h in lower,


            "value":
            lower.get(h)

        }



    return result


# =====================================================
# TECHNOLOGY FINGERPRINTING
# =====================================================


def detect_technologies(headers, html):


    technologies=[]


    data = (
        str(headers)
        +
        html
    ).lower()



    fingerprints={


        "Cloudflare":[
            "cf-ray",
            "cloudflare"
        ],


        "Akamai":[
            "akamai"
        ],


        "Nginx":[
            "nginx"
        ],


        "Apache":[
            "apache"
        ],


        "IIS":[
            "microsoft-iis"
        ],


        "WordPress":[
            "wp-content",
            "wordpress"
        ],


        "React":[
            "react",
            "__react"
        ],


        "Next.js":[
            "next.js",
            "__next"
        ],


        "Vue.js":[
            "vue"
        ],


        "Angular":[
            "ng-version"
        ],


        "Bootstrap":[
            "bootstrap"
        ]


    }





    for tech, signatures in fingerprints.items():


        for sig in signatures:


            if sig in data:


                technologies.append({

                    "name":tech,

                    "evidence":sig

                })


                break



    return technologies






# =====================================================
# COOKIE ANALYSIS
# =====================================================


def analyze_cookies(response):


    cookies=[]


    try:


        for cookie in response.cookies:


            cookies.append({


                "name":
                cookie.name,


                "secure":
                cookie.secure,


                "httponly":
                "httponly"
                in str(
                    cookie._rest
                ).lower(),


                "samesite":
                cookie._rest.get(
                    "SameSite"
                )

            })


    except Exception:

        pass



    return cookies





# =====================================================
# WAF DETECTION
# =====================================================


def detect_waf(headers):


    data=str(
        headers
    ).lower()



    waf_signatures={


        "Cloudflare":[
            "cf-ray",
            "cloudflare"
        ],


        "Akamai":[
            "akamai"
        ],


        "Imperva":[
            "imperva"
        ],


        "Sucuri":[
            "sucuri"
        ]

    }



    for name,signatures in waf_signatures.items():


        for sig in signatures:


            if sig in data:


                return {

                    "detected":True,

                    "provider":name

                }



    return {


        "detected":False

    }





# =====================================================
# HTTP INTELLIGENCE
# =====================================================


def get_http_info(host):


    result={


        "reachable":False,

        "url":None,

        "status_code":None,

        "response_time":None,

        "server":None,

        "powered_by":None,

        "technologies":[],

        "security_headers":{},

        "csp_raw":None,

        "cookies":[],

        "waf":{},

        "headers":{}

    }





    urls=[

        f"https://{host}",

        f"http://{host}"

    ]





    for url in urls:


        try:


            start=time.time()



            response=requests.get(

                url,

                timeout=8,

                allow_redirects=True,

                headers=USER_AGENT,

                verify=False

            )



            elapsed=round(

                time.time()-start,

                3

            )



            headers=response.headers



            html=response.text[:500000].lower()



            result.update({


                "reachable":True,


                "url":
                response.url,


                "status_code":
                response.status_code,


                "response_time":
                elapsed,


                "server":
                headers.get(
                    "Server"
                ),


                "powered_by":
                headers.get(
                    "X-Powered-By"
                ),


                "headers":
                dict(headers),


                "security_headers":
                analyze_headers(
                    headers
                ),


                "csp_raw":
                headers.get(
                    "Content-Security-Policy"
                ),


                "cookies":
                analyze_cookies(
                    response
                ),


                "technologies":
                detect_technologies(
                    headers,
                    html
                ),


                "waf":
                detect_waf(
                    headers
                )


            })



            return result



        except Exception:


            continue




    result["error"]="HTTP unreachable"


    return result


# =====================================================
# RISK ENGINE V2
# =====================================================


def calculate_risk(asset):


    score = 0

    findings = []

        # =====================================
    # Infrastructure Risk
    # =====================================


    infra = asset.get(
        "infrastructure",
        {}
    )


    ports = infra.get(
        "ports",
        {}
    )



    for port in ports.get(
        "ports",
        []
    ):


        if port.get(
            "risk"
        ) == "CRITICAL":


            score += 25


            findings.append({

                "issue":
                f"Critical service exposed: {port.get('service')} on port {port.get('port')}",

                "severity":
                "CRITICAL"

            })



        elif port.get(
            "risk"
        ) == "HIGH":


            score += 15


            findings.append({

                "issue":
                f"High risk service exposed: {port.get('service')}",

                "severity":
                "HIGH"

            })

    host = asset["host"].lower()



    # Sensitive asset names

    sensitive_keywords = [

        "admin",
        "administrator",
        "dev",
        "development",
        "test",
        "staging",
        "stage",
        "backup",
        "old",
        "vpn",
        "internal",
        "portal",
        "login"

    ]



    for keyword in sensitive_keywords:


        if keyword in host:


            score += 10


            findings.append({

                "issue":
                f"Sensitive hostname detected: {keyword}",

                "severity":
                "MEDIUM"

            })





    # SSL

    if asset["ssl"].get(
        "status"
    ) != "VALID":


        score += 20


        findings.append({

            "issue":
            "SSL certificate invalid or unavailable",

            "severity":
            "HIGH"

        })





    # HTTP exposure


    if asset["http"].get(
        "reachable"
    ):


        headers = asset["http"].get(
            "security_headers",
            {}
        )


        if not headers.get(
            "strict-transport-security",
            {}
        ).get(
            "present"
        ):


            score += 10


            findings.append({

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


            score += 10


            findings.append({

                "issue":
                "Missing Content Security Policy",

                "severity":
                "LOW"

            })





    # WAF absence


    if asset["http"].get(
        "waf",
        {}
    ).get(
        "detected"
    ) == False:


        score += 5


        findings.append({

            "issue":
            "No WAF/CDN detected",

            "severity":
            "INFO"

        })





    if score >= 50:

        severity="CRITICAL"

    elif score >=35:

        severity="HIGH"

    elif score >=20:

        severity="MEDIUM"

    else:

        severity="LOW"




    return {


        "score":score,


        "severity":severity,


        "findings":findings


    }







# =====================================================
# SINGLE ASSET ENRICHMENT
# =====================================================


def enrich_subdomain(host):


    asset={


        "host":host,


        "timestamp":
        datetime.utcnow().isoformat()
        +"Z",



        "dns":{},


        "ssl":{},


        "http":{},

        "infrastructure":{},

        "risk":{}


    }



    print(
        f"[+] Scanning {host}"
    )



    # DNS

    asset["dns"] = resolve_dns(
        host
    )



    # SSL

    asset["ssl"] = get_ssl_info(
        host
    )



    # HTTP

    asset["http"] = get_http_info(
        host
    )
    
    # Infrastructure Intelligence

    asset["infrastructure"] = get_infrastructure_info(
        host
    )



    # Risk

    asset["risk"] = calculate_risk(
        asset
    )



    return asset







# =====================================================
# PARALLEL SCANNER
# =====================================================


def enrich_all_subdomains(subdomain_result):


    assets=[]


    hosts=[

        item["host"]

        for item

        in subdomain_result.get(
            "subdomains",
            []
        )

    ]




    print(
        f"[+] Starting enrichment for {len(hosts)} assets"
    )



    with ThreadPoolExecutor(
        max_workers=10
    ) as executor:



        jobs={

            executor.submit(
                enrich_subdomain,
                host
            ):host

            for host in hosts

        }




        for future in as_completed(jobs):


            host=jobs[future]


            try:


                assets.append(
                    future.result()
                )



            except Exception as e:


                assets.append({

                    "host":host,

                    "error":str(e)

                })





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



        "timestamp":
        datetime.utcnow().isoformat()
        +"Z",



        "total_assets":
        len(assets),



        "assets":
        assets

    }








# =====================================================
# TEST MODE
# =====================================================


if __name__ == "__main__":


    target=input(
        "Enter subdomain: "
    ).strip().lower()



    result=enrich_subdomain(
        target
    )



    import json


    print(
        json.dumps(
            result,
            indent=4
        )
    )