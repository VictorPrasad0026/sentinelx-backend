"""
SentinelX CDN Detection Engine v1.0

Purpose:
    Detect CDN/WAF providers protecting
    internet-facing assets.

Detection Sources:

1. DNS Nameservers
2. CNAME Records
3. HTTP Headers
4. IP Provider Patterns


Output:

Domain
 |
 CDN Provider
 |
 Confidence
 |
 Evidence

"""


import socket
import requests
from datetime import datetime, timezone



# ==========================================================
# CDN Fingerprints
# ==========================================================


CDN_SIGNATURES = {


    "Cloudflare": {

        "nameservers": [

            "cloudflare"

        ],

        "headers": [

            "cf-ray",

            "cf-cache-status",

            "server: cloudflare"

        ],

        "cname": [

            "cloudflare"

        ]

    },



    "Akamai": {


        "nameservers": [

            "akama"

        ],

        "headers": [

            "akamai"

        ],

        "cname": [

            "akamai"

        ]

    },



    "AWS CloudFront": {


        "cname":[

            "cloudfront"

        ],

        "headers":[

            "x-amz-cf-id",

            "x-cache"

        ]

    },



    "Fastly": {


        "headers":[

            "x-served-by",

            "fastly"

        ],

        "cname":[

            "fastly"

        ]

    }



}





# ==========================================================
# DNS Lookup
# ==========================================================


def get_dns_text(domain):


    records=[]


    try:


        import dns.resolver


        for record_type in [
            "NS",
            "CNAME"
        ]:


            try:


                answers=dns.resolver.resolve(
                    domain,
                    record_type
                )


                for r in answers:

                    records.append(
                        str(r).lower()
                    )


            except:

                pass



    except:

        pass



    return records





# ==========================================================
# Header Detection
# ==========================================================


def get_headers(domain):


    try:


        response=requests.get(

            "https://" + domain,

            timeout=5,

            allow_redirects=True

        )


        headers=[]


        for k,v in response.headers.items():


            headers.append(

                f"{k}:{v}"

                .lower()

            )



        return headers



    except:


        return []







# ==========================================================
# CDN Analyzer
# ==========================================================


def detect_cdn(domain):


    evidence=[]

    provider=None

    confidence="LOW"



    dns_data=get_dns_text(
        domain
    )



    headers=get_headers(
        domain
    )




    combined_dns=" ".join(
        dns_data
    )



    combined_headers=" ".join(
        headers
    )




    for name, signature in CDN_SIGNATURES.items():



        # DNS Check

        for keyword in signature.get(
            "nameservers",
            []
        ):


            if keyword in combined_dns:


                provider=name

                evidence.append(

                    f"{name} nameserver detected"

                )


        # CNAME Check

        for keyword in signature.get(
            "cname",
            []
        ):


            if keyword in combined_dns:


                provider=name

                evidence.append(

                    f"{name} CNAME detected"

                )



        # Header Check


        for keyword in signature.get(
            "headers",
            []
        ):


            if keyword in combined_headers:


                provider=name

                evidence.append(

                    f"{name} header detected"

                )





    if len(evidence)>=2:


        confidence="HIGH"



    elif len(evidence)==1:


        confidence="MEDIUM"





    return {


        "detected":
        provider is not None,


        "provider":
        provider,


        "confidence":
        confidence,


        "evidence":
        evidence

    }







# ==========================================================
# Public API
# ==========================================================


def get_cdn_intelligence(domain):


    return {


        "domain":
        domain,


        "timestamp":
        datetime.now(
            timezone.utc
        ).isoformat(),


        "cdn":
        detect_cdn(
            domain
        )


    }







# ==========================================================
# CLI
# ==========================================================


if __name__=="__main__":


    import json


    domain=input(
        "Domain: "
    ).strip()



    result=get_cdn_intelligence(
        domain
    )


    print(

        json.dumps(
            result,
            indent=4
        )

    )