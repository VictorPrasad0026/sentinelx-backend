"""
SentinelX HTTP Intelligence Engine v1.0

Collects:

- HTTP Reachability
- Status Code
- Response Time
- Server Banner
- X-Powered-By
- Security Headers
- CSP Detection
- Cookie Security
- Technology Fingerprinting
- WAF Detection

Author:
SentinelX ASM Platform
"""


import requests
import time


USER_AGENT = {

    "User-Agent":
    "SentinelX-V2-ASM-Engine"

}



# =====================================================
# SECURITY HEADERS
# =====================================================


SECURITY_HEADERS = [

    "strict-transport-security",

    "content-security-policy",

    "x-frame-options",

    "x-content-type-options",

    "referrer-policy",

    "permissions-policy"

]





def analyze_headers(headers):


    result = {}


    lower = {

        k.lower(): v

        for k, v in headers.items()

    }



    for header in SECURITY_HEADERS:


        result[header] = {

            "present":
            header in lower,


            "value":
            lower.get(header)

        }


    return result





# =====================================================
# TECHNOLOGY DETECTION
# =====================================================


def detect_technologies(headers, html):


    technologies = []


    data = (

        str(headers)

        +

        html

    ).lower()



    fingerprints = {


        "Cloudflare": [

            "cf-ray",

            "cloudflare"

        ],


        "Akamai": [

            "akamai"

        ],


        "Nginx": [

            "nginx"

        ],


        "Apache": [

            "apache"

        ],


        "Microsoft IIS": [

            "microsoft-iis"

        ],


        "WordPress": [

            "wp-content",

            "wordpress"

        ],


        "React": [

            "react",

            "__react"

        ],


        "Next.js": [

            "next.js",

            "__next"

        ],


        "Vue.js": [

            "vue"

        ],


        "Angular": [

            "ng-version"

        ],


        "Bootstrap": [

            "bootstrap"

        ]

    }




    for tech, signatures in fingerprints.items():


        for signature in signatures:


            if signature in data:


                technologies.append({

                    "name": tech,

                    "evidence": signature

                })


                break



    return technologies





# =====================================================
# COOKIE ANALYSIS
# =====================================================


def analyze_cookies(response):


    cookies = []


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


    data = str(headers).lower()



    waf_signatures = {


        "Cloudflare": [

            "cf-ray",

            "cloudflare"

        ],



        "Akamai": [

            "akamai"

        ],



        "Imperva": [

            "imperva"

        ],



        "Sucuri": [

            "sucuri"

        ]

    }




    for provider, signatures in waf_signatures.items():


        for signature in signatures:


            if signature in data:


                return {


                    "detected":
                    True,


                    "provider":
                    provider

                }





    return {


        "detected":
        False,


        "provider":
        None

    }





# =====================================================
# HTTP INTELLIGENCE
# =====================================================


def get_http_info(host):


    result = {


        "reachable":
        False,


        "url":
        None,


        "status_code":
        None,


        "response_time":
        None,


        "server":
        None,


        "powered_by":
        None,


        "technologies":
        [],


        "security_headers":
        {},


        "csp_raw":
        None,


        "cookies":
        [],


        "waf":
        {},


        "headers":
        {}

    }





    urls = [

        f"https://{host}",

        f"http://{host}"

    ]





    for url in urls:


        try:


            start = time.time()



            response = requests.get(

                url,

                timeout=8,

                allow_redirects=True,

                headers=USER_AGENT,

                verify=False

            )



            elapsed = round(

                time.time() - start,

                3

            )



            headers = response.headers



            html = response.text[:500000].lower()



            result.update({



                "reachable":
                True,


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





    result["error"] = "HTTP unreachable"



    return result





# =====================================================
# TEST
# =====================================================


if __name__ == "__main__":


    import json



    target = input(

        "Domain: "

    )



    output = get_http_info(

        target

    )



    print(

        json.dumps(

            output,

            indent=4

        )

    )