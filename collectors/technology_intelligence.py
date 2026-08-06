import requests

from datetime import datetime



SECURITY_HEADERS = [

    "strict-transport-security",

    "content-security-policy",

    "x-frame-options",

    "x-content-type-options",

    "referrer-policy",

    "permissions-policy"

]





def analyze_security_headers(headers):

    result = {}


    lower_headers = {

        key.lower(): value

        for key, value in headers.items()

    }


    for header in SECURITY_HEADERS:

        result[header] = {

            "present":
            header in lower_headers,


            "value":
            lower_headers.get(header)

        }


    return result





def extract_csp(headers):


    for key, value in headers.items():


        if key.lower() == "content-security-policy":

            return {

                "enabled": True,

                "value": value

            }



    return {

        "enabled": False,

        "value": None

    }







def analyze_cookies(response):


    cookies = []


    for cookie in response.cookies:


        cookies.append({

            "name":
            cookie.name,


            "secure":
            cookie.secure,


            "httponly":
            "httponly"
            in str(cookie._rest).lower(),


            "samesite":
            cookie._rest.get(
                "SameSite"
            )

        })


    return cookies







def detect_technology(headers, html):


    technologies = []


    header_string = str(headers).lower()

    html = html.lower()



    fingerprints = {


        "Cloudflare":
        "cloudflare",


        "Akamai":
        "akamai",


        "Nginx":
        "nginx",


        "Apache":
        "apache",


        "WordPress":
        "wordpress",


        "React":
        "react",


        "Next.js":
        "next.js"

    }



    seen = set()

    for name, keyword in fingerprints.items():

        if keyword in header_string or keyword in html:

            if name not in seen:

                technologies.append({
                    "name": name,
                    "evidence": keyword
                })

                seen.add(name)

    return technologies







def detect_protection(status_code, headers):


    protection = {


        "detected":
        False,


        "type":
        None,


        "evidence":
        []

    }



    header_string = str(headers).lower()



    waf_signatures = [

        "cloudflare",

        "akamai",

        "incapsula",

        "imperva",

        "sucuri"

    ]



    for waf in waf_signatures:


        if waf in header_string:


            protection["detected"] = True


            protection["type"] = (

                "Possible WAF/CDN protection"

            )


            protection["evidence"].append(
                waf
            )



    if status_code in [403,429]:


        protection["detected"] = True


        protection["type"] = (

            "Access restriction / Bot protection"

        )


    return protection







def calculate_response_confidence(

        status_code,

        protection,

        html

):


    confidence = {


        "level":
        "HIGH",


        "reason":[]

    }




    if protection["detected"]:


        confidence["level"] = "LOW"


        confidence["reason"].append(

            "WAF/CDN protection detected"

        )





    if status_code in [403,429]:


        confidence["level"] = "LOW"


        confidence["reason"].append(

            "Restricted HTTP response"

        )





    keywords = [

        "captcha",

        "access denied",

        "verify you are human",

        "security challenge",

        "bot manager"

    ]



    body = html.lower()



    for word in keywords:


        if word in body:


            confidence["level"]="LOW"


            confidence["reason"].append(

                f"Challenge page detected: {word}"

            )


            break



    return confidence







def calculate_security_score(headers, confidence):


    if confidence["level"] == "LOW":


        return {


            "security_score":
            None,


            "status":
            "UNRELIABLE_RESPONSE",


            "reason":
            "Security gateway response detected"

        }



    score = 100


    missing=[]



    lower_headers=[

        h.lower()

        for h in headers.keys()

    ]



    for header in SECURITY_HEADERS:


        if header not in lower_headers:


            missing.append(header)

            score -=10




    return {


        "security_score":
        max(score,0),


        "status":
        "CALCULATED",


        "missing_headers":
        missing

    }









def get_technology_info(domain):


    result={


        "domain":domain,


        "timestamp":
        datetime.utcnow().isoformat(),


        "technology":{},


        "security_headers":{},


        "cookies":[],


        "csp_raw":{},


        "raw_headers":{},


        "protection":{},


        "response_confidence":{},


        "security_posture":{}

    }





    try:


        response=requests.get(


            f"https://{domain}",


            timeout=10,


            headers={

                "User-Agent":

                "Mozilla/5.0 SentinelX Security Scanner"

            },


            allow_redirects=True

        )



        headers=response.headers



        result["technology"]={


            "status_code":
            response.status_code,


            "final_url":
            response.url,


            "redirects":
            len(response.history),


            "server":
            headers.get(

                "Server",

                "Unknown"

            ),


            "powered_by":
            headers.get(

                "X-Powered-By",

                "Unknown"

            ),


            "detected_frameworks":
            detect_technology(

                headers,

                response.text

            )

        }





        result["raw_headers"]=dict(headers)



        result["security_headers"]=analyze_security_headers(

            headers

        )



        result["csp_raw"]=extract_csp(

            headers

        )



        result["cookies"]=analyze_cookies(

            response

        )



        result["protection"]=detect_protection(

            response.status_code,

            headers

        )



        result["response_confidence"]=calculate_response_confidence(

            response.status_code,

            result["protection"],

            response.text

        )



        result["security_posture"]=calculate_security_score(

            headers,

            result["response_confidence"]

        )



    except Exception as e:


        result["error"]=str(e)



    return result







if __name__=="__main__":


    target=input(
        "Enter domain: "
    )


    print(
        get_technology_info(target)
    )