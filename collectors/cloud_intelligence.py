"""
SentinelX Cloud Intelligence Engine v2.0

Purpose:
    Detect cloud hosting provider of internet assets.

Input:
    IP
    ASN
    Reverse DNS
    Hostname

Output:
    Cloud attribution intelligence

Pipeline:

IP
 |
ASN
 |
Reverse DNS
 |
Cloud Fingerprint
 |
Provider Confidence

"""


from datetime import datetime, timezone





# ==========================================================
# Cloud Fingerprints
# ==========================================================


CLOUD_SIGNATURES = {


    "AWS": [

        "amazon",
        "amazonaws",
        "aws",
        "ec2",
        "compute.amazonaws.com",
        "amazon-aws",
        "amazon-02"

    ],



    "Microsoft Azure": [

        "azure",
        "microsoft",
        "cloudapp.net",
        "windows.net"

    ],



    "Google Cloud": [

        "google",
        "gcp",
        "googleusercontent",
        "compute.googleapis.com"

    ],



    "DigitalOcean": [

        "digitalocean"

    ],



    "Cloudflare": [

        "cloudflare"

    ],



    "Oracle Cloud": [

        "oraclecloud",
        "oracle"

    ],



    "Alibaba Cloud": [

        "aliyun",
        "alibaba"

    ],



    "Hetzner Cloud": [

        "hetzner"

    ]

}







# ==========================================================
# Normalize
# ==========================================================


def normalize(value):

    if not value:

        return ""

    return str(value).lower()







# ==========================================================
# Cloud Detection Core
# ==========================================================


def detect_cloud_provider(
        asn=None,
        reverse_dns=None,
        hostname=None
):


    evidence=[]


    text=" ".join([

        normalize(asn),

        normalize(reverse_dns),

        normalize(hostname)

    ])




    for provider, signatures in CLOUD_SIGNATURES.items():


        for signature in signatures:


            if signature in text:


                evidence.append(signature)



                return {


                    "provider":provider,


                    "confidence":"HIGH",


                    "evidence":evidence


                }




    return {


        "provider":"UNKNOWN",


        "confidence":"LOW",


        "evidence":[]


    }







# ==========================================================
# Compatibility Wrapper
# Used by Infrastructure Engine
# ==========================================================



def detect_cloud(ip, reverse_dns=None):

    result = detect_cloud_provider(

        asn=None,

        reverse_dns=reverse_dns,

        hostname=ip

    )


    # AWS IP range fallback

    if result["provider"] == "UNKNOWN":

        if ip.startswith(
            (
                "3.",
                "13.",
                "18.",
                "34.",
                "35."
            )
        ):

            return {

                "provider": "AWS",

                "confidence": "MEDIUM",

                "evidence": [
                    "AWS IP Range Detection"
                ]

            }

    return result







# ==========================================================
# Main Collector
# ==========================================================


def get_cloud_intelligence(

        ip,

        asn_info=None,

        reverse_dns=None

):


    detection = detect_cloud_provider(

        asn=asn_info,

        reverse_dns=reverse_dns,

        hostname=ip

    )



    return {


        "ip":ip,


        "timestamp":

        datetime.now(
            timezone.utc
        ).isoformat(),



        "cloud_provider":

        detection["provider"],



        "confidence":

        detection["confidence"],



        "evidence":

        detection["evidence"]

    }







# ==========================================================
# CLI Test
# ==========================================================


if __name__=="__main__":


    import json



    result=get_cloud_intelligence(

        ip="3.108.140.28",


        asn_info=
        "AMAZON-02 - Amazon.com Inc",


        reverse_dns=
        "ec2-3-108-140-28.ap-south-1.compute.amazonaws.com"

    )



    print(

        json.dumps(

            result,

            indent=4

        )

    )