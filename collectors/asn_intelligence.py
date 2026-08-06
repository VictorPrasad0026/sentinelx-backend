"""
SentinelX ASN Intelligence Engine v1.0

Purpose:
    Identify Autonomous System information
    for discovered internet assets.

Input:
    IP address

Output:
    ASN ownership intelligence

Example:

IP
 |
ASN
 |
Organization
 |
Network Provider

"""


import socket
import ipaddress
from datetime import datetime, timezone


try:

    import ipwhois

except ImportError:

    ipwhois = None




# ==========================================================
# ASN PROVIDER CLASSIFICATION
# ==========================================================


CLOUD_PROVIDERS = {


    "AMAZON":
    "AWS",


    "AWS":
    "AWS",


    "GOOGLE":
    "Google Cloud",


    "MICROSOFT":
    "Azure",


    "AZURE":
    "Azure",


    "DIGITALOCEAN":
    "DigitalOcean",


    "ORACLE":
    "Oracle Cloud",


    "ALIBABA":
    "Alibaba Cloud",


    "CLOUDFLARE":
    "Cloudflare"

}





# ==========================================================
# Resolve IP
# ==========================================================


def resolve_ip(target):


    try:

        ipaddress.ip_address(target)

        return target


    except:


        try:

            return socket.gethostbyname(
                target
            )

        except:

            return None





# ==========================================================
# Cloud Detection
# ==========================================================


def detect_provider(description):


    if not description:

        return "Unknown"



    desc=description.upper()



    for key,value in CLOUD_PROVIDERS.items():


        if key in desc:

            return value



    return "Unknown"





# ==========================================================
# ASN Lookup
# ==========================================================


def get_asn_info(target):


    start=datetime.now(
        timezone.utc
    )


    ip=resolve_ip(target)



    if not ip:


        return {


            "error":
            "Unable to resolve IP"

        }




    result={


        "target":target,


        "ip":ip,


        "timestamp":
        start.isoformat(),



        "asn":None,


        "description":None,


        "network":None,


        "country":None,


        "registry":None,


        "cloud_provider":
        "Unknown"



    }





    # ------------------------------------
    # Offline fallback
    # ------------------------------------


    if ipwhois is None:


        result["message"]=(
            "Install ipwhois for ASN lookup"
        )


        return result





    try:


        from ipwhois import IPWhois



        lookup=IPWhois(
            ip
        ).lookup_rdap()



        result["asn"] = (

            lookup
            .get("asn")

        )


        result["description"]=(

            lookup
            .get("asn_description")

        )


        result["network"]=(

            lookup
            .get("network",{})
            .get("name")

        )


        result["country"]=(

            lookup
            .get("network",{})
            .get("country")

        )


        result["registry"]=(

            lookup
            .get("asn_registry")

        )



        result["cloud_provider"] = detect_provider(

            result["description"]

        )



    except Exception as e:


        result["error"]=str(e)




    return result





# ==========================================================
# SentinelX Wrapper
# ==========================================================


def get_asn_intelligence(target):


    return get_asn_info(
        target
    )





# ==========================================================
# Test
# ==========================================================


if __name__=="__main__":


    import json


    domain=input(
        "IP / Domain: "
    )


    data=get_asn_intelligence(
        domain
    )


    print(
        json.dumps(
            data,
            indent=4
        )
    )