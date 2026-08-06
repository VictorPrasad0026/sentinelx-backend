"""
SentinelX Reverse DNS Intelligence Engine v1.0

Purpose:
    Identify reverse DNS hostname
    associated with discovered IP assets.

Input:
    IP / Domain

Output:
    PTR record intelligence


Architecture:

IP
 |
 PTR Lookup
 |
 Hostname
 |
 Provider Hint
 |
 Risk Context

"""


import socket
import ipaddress

from datetime import datetime, timezone





# ==========================================================
# Resolve IP
# ==========================================================


def resolve_ip(target):


    try:

        ipaddress.ip_address(target)

        return target


    except ValueError:


        try:

            return socket.gethostbyname(
                target
            )


        except Exception:

            return None






# ==========================================================
# Provider Detection
# ==========================================================


def detect_provider(hostname):


    if not hostname:

        return None



    hostname = hostname.lower()



    providers = {


        "amazonaws":
        "AWS",


        "compute.amazonaws":
        "AWS EC2",


        "azure":
        "Microsoft Azure",


        "googleusercontent":
        "Google Cloud",


        "digitalocean":
        "DigitalOcean",


        "cloudapp":
        "Microsoft Azure",


        "linode":
        "Linode"


    }



    for keyword, provider in providers.items():


        if keyword in hostname:

            return provider



    return None






# ==========================================================
# Reverse DNS Lookup
# ==========================================================


def lookup_reverse_dns(ip):


    result = {


        "hostname": None,

        "provider_hint": None,

        "status": "UNKNOWN"

    }



    try:


        hostname = socket.gethostbyaddr(
            ip
        )[0]



        result["hostname"] = hostname


        result["provider_hint"] = detect_provider(
            hostname
        )


        result["status"] = "FOUND"



    except socket.herror:


        result["status"] = "NOT_FOUND"



    except Exception as e:


        result["error"] = str(e)



    return result






# ==========================================================
# Main Collector
# ==========================================================


def get_reverse_dns(target):


    timestamp = datetime.now(
        timezone.utc
    ).isoformat()



    ip = resolve_ip(
        target
    )



    if not ip:


        return {


            "target": target,

            "error":
            "Unable to resolve IP"


        }





    return {


        "target":
        target,


        "ip":
        ip,


        "timestamp":
        timestamp,


        "reverse_dns":

        lookup_reverse_dns(
            ip
        )


    }





# ==========================================================
# CLI Test
# ==========================================================


if __name__ == "__main__":


    import json



    target = input(
        "Domain/IP: "
    ).strip()



    result = get_reverse_dns(
        target
    )



    print(

        json.dumps(
            result,
            indent=4
        )

    )