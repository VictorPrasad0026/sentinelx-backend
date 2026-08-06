"""
SentinelX GeoIP Intelligence Engine v1.1

Purpose:
    Identify geographical intelligence
    for discovered internet assets.

Input:
    Domain / IP

Output:
    Country
    City
    Coordinates
    Timezone


Architecture:

Asset
 |
 IP
 |
 GeoIP Intelligence
 |
 Country
 City
 Coordinates
 Timezone

"""

import socket
import ipaddress
import os
import json

from datetime import datetime, timezone


# ==========================================================
# GeoIP Library
# ==========================================================

try:
    import geoip2.database

    GEOIP_AVAILABLE = True

except ImportError:

    GEOIP_AVAILABLE = False





# ==========================================================
# Database Location
# ==========================================================


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


GEOIP_DB = os.path.join(
    BASE_DIR,
    "databases",
    "GeoLite2-City.mmdb"
)





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
# GeoIP Lookup
# ==========================================================


def lookup_geo(ip):


    result = {


        "country": None,

        "country_code": None,

        "city": None,

        "latitude": None,

        "longitude": None,

        "timezone": None


    }



    # Check dependency

    if not GEOIP_AVAILABLE:


        result["error"] = (
            "geoip2 library not installed"
        )

        return result





    # Check database

    if not os.path.exists(GEOIP_DB):


        result["error"] = (

            "GeoIP database missing"

        )


        result["database"] = GEOIP_DB


        return result





    try:


        print(
            "[+] GeoIP Database:",
            GEOIP_DB
        )


        reader = geoip2.database.Reader(
            GEOIP_DB
        )



        response = reader.city(
            ip
        )



        result.update({


            "country":
            response.country.name,


            "country_code":
            response.country.iso_code,


            "city":
            response.city.name,


            "latitude":
            response.location.latitude,


            "longitude":
            response.location.longitude,


            "timezone":
            response.location.time_zone


        })



        reader.close()



    except Exception as e:


        result["error"] = str(e)



    return result







# ==========================================================
# Main Collector
# ==========================================================


def get_geoip_intelligence(target):


    start = datetime.now(
        timezone.utc
    )



    ip = resolve_ip(
        target
    )



    if not ip:


        return {


            "target": target,


            "error":
            "Unable to resolve IP"


        }





    geo = lookup_geo(
        ip
    )



    return {


        "target":
        target,


        "ip":
        ip,


        "timestamp":
        start.isoformat(),



        "geoip":

        geo


    }





# ==========================================================
# CLI TEST
# ==========================================================


if __name__ == "__main__":


    target = input(
        "Domain/IP: "
    ).strip()



    result = get_geoip_intelligence(
        target
    )



    print(

        json.dumps(

            result,

            indent=4

        )

    )