"""
SentinelX Service Banner Intelligence Engine v1.0

Purpose:
    Identify exposed service technologies
    and versions from open ports.

Input:
    IP + open ports

Output:
    Service intelligence


Flow:

IP
 |
 Port
 |
 Banner
 |
 Technology
 |
 Version
 |
 Risk

"""


import socket
import re
from datetime import datetime, timezone





# ==========================================================
# Banner Probes
# ==========================================================


SERVICE_PROBES = {


    21:
    b"",


    22:
    b"",


    25:
    b"",


    80:
    b"HEAD / HTTP/1.0\r\n\r\n",


    443:
    b"HEAD / HTTP/1.0\r\n\r\n",


    8080:
    b"HEAD / HTTP/1.0\r\n\r\n",


    3306:
    b"",


    6379:
    b"PING\r\n"

}





# ==========================================================
# Technology Fingerprints
# ==========================================================


TECH_SIGNATURES = {


    "nginx":[

        "nginx"

    ],


    "Apache":[

        "apache"

    ],


    "Microsoft IIS":[

        "iis",

        "microsoft"

    ],


    "OpenSSH":[

        "openssh"

    ],


    "Postfix":[

        "postfix"

    ],


    "MySQL":[

        "mysql"

    ],


    "Redis":[

        "redis"

    ]

}







# ==========================================================
# Banner Grabber
# ==========================================================


def grab_banner(ip, port, timeout=3):


    banner=""


    try:


        sock=socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )


        sock.settimeout(
            timeout
        )


        sock.connect(
            (
                ip,
                port
            )
        )



        probe=SERVICE_PROBES.get(
            port,
            b""
        )



        if probe:


            try:

                sock.send(
                    probe
                )

            except:

                pass




        data=sock.recv(
            2048
        )



        banner=data.decode(
            errors="ignore"
        ).strip()



        sock.close()



    except:


        pass



    return banner







# ==========================================================
# Technology Detection
# ==========================================================


def detect_technology(banner):


    banner_lower=banner.lower()



    for tech, signatures in TECH_SIGNATURES.items():


        for sig in signatures:


            if sig in banner_lower:


                return tech



    return None






# ==========================================================
# Version Extraction
# ==========================================================


def extract_version(banner):


    patterns=[


        r"nginx/([\d\.]+)",


        r"Apache/([\d\.]+)",


        r"OpenSSH[_-]([\d\.]+)",


        r"MySQL.*?([\d\.]+)"

    ]



    for pattern in patterns:


        match=re.search(

            pattern,

            banner,

            re.I

        )


        if match:

            return match.group(1)



    return None







# ==========================================================
# Analyze Service
# ==========================================================


def analyze_service(ip, port):


    banner=grab_banner(
        ip,
        port
    )


    technology=detect_technology(
        banner
    )


    version=extract_version(
        banner
    )



    return {


        "port":
        port,


        "banner":
        banner if banner else None,


        "technology":
        technology,


        "version":
        version,


        "confidence":
        "MEDIUM"
        if banner
        else
        "LOW"


    }







# ==========================================================
# Public API
# ==========================================================


def get_service_banner_intelligence(ip, ports):


    services=[]



    for port in ports:


        services.append(

            analyze_service(
                ip,
                port
            )

        )



    return {


        "ip":
        ip,


        "timestamp":
        datetime.now(
            timezone.utc
        ).isoformat(),


        "services":
        services

    }








# ==========================================================
# CLI Test
# ==========================================================


if __name__=="__main__":


    import json



    ip=input(
        "IP: "
    )


    ports=input(
        "Ports (comma separated): "
    )


    ports=[

        int(x)

        for x in ports.split(",")

    ]



    result=get_service_banner_intelligence(

        ip,

        ports

    )



    print(

        json.dumps(
            result,
            indent=4
        )

    )