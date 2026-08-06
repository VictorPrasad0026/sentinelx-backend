"""
SentinelX Port Intelligence Engine v2.0

Purpose:
    External attack surface port discovery.

Input:
    hostname / IP

Output:
    Structured infrastructure intelligence
"""

import socket
import ssl
import time

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed



# ==========================================================
# Known Services
# ==========================================================


PORT_DATABASE = {

    # ──────────────────────────────────────────────────────────────────
    #  FILE TRANSFER / REMOTE ACCESS
    # ──────────────────────────────────────────────────────────────────
    21:   {"service": "FTP",          "risk": "HIGH",     "score": 15},
    22:   {"service": "SSH",          "risk": "MEDIUM",   "score": 8},
    23:   {"service": "TELNET",       "risk": "CRITICAL", "score": 25},
    69:   {"service": "TFTP",         "risk": "HIGH",     "score": 18},
    115:  {"service": "SFTP",         "risk": "MEDIUM",   "score": 8},
    989:  {"service": "FTPS-DATA",    "risk": "MEDIUM",   "score": 5},
    990:  {"service": "FTPS-CONTROL", "risk": "MEDIUM",   "score": 5},
    992:  {"service": "TELNETS",      "risk": "HIGH",     "score": 20},
    2049: {"service": "NFS",          "risk": "HIGH",     "score": 20},
    873:  {"service": "RSYNC",        "risk": "MEDIUM",   "score": 12},
    548:  {"service": "AFP",          "risk": "MEDIUM",   "score": 8},

    # ──────────────────────────────────────────────────────────────────
    #  WEB SERVICES & PROXIES
    # ──────────────────────────────────────────────────────────────────
    80:   {"service": "HTTP",         "risk": "LOW",      "score": 2},
    443:  {"service": "HTTPS",        "risk": "LOW",      "score": 2},
    81:   {"service": "HTTP-ALT",     "risk": "LOW",      "score": 3},
    3000: {"service": "HTTP-ALT",     "risk": "LOW",      "score": 3},
    5000: {"service": "HTTP-ALT",     "risk": "LOW",      "score": 3},
    8000: {"service": "HTTP-ALT",     "risk": "LOW",      "score": 3},
    8008: {"service": "HTTP-ALT",     "risk": "LOW",      "score": 3},
    8080: {"service": "HTTP-ALT",     "risk": "LOW",      "score": 3},
    8888: {"service": "HTTP-ALT",     "risk": "LOW",      "score": 3},
    9443: {"service": "HTTPS-ALT",    "risk": "LOW",      "score": 2},
    8443: {"service": "HTTPS-ALT",    "risk": "LOW",      "score": 2},
    6443: {"service": "HTTPS-ALT",    "risk": "LOW",      "score": 2},
    9090: {"service": "HTTP-ALT",     "risk": "LOW",      "score": 3},
    3128: {"service": "SQUID-PROXY",  "risk": "MEDIUM",   "score": 8},
    1080: {"service": "SOCKS-PROXY",  "risk": "MEDIUM",   "score": 10},

    # ──────────────────────────────────────────────────────────────────
    #  EMAIL SERVICES
    # ──────────────────────────────────────────────────────────────────
    25:   {"service": "SMTP",         "risk": "MEDIUM",   "score": 5},
    110:  {"service": "POP3",         "risk": "MEDIUM",   "score": 5},
    143:  {"service": "IMAP",         "risk": "MEDIUM",   "score": 5},
    465:  {"service": "SMTPS",        "risk": "LOW",      "score": 3},
    587:  {"service": "SMTP-SUBMIT",  "risk": "LOW",      "score": 3},
    993:  {"service": "IMAPS",        "risk": "LOW",      "score": 2},
    995:  {"service": "POP3S",        "risk": "LOW",      "score": 2},
    2525: {"service": "SMTP-ALT",     "risk": "MEDIUM",   "score": 5},

    # ──────────────────────────────────────────────────────────────────
    #  DIRECTORY SERVICES / AUTH
    # ──────────────────────────────────────────────────────────────────
    88:   {"service": "KERBEROS",     "risk": "MEDIUM",   "score": 8},
    389:  {"service": "LDAP",         "risk": "MEDIUM",   "score": 8},
    636:  {"service": "LDAPS",        "risk": "MEDIUM",   "score": 6},
    3268: {"service": "GC-LDAP",      "risk": "MEDIUM",   "score": 8},
    3269: {"service": "GC-LDAPS",     "risk": "MEDIUM",   "score": 6},
    749:  {"service": "KERBEROS-ADM", "risk": "HIGH",     "score": 15},

    # ──────────────────────────────────────────────────────────────────
    #  DATABASES
    # ──────────────────────────────────────────────────────────────────
    3306: {"service": "MYSQL",        "risk": "CRITICAL", "score": 25},
    1433: {"service": "MSSQL",        "risk": "CRITICAL", "score": 25},
    1434: {"service": "MSSQL-MONITOR","risk": "MEDIUM",   "score": 8},
    1521: {"service": "ORACLE-DB",    "risk": "CRITICAL", "score": 25},
    1522: {"service": "ORACLE-DB",    "risk": "CRITICAL", "score": 25},
    1523: {"service": "ORACLE-DB",    "risk": "CRITICAL", "score": 25},
    1524: {"service": "ORACLE-DB",    "risk": "CRITICAL", "score": 25},
    1830: {"service": "ORACLE-DB",    "risk": "CRITICAL", "score": 25},
    2483: {"service": "ORACLE-DB",    "risk": "CRITICAL", "score": 25},
    2484: {"service": "ORACLE-DBS",   "risk": "CRITICAL", "score": 25},
    5432: {"service": "POSTGRESQL",   "risk": "CRITICAL", "score": 25},
    6379: {"service": "REDIS",        "risk": "CRITICAL", "score": 30},
    27017:{"service": "MONGODB",       "risk": "CRITICAL", "score": 30},
    27018:{"service": "MONGODB",       "risk": "CRITICAL", "score": 30},
    27019:{"service": "MONGODB",       "risk": "CRITICAL", "score": 30},
    9200: {"service": "ELASTICSEARCH","risk": "CRITICAL", "score": 30},
    9300: {"service": "ELASTICSEARCH","risk": "CRITICAL", "score": 25},
    5984: {"service": "COUCHDB",      "risk": "CRITICAL", "score": 25},
    9042: {"service": "CASSANDRA",    "risk": "CRITICAL", "score": 25},
    9160: {"service": "CASSANDRA-THRIFT","risk":"CRITICAL","score": 25},
    7000: {"service": "CASSANDRA",    "risk": "HIGH",     "score": 20},
    7001: {"service": "CASSANDRA-SSL","risk": "HIGH",     "score": 18},
    7199: {"service": "CASSANDRA-JMX","risk": "CRITICAL", "score": 25},
    7474: {"service": "NEO4J",        "risk": "HIGH",     "score": 20},
    7687: {"service": "NEO4J-BOLT",   "risk": "HIGH",     "score": 20},
    4000: {"service": "DB2",          "risk": "CRITICAL", "score": 25},
    50000:{"service": "DB2",          "risk": "CRITICAL", "score": 25},
    523:  {"service": "DB2",          "risk": "CRITICAL", "score": 25},
    3050: {"service": "FIREBIRD",     "risk": "HIGH",     "score": 20},
    2424: {"service": "ORIENTDB",     "risk": "HIGH",     "score": 20},
    2480: {"service": "ORIENTDB-HTTP","risk": "MEDIUM",   "score": 10},

    # ──────────────────────────────────────────────────────────────────
    #  WINDOWS / SMB / RPC
    # ──────────────────────────────────────────────────────────────────
    135:  {"service": "MSRPC",        "risk": "HIGH",     "score": 15},
    137:  {"service": "NETBIOS-NS",   "risk": "MEDIUM",   "score": 8},
    138:  {"service": "NETBIOS-DGM",  "risk": "MEDIUM",   "score": 8},
    139:  {"service": "NETBIOS-SSN",  "risk": "HIGH",     "score": 15},
    445:  {"service": "SMB",          "risk": "CRITICAL", "score": 25},
    464:  {"service": "KERBEROS-PW",  "risk": "MEDIUM",   "score": 10},
    593:  {"service": "MSRPC-HTTP",   "risk": "HIGH",     "score": 15},
    636:  {"service": "LDAPS",        "risk": "MEDIUM",   "score": 6},
    3268: {"service": "GC-LDAP",      "risk": "MEDIUM",   "score": 8},
    3269: {"service": "GC-LDAPS",     "risk": "MEDIUM",   "score": 6},
    3389: {"service": "RDP",          "risk": "HIGH",     "score": 20},
    5985: {"service": "WINRM-HTTP",   "risk": "HIGH",     "score": 15},
    5986: {"service": "WINRM-HTTPS",  "risk": "HIGH",     "score": 12},
    47001:{"service": "WINRM-HTTP",   "risk": "HIGH",     "score": 15},
    9389: {"service": "AD-DS-WEB",    "risk": "MEDIUM",   "score": 8},

    # ──────────────────────────────────────────────────────────────────
    #  VNC / REMOTE DESKTOP
    # ──────────────────────────────────────────────────────────────────
    5800: {"service": "VNC-HTTP",     "risk": "HIGH",     "score": 18},
    5801: {"service": "VNC-HTTP",     "risk": "HIGH",     "score": 18},
    5802: {"service": "VNC-HTTP",     "risk": "HIGH",     "score": 18},
    5900: {"service": "VNC",          "risk": "HIGH",     "score": 20},
    5901: {"service": "VNC-1",        "risk": "HIGH",     "score": 20},
    5902: {"service": "VNC-2",        "risk": "HIGH",     "score": 20},
    5903: {"service": "VNC-3",        "risk": "HIGH",     "score": 20},
    5904: {"service": "VNC-4",        "risk": "HIGH",     "score": 20},
    5905: {"service": "VNC-5",        "risk": "HIGH",     "score": 20},
    5906: {"service": "VNC-6",        "risk": "HIGH",     "score": 20},
    5907: {"service": "VNC-7",        "risk": "HIGH",     "score": 20},
    5908: {"service": "VNC-8",        "risk": "HIGH",     "score": 20},
    5909: {"service": "VNC-9",        "risk": "HIGH",     "score": 20},
    5910: {"service": "VNC-10",       "risk": "HIGH",     "score": 20},
    5938: {"service": "TEAMVIEWER",   "risk": "HIGH",     "score": 18},
    4899: {"service": "RADMIN",       "risk": "HIGH",     "score": 20},
    5631: {"service": "PCANYWHERE",   "risk": "HIGH",     "score": 18},
    5632: {"service": "PCANYWHERE-STATUS","risk":"MEDIUM","score": 8},

    # ──────────────────────────────────────────────────────────────────
    #  CONTAINER / ORCHESTRATION
    # ──────────────────────────────────────────────────────────────────
    2375: {"service": "DOCKER-API",   "risk": "CRITICAL", "score": 30},
    2376: {"service": "DOCKER-TLS",   "risk": "HIGH",     "score": 20},
    4243: {"service": "DOCKER-ALT",   "risk": "CRITICAL", "score": 30},
    10250:{"service": "KUBE-API",     "risk": "CRITICAL", "score": 30},
    10251:{"service": "KUBE-SCHED",   "risk": "HIGH",     "score": 20},
    10252:{"service": "KUBE-CM",      "risk": "HIGH",     "score": 20},
    10255:{"service": "KUBE-READ",    "risk": "HIGH",     "score": 18},
    8001: {"service": "KUBE-PROXY",   "risk": "HIGH",     "score": 18},
    8443: {"service": "KUBE-API-SSL", "risk": "HIGH",     "score": 15},
    6443: {"service": "KUBE-API-RO",  "risk": "HIGH",     "score": 15},
    8444: {"service": "KUBE-API-ADM", "risk": "MEDIUM",   "score": 10},

    # ──────────────────────────────────────────────────────────────────
    #  MESSAGE QUEUES / STREAMING
    # ──────────────────────────────────────────────────────────────────
    5671: {"service": "AMQP-SSL",     "risk": "MEDIUM",   "score": 8},
    5672: {"service": "RABBITMQ",     "risk": "HIGH",     "score": 15},
    15672:{"service": "RABBITMQ-ADM", "risk": "HIGH",     "score": 18},
    61613:{"service": "ACTIVEMQ-STOMP","risk":"HIGH",     "score": 15},
    61614:{"service": "ACTIVEMQ-SSL", "risk": "MEDIUM",   "score": 10},
    61616:{"service": "ACTIVEMQ-OPEN","risk": "HIGH",     "score": 15},
    8161: {"service": "ACTIVEMQ-ADM", "risk": "HIGH",     "score": 18},
    9092: {"service": "KAFKA",        "risk": "HIGH",     "score": 15},
    2181: {"service": "ZOOKEEPER",    "risk": "HIGH",     "score": 20},
    2888: {"service": "ZOOKEEPER",    "risk": "MEDIUM",   "score": 10},
    3888: {"service": "ZOOKEEPER",    "risk": "MEDIUM",   "score": 10},
    1883: {"service": "MQTT",         "risk": "MEDIUM",   "score": 10},
    8883: {"service": "MQTTS",        "risk": "LOW",      "score": 5},
    5555: {"service": "ADB",          "risk": "HIGH",     "score": 20},

    # ──────────────────────────────────────────────────────────────────
    #  REMOTE PROCEDURE CALLS / DISTRIBUTED SYSTEMS
    # ──────────────────────────────────────────────────────────────────
    1099: {"service": "RMI-REGISTRY", "risk": "HIGH",     "score": 18},
    1100: {"service": "RMI-REGISTRY", "risk": "HIGH",     "score": 18},
    1098: {"service": "RMI-ACTIVATION","risk":"HIGH",     "score": 15},
    3873: {"service": "RMI-JMX",      "risk": "HIGH",     "score": 15},
    8649: {"service": "GANGLIA-MON",  "risk": "MEDIUM",   "score": 8},
    8651: {"service": "GANGLIA-MON",  "risk": "MEDIUM",   "score": 8},
    4505: {"service": "SALT-MASTER",  "risk": "HIGH",     "score": 15},
    4506: {"service": "SALT-MASTER",  "risk": "HIGH",     "score": 15},

    # ──────────────────────────────────────────────────────────────────
    #  ICS / SCADA / IOT
    # ──────────────────────────────────────────────────────────────────
    502:  {"service": "MODBUS",       "risk": "HIGH",     "score": 20},
    102:  {"service": "IEC-61850",    "risk": "HIGH",     "score": 20},
    20000:{"service": "DNP3",         "risk": "HIGH",     "score": 20},
    44818:{"service": "ETHERNET-IP",  "risk": "HIGH",     "score": 18},
    47808:{"service": "BACNET",       "risk": "MEDIUM",   "score": 10},
    4840: {"service": "OPC-UA",       "risk": "MEDIUM",   "score": 10},
    4800: {"service": "MELSEC-Q",     "risk": "HIGH",     "score": 18},
    623:  {"service": "IPMI",         "risk": "CRITICAL", "score": 25},

    # ──────────────────────────────────────────────────────────────────
    #  PRINT / FILE / MISC SERVICES
    # ──────────────────────────────────────────────────────────────────
    631:  {"service": "IPP",          "risk": "MEDIUM",   "score": 8},
    515:  {"service": "LPD",          "risk": "MEDIUM",   "score": 8},
    9100: {"service": "PJL",          "risk": "MEDIUM",   "score": 10},
    79:   {"service": "FINGER",       "risk": "MEDIUM",   "score": 5},
    512:  {"service": "REXEC",        "risk": "HIGH",     "score": 18},
    513:  {"service": "RLOGIN",       "risk": "HIGH",     "score": 18},
    514:  {"service": "RSH",          "risk": "HIGH",     "score": 18},
    2049: {"service": "NFS",          "risk": "HIGH",     "score": 20},
    111:  {"service": "RPCBIND",      "risk": "MEDIUM",   "score": 10},
    177:  {"service": "XDMCP",        "risk": "MEDIUM",   "score": 8},
    427:  {"service": "SLP",          "risk": "MEDIUM",   "score": 8},
    548:  {"service": "AFP",          "risk": "MEDIUM",   "score": 8},
    1900: {"service": "SSDP",         "risk": "LOW",      "score": 3},
    5351: {"service": "NAT-PMP",      "risk": "MEDIUM",   "score": 5},
    5353: {"service": "MDNS",         "risk": "LOW",      "score": 3},
    5355: {"service": "LLMNR",        "risk": "MEDIUM",   "score": 5},

    # ──────────────────────────────────────────────────────────────────
    #  TIME / LOGGING / MONITORING
    # ──────────────────────────────────────────────────────────────────
    123:  {"service": "NTP",          "risk": "MEDIUM",   "score": 5},
    161:  {"service": "SNMP",         "risk": "HIGH",     "score": 15},
    162:  {"service": "SNMP-TRAP",    "risk": "MEDIUM",   "score": 8},
    514:  {"service": "SYSLOG",       "risk": "MEDIUM",   "score": 5},
    601:  {"service": "SYSLOG-TLS",   "risk": "LOW",      "score": 3},
    6514: {"service": "SYSLOG-TLS",   "risk": "LOW",      "score": 3},
    37:   {"service": "TIME",         "risk": "LOW",      "score": 2},
    13:   {"service": "DAYTIME",      "risk": "LOW",      "score": 2},

    # ──────────────────────────────────────────────────────────────────
    #  VPN / TUNNELING
    # ──────────────────────────────────────────────────────────────────
    500:  {"service": "IKE",          "risk": "MEDIUM",   "score": 8},
    4500: {"service": "IPSEC-NAT",    "risk": "MEDIUM",   "score": 8},
    1701: {"service": "L2TP",         "risk": "MEDIUM",   "score": 8},
    1723: {"service": "PPTP",         "risk": "HIGH",     "score": 15},
    1194: {"service": "OPENVPN",      "risk": "MEDIUM",   "score": 5},
    51820:{"service": "WIREGUARD",    "risk": "LOW",      "score": 3},

    # ──────────────────────────────────────────────────────────────────
    #  GIT / VERSION CONTROL
    # ──────────────────────────────────────────────────────────────────
    22:   {"service": "GIT-SSH",      "risk": "MEDIUM",   "score": 8},
    9418: {"service": "GIT",          "risk": "MEDIUM",   "score": 8},
    443:  {"service": "GIT-HTTPS",    "risk": "LOW",      "score": 2},
    3690: {"service": "SVN",          "risk": "MEDIUM",   "score": 8},

    # ──────────────────────────────────────────────────────────────────
    #  VOIP / SIP
    # ──────────────────────────────────────────────────────────────────
    5060: {"service": "SIP",          "risk": "HIGH",     "score": 15},
    5061: {"service": "SIP-TLS",      "risk": "MEDIUM",   "score": 10},
    5080: {"service": "SIP-ALT",      "risk": "HIGH",     "score": 15},
    1720: {"service": "H323",         "risk": "MEDIUM",   "score": 8},
    2000: {"service": "SCCP",         "risk": "MEDIUM",   "score": 8},

    # ──────────────────────────────────────────────────────────────────
    #  X WINDOW SYSTEM
    # ──────────────────────────────────────────────────────────────────
    6000: {"service": "X11",          "risk": "CRITICAL", "score": 25},
    6001: {"service": "X11-1",        "risk": "CRITICAL", "score": 25},
    6002: {"service": "X11-2",        "risk": "CRITICAL", "score": 25},
    6003: {"service": "X11-3",        "risk": "CRITICAL", "score": 25},
    6004: {"service": "X11-4",        "risk": "CRITICAL", "score": 25},
    6005: {"service": "X11-5",        "risk": "CRITICAL", "score": 25},
    6006: {"service": "X11-6",        "risk": "CRITICAL", "score": 25},
    6007: {"service": "X11-7",        "risk": "CRITICAL", "score": 25},
    6008: {"service": "X11-8",        "risk": "CRITICAL", "score": 25},
    6009: {"service": "X11-9",        "risk": "CRITICAL", "score": 25},
    6010: {"service": "X11-10",       "risk": "CRITICAL", "score": 25},
    6011: {"service": "X11-11",       "risk": "CRITICAL", "score": 25},
    6012: {"service": "X11-12",       "risk": "CRITICAL", "score": 25},
    6013: {"service": "X11-13",       "risk": "CRITICAL", "score": 25},
    6014: {"service": "X11-14",       "risk": "CRITICAL", "score": 25},
    6015: {"service": "X11-15",       "risk": "CRITICAL", "score": 25},
    6016: {"service": "X11-16",       "risk": "CRITICAL", "score": 25},
    6017: {"service": "X11-17",       "risk": "CRITICAL", "score": 25},
    6018: {"service": "X11-18",       "risk": "CRITICAL", "score": 25},
    6019: {"service": "X11-19",       "risk": "CRITICAL", "score": 25},
    7100: {"service": "X11-FS",       "risk": "HIGH",     "score": 18},

    # ──────────────────────────────────────────────────────────────────
    #  OTHER HIGH-VALUE / MALWARE / BACKDOOR PORTS
    # ──────────────────────────────────────────────────────────────────
    4444: {"service": "METASPLOIT",   "risk": "CRITICAL", "score": 30},
    4445: {"service": "METASPLOIT",   "risk": "CRITICAL", "score": 30},
    31337:{"service": "BACKDOOR",     "risk": "CRITICAL", "score": 30},
    31338:{"service": "BACKDOOR",     "risk": "CRITICAL", "score": 30},
    6667: {"service": "IRC",          "risk": "MEDIUM",   "score": 10},
    6697: {"service": "IRC-SSL",      "risk": "LOW",      "score": 5},
    6660: {"service": "IRC",          "risk": "MEDIUM",   "score": 10},
    6661: {"service": "IRC",          "risk": "MEDIUM",   "score": 10},
    6662: {"service": "IRC",          "risk": "MEDIUM",   "score": 10},
    6663: {"service": "IRC",          "risk": "MEDIUM",   "score": 10},
    6664: {"service": "IRC",          "risk": "MEDIUM",   "score": 10},
    6665: {"service": "IRC",          "risk": "MEDIUM",   "score": 10},
    6666: {"service": "IRC",          "risk": "MEDIUM",   "score": 10},
    6668: {"service": "IRC",          "risk": "MEDIUM",   "score": 10},
    6669: {"service": "IRC",          "risk": "MEDIUM",   "score": 10},

    # ──────────────────────────────────────────────────────────────────
    #  cPanel / WEB HOSTING PANELS
    # ──────────────────────────────────────────────────────────────────
    2082: {"service": "CPANEL-HTTP",  "risk": "MEDIUM",   "score": 10},
    2083: {"service": "CPANEL-HTTPS", "risk": "MEDIUM",   "score": 8},
    2086: {"service": "WHM-HTTP",     "risk": "MEDIUM",   "score": 10},
    2087: {"service": "WHM-HTTPS",    "risk": "MEDIUM",   "score": 8},
    2077: {"service": "WEBDAV-HTTP",  "risk": "MEDIUM",   "score": 8},
    2078: {"service": "WEBDAV-HTTPS", "risk": "MEDIUM",   "score": 6},

    # ──────────────────────────────────────────────────────────────────
    #  ELASTIC / KIBANA / LOGSTASH
    # ──────────────────────────────────────────────────────────────────
    5601: {"service": "KIBANA",       "risk": "MEDIUM",   "score": 10},
    9600: {"service": "LOGSTASH",     "risk": "MEDIUM",   "score": 10},
    5044: {"service": "LOGSTASH-BEATS","risk":"MEDIUM",   "score": 8},

    # ──────────────────────────────────────────────────────────────────
    #  JAVA / APPLICATION SERVERS
    # ──────────────────────────────────────────────────────────────────
    8009: {"service": "AJP",          "risk": "CRITICAL", "score": 25},
    4848: {"service": "GLASSFISH",    "risk": "HIGH",     "score": 18},
    8089: {"service": "JETTY",        "risk": "MEDIUM",   "score": 8},
    8990: {"service": "JETTY",        "risk": "MEDIUM",   "score": 8},
    8991: {"service": "JETTY-SSL",    "risk": "MEDIUM",   "score": 6},
    4713: {"service": "JBOSS",        "risk": "HIGH",     "score": 18},
    4712: {"service": "JBOSS-SSL",    "risk": "HIGH",     "score": 15},
    8083: {"service": "JBOSS-ADM",    "risk": "HIGH",     "score": 18},
    9990: {"service": "WILDFLY-ADM",  "risk": "HIGH",     "score": 18},
    9999: {"service": "WILDFLY-ADM",  "risk": "HIGH",     "score": 18},
    8005: {"service": "TOMCAT-SHUT",  "risk": "MEDIUM",   "score": 10},
    8080: {"service": "TOMCAT",       "risk": "LOW",      "score": 3},

    # ──────────────────────────────────────────────────────────────────
    #  APPLE / iOS SERVICES
    # ──────────────────────────────────────────────────────────────────
    3689: {"service": "DAAP",         "risk": "LOW",      "score": 3},
    5003: {"service": "APPLE-JR",     "risk": "LOW",      "score": 2},
    5004: {"service": "APPLE-RTP",    "risk": "LOW",      "score": 2},
    5005: {"service": "APPLE-RTP",    "risk": "LOW",      "score": 2},

    # ──────────────────────────────────────────────────────────────────
    #  NETWORK INFRASTRUCTURE
    # ──────────────────────────────────────────────────────────────────
    53:   {"service": "DNS",          "risk": "MEDIUM",   "score": 5},
    67:   {"service": "DHCP",         "risk": "MEDIUM",   "score": 5},
    68:   {"service": "DHCP",         "risk": "MEDIUM",   "score": 5},
    179:  {"service": "BGP",          "risk": "HIGH",     "score": 18},
    546:  {"service": "DHCPV6-CLI",   "risk": "LOW",      "score": 2},
    547:  {"service": "DHCPV6-SRV",   "risk": "MEDIUM",   "score": 5},
    520:  {"service": "RIP",          "risk": "MEDIUM",   "score": 8},
    646:  {"service": "LDP",          "risk": "MEDIUM",   "score": 8},
    830:  {"service": "NETCONF",      "risk": "MEDIUM",   "score": 8},
}



DEFAULT_PORTS=list(PORT_DATABASE.keys())



# ==========================================================
# Resolve Host
# ==========================================================


def resolve_host(host):

    try:

        return socket.gethostbyname(host)

    except:

        return None




# ==========================================================
# Banner Grab
# ==========================================================


def grab_banner(ip,port):


    try:

        sock=socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect(
            (ip,port)
        )


        if port in [80,443,8080]:

            sock.send(
                b"HEAD / HTTP/1.0\r\n\r\n"
            )


        data=sock.recv(512)


        sock.close()


        if data:

            return (
                data
                .decode(
                    errors="ignore"
                )
                .replace("\n"," ")
                [:200]
            )


    except:

        pass


    return None




# ==========================================================
# Port Scanner
# ==========================================================


def scan_port(ip,port):


    service=PORT_DATABASE.get(
        port,
        {
            "service":"UNKNOWN",
            "risk":"UNKNOWN",
            "score":0
        }
    )


    result={


        "port":port,

        "protocol":"TCP",

        "state":"CLOSED",

        "service":
        service["service"],

        "risk":
        service["risk"],

        "banner":None


    }



    try:


        sock=socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )


        sock.settimeout(1)


        status=sock.connect_ex(
            (
                ip,
                port
            )
        )


        sock.close()



        if status==0:


            result["state"]="OPEN"


            result["banner"]=grab_banner(
                ip,
                port
            )



    except:

        pass



    return result





# ==========================================================
# Exposure Calculation
# ==========================================================


def calculate_exposure(ports):


    score=0


    for p in ports:


        if p["state"]=="OPEN":


            score+=PORT_DATABASE.get(
                p["port"],
                {}
            ).get(
                "score",
                0
            )



    return min(score,100)




# ==========================================================
# ASM Findings
# ==========================================================


def generate_findings(ports):


    findings=[]


    for p in ports:


        if p["state"]!="OPEN":

            continue



        if p["risk"] in [
            "HIGH",
            "CRITICAL"
        ]:


            findings.append({


                "category":
                "Infrastructure",


                "issue":
                f"{p['service']} exposed on port {p['port']}",


                "severity":
                p["risk"],


                "port":
                p["port"],


                "recommendation":
                "Restrict internet exposure using firewall or VPN"


            })



    return findings




# ==========================================================
# Main Collector
# ==========================================================


def get_port_intelligence(host):


    start=time.time()



    ip=resolve_host(host)


    if not ip:


        return {

            "error":
            "Unable to resolve host"

        }



    results=[]



    with ThreadPoolExecutor(
        max_workers=20
    ) as executor:


        jobs=[

            executor.submit(
                scan_port,
                ip,
                p
            )

            for p in DEFAULT_PORTS

        ]



        for job in as_completed(jobs):

            results.append(
                job.result()
            )



    results.sort(
        key=lambda x:x["port"]
    )



    open_ports=[

        x for x in results

        if x["state"]=="OPEN"

    ]



    return {


        "host":host,


        "ip":ip,


        "timestamp":
        datetime.now(
            timezone.utc
        ).isoformat(),



        "ports":

        open_ports,



        "summary":{


            "total_scanned":
            len(DEFAULT_PORTS),


            "open":

            len(open_ports)


        },



        "exposure_score":

        calculate_exposure(
            results
        ),



        "findings":

        generate_findings(
            results
        ),



        "scan_time":

        round(
            time.time()-start,
            2
        )

    }




# ==========================================================
# Testing
# ==========================================================


if __name__=="__main__":


    import json


    domain=input(
        "Target: "
    )


    result=get_port_intelligence(
        domain
    )


    print(
        json.dumps(
            result,
            indent=4
        )
    )