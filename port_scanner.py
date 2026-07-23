#!/usr/bin/env python3
"""
Port Scanner Tool
=================
สแกน Port ที่เปิดอยู่บนอุปกรณ์เป้าหมาย
รองรับ Single IP, Multiple IPs, Range
พร้อม Service Detection และ Banner Grabbing

Usage:
    python3 port_scanner.py
    python3 port_scanner.py -t 192.168.1.1
    python3 port_scanner.py -t 192.168.1.1 -p 1-1000
    python3 port_scanner.py -t 192.168.1.1,192.168.1.2 -p 80,443,554,8000
"""

import socket
import sys
import time
import os
import re
import json
import argparse
import concurrent.futures
from datetime import datetime

# ─── สี Terminal ────────────────────────────────────────────────────


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    MAGENTA = '\033[35m'
    WHITE = '\033[97m'
    BG_GREEN = '\033[42m'
    BG_RED = '\033[41m'


# ─── Well-Known Ports Database ──────────────────────────────────────
SERVICE_PORTS = {
    1: "tcpmux",
    7: "echo",
    9: "discard",
    11: "systat",
    13: "daytime",
    15: "netstat",
    17: "qotd",
    19: "chargen",
    20: "ftp-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "time",
    42: "nameserver",
    43: "whois",
    49: "TACACS",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    70: "Gopher",
    79: "finger",
    80: "HTTP",
    81: "HTTP-Alt",
    82: "HTTP-Alt",
    83: "HTTP-Alt",
    84: "HTTP-Alt",
    85: "HTTP-Alt",
    88: "Kerberos",
    102: "ISO-TSAP",
    104: "DICOM",
    110: "POP3",
    111: "RPCbind",
    113: "auth/ident",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    194: "IRC",
    199: "smux",
    201: "AppleTalk",
    264: "BGMP",
    318: "TSP",
    381: "HP-Openview",
    383: "HP-Openview",
    389: "LDAP",
    411: "Direct Connect",
    412: "Direct Connect",
    427: "SLP",
    443: "HTTPS",
    444: "SNPP",
    445: "SMB/CIFS",
    464: "Kerberos-Change",
    465: "SMTPS",
    497: "Retrospect",
    500: "ISAKMP/IKE",
    502: "Modbus",
    503: "Intrinsa",
    512: "rexec",
    513: "rlogin",
    514: "Syslog/rshell",
    515: "LPD/Printer",
    520: "RIP",
    521: "RIPng",
    540: "UUCP",
    548: "AFP",
    554: "RTSP",
    563: "NNTPS",
    587: "SMTP-Submit",
    591: "FileMaker",
    593: "HTTP-RPC",
    623: "IPMI/ASF",
    626: "serialnumberd",
    631: "IPP/CUPS",
    636: "LDAPS",
    646: "LDP",
    691: "MS-Exchange",
    749: "Kerberos-Admin",
    843: "Adobe-Flash",
    860: "iSCSI",
    873: "rsync",
    888: "HTTP-Alt",
    902: "VMware-Auth",
    903: "VMware-Remote",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",
    1024: "Reserved",
    1025: "NFS/IIS",
    1026: "MSTask",
    1027: "MSTask",
    1028: "MSTask",
    1029: "MSTask",
    1080: "SOCKS",
    1099: "RMI-Registry",
    1194: "OpenVPN",
    1214: "KaZaA",
    1241: "Nessus",
    1311: "Dell-OpenManage",
    1337: "WASTE",
    1433: "MSSQL",
    1434: "MSSQL-Monitor",
    1500: "VPNet",
    1503: "Windows-Messenger",
    1521: "Oracle-DB",
    1524: "ingreslock",
    1588: "PTP",
    1645: "RADIUS-Old",
    1646: "RADIUS-Old",
    1701: "L2TP",
    1716: "KDE-Connect",
    1723: "PPTP",
    1741: "CiscoWorks",
    1755: "MMS",
    1812: "RADIUS",
    1813: "RADIUS-Acct",
    1883: "MQTT",
    1900: "UPnP/SSDP",
    1935: "RTMP",
    2000: "Cisco-SCCP",
    2002: "Cisco-ACS",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2086: "WHM",
    2087: "WHM-SSL",
    2100: "Oracle-XDB",
    2181: "ZooKeeper",
    2222: "SSH-Alt",
    2375: "Docker",
    2376: "Docker-SSL",
    2379: "etcd",
    2380: "etcd-Peer",
    2483: "Oracle-DB-TLS",
    2484: "Oracle-DB-TLS",
    2500: "RTF/RFS",
    2638: "Sybase",
    2745: "Bagle-Worm",
    2967: "Symantec-AV",
    3000: "Grafana/Node",
    3001: "Node-Alt",
    3050: "Firebird",
    3074: "Xbox-Live",
    3124: "HTTP-Proxy",
    3128: "Squid-Proxy",
    3222: "GLBP",
    3260: "iSCSI-Target",
    3268: "MS-GC",
    3269: "MS-GC-SSL",
    3306: "MySQL",
    3389: "RDP",
    3396: "Printer-Agent",
    3478: "STUN/TURN",
    3500: "RTMP-Alt",
    3544: "Teredo",
    3632: "distcc",
    3689: "iTunes-DAAP",
    3690: "SVN",
    3784: "BFD-Control",
    3785: "BFD-Echo",
    3868: "Diameter",
    3872: "OMA-DM",
    3900: "udt",
    4000: "ICQ/Diablo",
    4022: "DNox",
    4040: "YWMS",
    4063: "HP-OV-SDM",
    4064: "HP-OV-SDM",
    4200: "vRealm",
    4242: "QuReS",
    4369: "EPMD",
    4443: "Pharos",
    4444: "Krb524",
    4500: "IPSec-NAT",
    4567: "TRAM",
    4662: "eMule",
    4711: "McAfee-Web",
    4730: "Gearman",
    4786: "Cisco-Smart",
    4848: "GlassFish",
    4899: "Radmin",
    4993: "Home-Agent",
    5000: "UPnP/Flask",
    5001: "Synology",
    5003: "FileMaker",
    5004: "RTP-Ctrl",
    5005: "RTP-Data",
    5006: "WSRM",
    5007: "WSRM",
    5050: "Multimedia-Conf",
    5051: "ITA-Agent",
    5060: "SIP",
    5061: "SIP-TLS",
    5080: "OnScreen",
    5104: "IBM-Tivoli",
    5190: "AIM/ICQ",
    5222: "XMPP-Client",
    5223: "XMPP-Client-SSL",
    5228: "Google-Play",
    5269: "XMPP-Server",
    5280: "XMPP-WebSocket",
    5353: "mDNS",
    5357: "WSD",
    5431: "Park-Agent",
    5432: "PostgreSQL",
    5500: "VNC-Server",
    5555: "Android-ADB",
    5601: "Kibana",
    5631: "pcAnywhere",
    5632: "pcAnywhere",
    5666: "NRPE",
    5672: "AMQP",
    5683: "CoAP",
    5800: "VNC-HTTP",
    5900: "VNC",
    5901: "VNC-1",
    5984: "CouchDB",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6000: "X11",
    6001: "X11-1",
    6379: "Redis",
    6443: "Kubernetes-API",
    6500: "BoKS",
    6501: "BoKS-Auth",
    6502: "Netop",
    6503: "Netop",
    6514: "Syslog-TLS",
    6543: "Pylons",
    6553: "Controlone",
    6588: "AnalogX-Proxy",
    6665: "IRC-Alt",
    6666: "IRC-Alt",
    6667: "IRC",
    6668: "IRC-Alt",
    6669: "IRC-Alt",
    6697: "IRC-SSL",
    6699: "WinMX",
    6881: "BitTorrent",
    6969: "acmsoda",
    7000: "Cassandra",
    7001: "WebLogic",
    7002: "WebLogic-SSL",
    7070: "RealServer",
    7071: "Zimbra-Admin",
    7078: "Zimbra",
    7100: "X-Font-Server",
    7171: "AS2",
    7199: "Cassandra-JMX",
    7272: "WatchMe",
    7373: "PXC",
    7443: "OracleAS",
    7474: "Neo4j",
    7547: "TR-069/CWMP",
    7548: "CWMP-SSL",
    7634: "hddtemp",
    7657: "I2P",
    7777: "iChat",
    7778: "Interwise",
    7779: "Vstat",
    7790: "Central-Point",
    8000: "HTTP-Alt",
    8001: "HTTP-Alt",
    8008: "HTTP-Alt",
    8009: "AJP13",
    8010: "HTTP-Alt",
    8020: "HDFS-NN",
    8042: "YARN-NM",
    8060: "Roku",
    8069: "Odoo",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt",
    8082: "HTTP-Alt",
    8083: "HTTP-Alt",
    8084: "HTTP-Alt",
    8085: "HTTP-Alt",
    8086: "InfluxDB",
    8087: "Riak",
    8088: "YARN-RM",
    8089: "Splunk",
    8090: "HTTP-Alt",
    8091: "Couchbase",
    8118: "Privoxy",
    8123: "HomeAssistant",
    8139: "Puppet",
    8140: "Puppet-Master",
    8161: "ActiveMQ",
    8200: "Vault",
    8222: "VMware-VI-API",
    8243: "WSO2-HTTPS",
    8280: "WSO2-HTTP",
    8291: "MikroTik-Winbox",
    8333: "Bitcoin",
    8334: "Bitcoin-Alt",
    8388: "Shadowsocks",
    8443: "HTTPS-Alt",
    8444: "HTTPS-Alt",
    8480: "HTTP-Alt",
    8500: "Consul",
    8530: "WSUS-HTTP",
    8531: "WSUS-HTTPS",
    8554: "RTSP-Alt",
    8649: "Ganglia",
    8686: "JMX",
    8700: "HTTP-Alt",
    8765: "WebSocket",
    8834: "Nessus-Web",
    8880: "CDDBP-Alt",
    8888: "HTTP-Alt",
    8899: "Osprey",
    8983: "Solr",
    9000: "HTTP-Alt/PHP-FPM",
    9001: "Tor-ORPort",
    9042: "Cassandra-CQL",
    9043: "WAS-Admin-SSL",
    9050: "Tor-SOCKS",
    9060: "WAS-Admin",
    9080: "GlassFish",
    9090: "WebSocket/Prometheus",
    9091: "Transmission",
    9092: "Kafka",
    9100: "Printer-RAW",
    9200: "Elasticsearch",
    9201: "Elasticsearch",
    9300: "Elasticsearch",
    9418: "Git",
    9443: "HTTPS-Alt",
    9500: "iSQLPlus",
    9595: "PingFed-Admin",
    9600: "Logstash",
    9618: "Condor",
    9870: "HDFS-NN-Web",
    9876: "SD",
    9990: "WildFly-Admin",
    9999: "HTTP-Alt",
    10000: "Webmin/NDMP",
    10001: "SCP-Config",
    10050: "Zabbix-Agent",
    10051: "Zabbix-Server",
    10250: "Kubelet",
    10255: "Kubelet-RO",
    10443: "HTTPS-Alt",
    11211: "Memcached",
    11371: "OpenPGP-HTTP",
    12345: "NetBus",
    12443: "HTTPS-Alt",
    13720: "NetBackup",
    13722: "NetBackup-BPC",
    14147: "FileZilla-Admin",
    15000: "Hydra",
    15672: "RabbitMQ-Mgmt",
    16010: "HBase-Master",
    16020: "HBase-Region",
    17000: "Courier-Auth",
    18080: "HTTP-Alt",
    19132: "Minecraft-BE",
    19150: "GKrellM",
    19226: "AdminSecure",
    20000: "DNP",
    20547: "VMware",
    20880: "Dubbo",
    21025: "Starbound",
    22222: "SSH-Alt",
    23023: "Telnet-Alt",
    25565: "Minecraft",
    25575: "Minecraft-RCON",
    27015: "Steam",
    27017: "MongoDB",
    27018: "MongoDB-Shard",
    27019: "MongoDB-Config",
    28015: "RethinkDB",
    28017: "MongoDB-Web",
    30000: "NDMPS",
    30303: "Ethereum",
    32400: "Plex",
    33060: "MySQL-X",
    33848: "Jenkins",
    35357: "Keystone-Admin",
    37777: "Dahua-NVR",
    37778: "Dahua-NVR-Data",
    40000: "SafeNet",
    43594: "RuneScape",
    44158: "Helium",
    44818: "EtherNet/IP",
    47808: "BACnet",
    49151: "IANA-Reserved",
    49152: "Dynamic",
    50000: "SAP",
    50070: "HDFS-NN-Old",
    51413: "Transmission",
    54321: "Back-Orifice",
    55442: "Unknown",
    55553: "Unknown",
    60000: "Unknown",
    60443: "Unknown",
    61613: "STOMP",
    61616: "ActiveMQ-OpenWire",
    62078: "iPhone-Sync",
    64738: "Mumble",
}

# ─── กลุ่ม Port สำหรับสแกนด่วน ────────────────────────────────────
PRESET_PORTS = {
    "quick": "สแกนด่วน (Top 20 ports)",
    "common": "Port ที่พบบ่อย (100 ports)",
    "web": "Web Services",
    "database": "Database Services",
    "camera": "IP Camera / CCTV / NVR",
    "remote": "Remote Access",
    "mail": "Mail Services",
    "iot": "IoT / Smart Devices",
    "full": "Full Scan (1-65535)",
    "custom": "กำหนดเอง",
}

QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

COMMON_PORTS = [
    20, 21, 22, 23, 25, 26, 37, 43, 53, 67, 68, 69, 79, 80, 81, 82, 83, 84, 85, 88,
    104, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 194, 389,
    443, 444, 445, 464, 465, 500, 502, 514, 515, 520, 548, 554, 563, 587, 623, 631,
    636, 873, 888, 902, 990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 1812,
    1883, 1900, 1935, 2000, 2049, 2082, 2083, 2181, 2222, 2375, 3000, 3128, 3260,
    3306, 3389, 3478, 3690, 4443, 4786, 5000, 5060, 5222, 5432, 5555, 5601, 5672,
    5900, 5984, 5985, 6379, 6443, 6667, 7001, 7443, 7474, 7547, 8000, 8008, 8009,
    8080, 8081, 8086, 8088, 8089, 8090, 8123, 8139, 8140, 8291, 8443, 8554, 8834,
    8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 9600, 9870, 9990,
    10000, 10050, 10051, 10250, 11211, 15672, 27017, 32400, 37777, 50000
]

WEB_PORTS = [
    80, 81, 82, 83, 84, 85, 443, 591, 888, 1080, 2082, 2083, 2086, 2087, 3000,
    3001, 3128, 4443, 4848, 5000, 5601, 7001, 7002, 7070, 7443, 7474, 8000, 8001,
    8008, 8009, 8010, 8020, 8042, 8060, 8069, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8091, 8118, 8123, 8161, 8200, 8243, 8280, 8291,
    8333, 8388, 8443, 8444, 8480, 8500, 8530, 8531, 8649, 8686, 8700, 8765, 8834,
    8880, 8888, 8899, 8983, 9000, 9001, 9043, 9060, 9080, 9090, 9091, 9200, 9201,
    9300, 9418, 9443, 9500, 9595, 9600, 9870, 9990, 9999, 10000, 18080
]

DATABASE_PORTS = [
    1433, 1434, 1521, 2483, 2484, 3050, 3306, 5432, 5984, 6379, 7199, 7474,
    8086, 8087, 9042, 9200, 9300, 11211, 15672, 27017, 27018, 27019, 28015,
    28017, 33060, 50000
]

CAMERA_PORTS = [
    80, 81, 82, 83, 84, 85, 443, 554, 555, 1025, 1935, 3702, 4200, 4443,
    5000, 5060, 5061, 7001, 7002, 7070, 8000, 8001, 8008, 8080, 8081,
    8090, 8091, 8443, 8554, 8555, 8800, 8888, 8899, 9000, 9001, 9090,
    9527, 10001, 34567, 34599, 37777, 37778, 49152, 49153, 49154, 49155,
    50000, 50001, 50002, 55442, 55553, 56000, 60001, 60002, 60443
]

REMOTE_PORTS = [
    22, 23, 135, 389, 445, 636, 902, 903, 1194, 1433, 1521, 1701, 1723,
    2222, 2375, 2376, 3268, 3269, 3306, 3389, 4899, 5060, 5432, 5500,
    5631, 5632, 5800, 5900, 5901, 5985, 5986, 6000, 6001, 8291, 10000,
    22222
]

MAIL_PORTS = [
    25, 110, 143, 465, 587, 993, 995, 2525
]

IOT_PORTS = [
    23, 80, 443, 502, 554, 623, 1883, 1900, 4443, 5353, 5555, 5683,
    6668, 7547, 8000, 8080, 8443, 8554, 8883, 9000, 9100, 10000,
    19132, 37777, 44818, 47808, 49152
]


# ─── ฟังก์ชันหลัก ──────────────────────────────────────────────────

def clear_screen():
    """ล้างหน้าจอ Terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """แสดง Banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     ██████╗  ██████╗ ██████╗ ████████╗                          ║
║     ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝                          ║
║     ██████╔╝██║   ██║██████╔╝   ██║                             ║
║     ██╔═══╝ ██║   ██║██╔══██╗   ██║                             ║
║     ██║     ╚██████╔╝██║  ██║   ██║                             ║
║     ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝                             ║
║      ███████╗ ██████╗ █████╗ ███╗   ██╗                         ║
║      ██╔════╝██╔════╝██╔══██╗████╗  ██║                         ║
║      ███████╗██║     ███████║██╔██╗ ██║                         ║
║      ╚════██║██║     ██╔══██║██║╚██╗██║                         ║
║      ███████║╚██████╗██║  ██║██║ ╚████║                         ║
║      ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                         ║
║                                                                  ║
║           {Colors.YELLOW}Port Scanner v2.0{Colors.CYAN}                                   ║
║           {Colors.DIM}Scan · Detect · Identify{Colors.RESET}{Colors.CYAN}{Colors.BOLD}                       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)


def scan_port(ip, port, timeout=1.5):
    """สแกน port เดียว คืน dict ถ้าเปิด, None ถ้าปิด"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = SERVICE_PORTS.get(port, "Unknown")
            banner = grab_banner(sock, ip, port, timeout)
            sock.close()
            return {
                "port": port,
                "state": "OPEN",
                "service": service,
                "banner": banner
            }
        sock.close()
    except socket.timeout:
        pass
    except OSError:
        pass
    except Exception:
        pass
    return None


def grab_banner(sock, ip, port, timeout=1.5):
    """พยายามดึง Banner จาก port ที่เปิดอยู่"""
    banner = ""
    try:
        # สำหรับ HTTP ports ส่ง GET request
        http_ports = [80, 81, 82, 83, 84, 85, 443, 888, 8000, 8001, 8008, 8009,
                      8010, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8088, 8089,
                      8090, 8091, 8443, 8554, 8888, 9000, 9090, 9443]

        if port in http_ports:
            try:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(timeout)
                sock2.connect((ip, port))
                sock2.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                response = sock2.recv(512).decode('utf-8', errors='ignore')
                sock2.close()

                # ดึง Server header
                server_match = re.search(r'Server:\s*(.+)', response, re.IGNORECASE)
                if server_match:
                    banner = server_match.group(1).strip()[:80]
                elif 'HTTP/' in response:
                    first_line = response.split('\n')[0].strip()
                    banner = first_line[:80]
            except Exception:
                pass
        elif port == 554:
            # RTSP
            try:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(timeout)
                sock2.connect((ip, port))
                sock2.sendall(b"OPTIONS rtsp://" + ip.encode() + b" RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                response = sock2.recv(512).decode('utf-8', errors='ignore')
                sock2.close()
                server_match = re.search(r'Server:\s*(.+)', response, re.IGNORECASE)
                if server_match:
                    banner = server_match.group(1).strip()[:80]
                elif 'RTSP/' in response:
                    first_line = response.split('\n')[0].strip()
                    banner = first_line[:80]
            except Exception:
                pass
        else:
            # ลองรับ banner ปกติ
            try:
                sock.settimeout(2)
                data = sock.recv(256)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
                    banner = banner.replace('\r', '').replace('\n', ' ')[:80]
            except Exception:
                pass
    except Exception:
        pass

    return banner


def parse_ports(port_str):
    """แปลงข้อความ port ให้เป็น list"""
    ports = set()
    parts = port_str.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-')
                start, end = int(start.strip()), int(end.strip())
                if start > end:
                    start, end = end, start
                for p in range(start, end + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                print(f"{Colors.RED}  ❌ Invalid port range: {part}{Colors.RESET}")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                print(f"{Colors.RED}  ❌ Invalid port: {part}{Colors.RESET}")
    return sorted(ports)


def parse_targets(target_str):
    """แปลง input เป้าหมาย ให้เป็น list ของ IP"""
    ips = []
    parts = target_str.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part and not '/' in part:
            # Range: 192.168.1.1-10
            try:
                base_and_start, end = part.rsplit('-', 1)
                octets = base_and_start.split('.')
                if len(octets) == 4:
                    base = '.'.join(octets[:3])
                    start = int(octets[3])
                    end_num = int(end)
                    for i in range(start, end_num + 1):
                        if 0 <= i <= 255:
                            ips.append(f"{base}.{i}")
                else:
                    ips.append(part)
            except (ValueError, IndexError):
                ips.append(part)
        elif '/' in part:
            # CIDR
            try:
                import ipaddress
                network = ipaddress.ip_network(part, strict=False)
                for ip in network.hosts():
                    ips.append(str(ip))
            except ValueError:
                ips.append(part)
        else:
            ips.append(part)
    return ips


def run_port_scan(ip, ports, max_threads=200, timeout=1.5):
    """สแกน ports ทั้งหมดบน IP ที่กำหนด"""
    results = []
    total = len(ports)
    scanned = 0
    open_count = 0

    print(f"\n{Colors.CYAN}  🔍 สแกน {Colors.BOLD}{ip}{Colors.RESET}{Colors.CYAN}"
          f" | {total} ports | timeout {timeout}s{Colors.RESET}")
    print(f"{Colors.DIM}  ใช้ {min(max_threads, total)} threads{Colors.RESET}\n")

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_threads, total)) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in ports}

        for future in concurrent.futures.as_completed(future_to_port):
            scanned += 1
            result = future.result()
            if result:
                open_count += 1
                results.append(result)
                banner_text = f" │ {Colors.DIM}{result['banner']}{Colors.RESET}" if result['banner'] else ""
                print(f"  {Colors.GREEN}✓{Colors.RESET} "
                      f"{Colors.BG_GREEN}{Colors.WHITE}{Colors.BOLD} OPEN {Colors.RESET} "
                      f"{Colors.YELLOW}{result['port']:>5}{Colors.RESET}/tcp  "
                      f"{Colors.CYAN}{result['service']:<20}{Colors.RESET}"
                      f"{banner_text}")
            else:
                # Progress
                if total > 100 and scanned % max(1, total // 20) == 0:
                    pct = (scanned / total) * 100
                    print(f"  {Colors.DIM}  [{scanned}/{total}] ({pct:.0f}%) scanning...{Colors.RESET}")

    elapsed = time.time() - start_time
    print(f"\n{Colors.CYAN}  ⏱️  สแกนเสร็จใน {elapsed:.1f} วินาที{Colors.RESET}")
    print(f"{Colors.GREEN}  📊 พบ {open_count} port(s) เปิดอยู่ จากทั้งหมด {total} ports{Colors.RESET}")

    return sorted(results, key=lambda x: x['port'])


def print_results_table(ip, results):
    """แสดงผลลัพธ์เป็นตาราง"""
    if not results:
        print(f"\n{Colors.YELLOW}  ⚠️  ไม่พบ port ที่เปิดอยู่บน {ip}{Colors.RESET}")
        return

    port_w = 7
    state_w = 6
    service_w = max(len(r['service']) for r in results)
    service_w = max(service_w, 10)
    service_w = min(service_w, 25)
    banner_w = 50

    total_w = port_w + state_w + service_w + banner_w + 15

    print(f"\n{Colors.CYAN}{Colors.BOLD}  ╔{'═' * total_w}╗{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}║{Colors.RESET}  🎯 Scan Results for: "
          f"{Colors.GREEN}{Colors.BOLD}{ip}{Colors.RESET}"
          f"{' ' * (total_w - 27 - len(ip))}"
          f"{Colors.CYAN}{Colors.BOLD}║{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}╠{'═' * total_w}╣{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}║{Colors.RESET}  "
          f"{Colors.BOLD}{'PORT':<{port_w}}  {'STATE':<{state_w}}  {'SERVICE':<{service_w}}  {'BANNER / VERSION':<{banner_w}}{Colors.RESET}"
          f"  {Colors.CYAN}{Colors.BOLD}║{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}╠{'─' * total_w}╣{Colors.RESET}")

    for r in results:
        banner_text = r['banner'][:banner_w] if r['banner'] else "-"
        port_str = f"{r['port']}/tcp"
        state_color = Colors.GREEN if r['state'] == 'OPEN' else Colors.RED

        print(f"  {Colors.CYAN}{Colors.BOLD}║{Colors.RESET}  "
              f"{Colors.YELLOW}{port_str:<{port_w}}{Colors.RESET}  "
              f"{state_color}{r['state']:<{state_w}}{Colors.RESET}  "
              f"{Colors.CYAN}{r['service']:<{service_w}}{Colors.RESET}  "
              f"{Colors.DIM}{banner_text:<{banner_w}}{Colors.RESET}"
              f"  {Colors.CYAN}{Colors.BOLD}║{Colors.RESET}")

    print(f"  {Colors.CYAN}{Colors.BOLD}╚{'═' * total_w}╝{Colors.RESET}")

    # สรุปตาม category
    print_port_summary(results)


def print_port_summary(results):
    categories = {
        "🌐 Web Services": [80, 81, 82, 83, 84, 85, 443, 888, 8000, 8008, 8080, 8081, 8082,
                           8083, 8084, 8085, 8443, 8888, 9000, 9090, 9443],
        "📹 Camera/RTSP": [554, 555, 8554, 8555, 37777, 37778, 34567, 34599, 9527],
        "🔐 Remote Access": [22, 23, 135, 445, 3389, 5900, 5901, 8291],
        "🗄️  Database": [1433, 1521, 3306, 5432, 6379, 9200, 27017, 11211],
        "📧 Mail": [25, 110, 143, 465, 587, 993, 995],
        "📁 File Transfer": [20, 21, 69, 139, 445, 548, 873, 2049],
        "🔒 Security/VPN": [500, 1194, 1701, 1723, 4500, 8443],
    }

    found_categories = {}
    for r in results:
        for cat, ports in categories.items():
            if r['port'] in ports:
                if cat not in found_categories:
                    found_categories[cat] = []
                found_categories[cat].append(r)

    if found_categories:
        print(f"\n{Colors.BOLD}  📋 สรุปตามหมวดหมู่:{Colors.RESET}")
        for cat, ports in found_categories.items():
            port_list = ", ".join([f"{p['port']}" for p in ports])
            print(f"    {cat}: {Colors.GREEN}{port_list}{Colors.RESET}")


def show_port_menu():
    """แสดงเมนูเลือก port preset"""
    print(f"""
{Colors.BOLD}  🎯 เลือกกลุ่ม Port ที่ต้องการสแกน:{Colors.RESET}
  {Colors.CYAN}┌────────────────────────────────────────────────────────────────┐{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[1]{Colors.RESET} 🚀 Quick Scan       ── Top 20 ports ที่ใช้บ่อย         {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[2]{Colors.RESET} 📊 Common Ports     ── 100+ ports ที่พบบ่อย            {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[3]{Colors.RESET} 🌐 Web Services     ── HTTP/HTTPS/Proxy                {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[4]{Colors.RESET} 🗄️  Database         ── MySQL/PostgreSQL/Redis/Mongo    {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[5]{Colors.RESET} 📹 Camera/CCTV      ── RTSP/HTTP/Hikvision/Dahua       {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[6]{Colors.RESET} 🔐 Remote Access    ── SSH/RDP/VNC/Telnet              {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[7]{Colors.RESET} 📧 Mail Services    ── SMTP/POP3/IMAP                  {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[8]{Colors.RESET} 📡 IoT/Smart        ── MQTT/CoAP/UPnP                  {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[9]{Colors.RESET} 💪 Full Scan        ── 1-65535 (ใช้เวลานาน)            {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[U]{Colors.RESET} 📡 UDP Scan         ── DNS/SNMP/NTP/DHCP/SSDP (UDP)    {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[0]{Colors.RESET} ✏️  Custom           ── กำหนดเอง (เช่น 80,443,554)      {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}└────────────────────────────────────────────────────────────────┘{Colors.RESET}
""")


# ─── UDP Port Scanner ─────────────────────────────────────────────

UDP_PORTS = {
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    161: "SNMP",
    162: "SNMP-Trap",
    500: "IKE/IPSec",
    514: "Syslog",
    520: "RIP",
    623: "IPMI",
    1194: "OpenVPN",
    1701: "L2TP",
    1812: "RADIUS",
    1813: "RADIUS-Acct",
    1900: "UPnP/SSDP",
    4500: "IPSec-NAT",
    5353: "mDNS",
    5683: "CoAP",
    1883: "MQTT",
    47808: "BACnet",
}


def scan_udp_port(ip, port, timeout=2):
    """สแกน UDP port เดียว — คืน dict ถ้า open|filtered, None ถ้าปิด"""
    service = UDP_PORTS.get(port, "Unknown")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Probe payload ตาม protocol
        if port == 53:   # DNS query
            payload = b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'
        elif port == 161:  # SNMP GetRequest
            payload = (b'0\x26\x02\x01\x00\x04\x06public'
                       b'\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00'
                       b'\x02\x01\x000\x0b0\x09\x06\x05+\x06\x01\x02\x01\x05\x00')
        elif port == 123:  # NTP
            payload = b'\x1b' + b'\x00' * 47
        elif port == 1900:  # SSDP
            payload = (b'M-SEARCH * HTTP/1.1\r\n'
                       b'HOST: 239.255.255.250:1900\r\n'
                       b'MAN: "ssdp:discover"\r\nMX: 1\r\n'
                       b'ST: ssdp:all\r\n\r\n')
        elif port == 5353:  # mDNS
            payload = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05_http\x04_tcp\x05local\x00\x00\xff\x00\xff'
        else:
            payload = b'\x00' * 4

        sock.sendto(payload, (ip, port))
        data, _ = sock.recvfrom(1024)
        sock.close()
        banner = ""
        if data:
            try:
                banner = data[:80].decode('utf-8', errors='ignore').strip().replace('\n', ' ')
            except BaseException:
                pass
        return {"port": port, "proto": "UDP", "state": "OPEN", "service": service, "banner": banner}
    except socket.timeout:
        # UDP timeout = open|filtered (ปกติของ UDP)
        return {"port": port, "proto": "UDP", "state": "OPEN|FILTERED", "service": service, "banner": ""}
    except Exception:
        return None


def run_udp_scan(ip, timeout=2):
    """สแกน UDP ports ทั้งหมด"""
    ports = list(UDP_PORTS.keys())
    results = []

    print(f"\n{Colors.CYAN}  📡 UDP Scan {Colors.BOLD}{ip}{Colors.RESET}{Colors.CYAN}"
          f" | {len(ports)} UDP ports{Colors.RESET}")
    print(f"{Colors.DIM}  (UDP open|filtered = ไม่ได้รับ ICMP port-unreachable){Colors.RESET}\n")

    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_udp_port, ip, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                color = Colors.GREEN if res['state'] == 'OPEN' else Colors.YELLOW
                banner_t = f" | {Colors.DIM}{res['banner']}{Colors.RESET}" if res['banner'] else ""
                print(f"  {color}✓{Colors.RESET} "
                      f"{color}[{res['state']}]{Colors.RESET} "
                      f"{Colors.YELLOW}{res['port']:>6}{Colors.RESET}/udp  "
                      f"{Colors.CYAN}{res['service']:<20}{Colors.RESET}"
                      f"{banner_t}")
                results.append(res)

    elapsed = time.time() - start
    print(f"\n{Colors.CYAN}  ⏱️  สแกนเสร็จใน {elapsed:.1f} วินาที{Colors.RESET}")
    print(f"{Colors.GREEN}  📊 พบ UDP {len(results)} port(s) open/filtered{Colors.RESET}")
    return sorted(results, key=lambda x: x['port'])


def export_results(ip, results, filename):
    """บันทึกผลลัพธ์เป็น CSV หรือ JSON"""
    if filename.endswith('.json'):
        data = {
            "target": ip,
            "scan_time": datetime.now().isoformat(),
            "open_ports": results
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    else:
        if not filename.endswith('.csv'):
            filename += '.csv'
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("Target,Port,State,Service,Banner\n")
            for r in results:
                banner = r['banner'].replace('"', '""') if r['banner'] else ""
                f.write(f'{ip},{r["port"]},{r["state"]},{r["service"]},"{banner}"\n')

    print(f"\n{Colors.GREEN}  ✅ ผลลัพธ์ถูกบันทึกไปที่: {filename}{Colors.RESET}")


def get_preset_ports(preset_name):
    """คืน list ของ ports ตาม preset"""
    presets = {
        "quick": QUICK_PORTS,
        "common": COMMON_PORTS,
        "web": WEB_PORTS,
        "database": DATABASE_PORTS,
        "camera": CAMERA_PORTS,
        "remote": REMOTE_PORTS,
        "mail": MAIL_PORTS,
        "iot": IOT_PORTS,
    }
    return presets.get(preset_name, QUICK_PORTS)


def show_port_menu():
    """แสดงเมนูเลือก port preset"""
    print(f"""
{Colors.BOLD}  🎯 เลือกกลุ่ม Port ที่ต้องการสแกน:{Colors.RESET}
  {Colors.CYAN}┌──────────────────────────────────────────────────────────────┐{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[1]{Colors.RESET} 🚀 Quick Scan       ── Top 20 ports ที่ใช้บ่อย         {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[2]{Colors.RESET} 📊 Common Ports     ── 100+ ports ที่พบบ่อย            {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[3]{Colors.RESET} 🌐 Web Services     ── HTTP/HTTPS/Proxy                {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[4]{Colors.RESET} 🗄️  Database         ── MySQL/PostgreSQL/Redis/Mongo    {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[5]{Colors.RESET} 📹 Camera/CCTV      ── RTSP/HTTP/Hikvision/Dahua       {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[6]{Colors.RESET} 🔐 Remote Access    ── SSH/RDP/VNC/Telnet              {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[7]{Colors.RESET} 📧 Mail Services    ── SMTP/POP3/IMAP                  {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[8]{Colors.RESET} 📡 IoT/Smart        ── MQTT/CoAP/UPnP                  {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[9]{Colors.RESET} 💪 Full Scan        ── 1-65535 (ใช้เวลานาน)            {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[0]{Colors.RESET} ✏️  Custom           ── กำหนดเอง (เช่น 80,443,554)      {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}└──────────────────────────────────────────────────────────────┘{Colors.RESET}
""")


def interactive_mode():
    """โหมด Interactive"""
    clear_screen()
    print_banner()

    while True:
        # รับ target
        print(f"\n{Colors.BOLD}  📡 ใส่ IP เป้าหมาย:{Colors.RESET}")
        print(f"{Colors.DIM}  รูปแบบ: Single (192.168.1.1) | หลายตัว (192.168.1.1,192.168.1.2)"
              f" | Range (192.168.1.1-10){Colors.RESET}")
        target = input(f"  {Colors.BOLD}Target: {Colors.RESET}").strip()
        if not target:
            continue
        if target.lower() in ['q', 'quit', 'exit', '0']:
            print(f"\n{Colors.CYAN}  👋 ขอบคุณที่ใช้งาน Port Scanner!{Colors.RESET}\n")
            sys.exit(0)

        targets = parse_targets(target)
        if not targets:
            print(f"{Colors.RED}  ❌ ไม่สามารถแปลงเป้าหมายได้{Colors.RESET}")
            continue

        # ทดสอบ ping ก่อน
        print(f"\n{Colors.DIM}  กำลังเช็คว่า host ออนไลน์...{Colors.RESET}")
        for t in targets:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((t, 80))
                sock.close()
                print(f"  {Colors.GREEN}✓{Colors.RESET} {t} - reachable")
            except Exception:
                try:
                    socket.gethostbyname(t)
                    print(f"  {Colors.YELLOW}~{Colors.RESET} {t} - DNS resolved (may be filtered)")
                except Exception:
                    print(f"  {Colors.RED}✗{Colors.RESET} {t} - unreachable or invalid")

        # เลือกกลุ่ม port
        show_port_menu()
        port_choice = input(
            f"  {Colors.BOLD}เลือก [{Colors.CYAN}0-9{Colors.RESET}{Colors.BOLD}]: {Colors.RESET}").strip()

        ports = []
        if port_choice == '1':
            ports = QUICK_PORTS
        elif port_choice == '2':
            ports = COMMON_PORTS
        elif port_choice == '3':
            ports = WEB_PORTS
        elif port_choice == '4':
            ports = DATABASE_PORTS
        elif port_choice == '5':
            ports = CAMERA_PORTS
        elif port_choice == '6':
            ports = REMOTE_PORTS
        elif port_choice == '7':
            ports = MAIL_PORTS
        elif port_choice == '8':
            ports = IOT_PORTS
        elif port_choice == '9':
            print(f"\n{Colors.YELLOW}  ⚠️  Full Scan จะสแกนทั้ง 65,535 ports และใช้เวลานานมาก{Colors.RESET}")
            confirm = input(f"  {Colors.BOLD}ยืนยัน? [y/N]: {Colors.RESET}").strip().lower()
            if confirm != 'y':
                continue
            ports = list(range(1, 65536))
        elif port_choice == '0':
            print(f"\n{Colors.BOLD}  ใส่ Port ที่ต้องการ:{Colors.RESET}")
            print(f"{Colors.DIM}  รูปแบบ: Single (80) | หลายตัว (80,443,554) | Range (1-1000)"
                  f" | ผสม (22,80,443,8000-8100){Colors.RESET}")
            port_input = input(f"  {Colors.BOLD}Ports: {Colors.RESET}").strip()
            if not port_input:
                continue
            ports = parse_ports(port_input)
        else:
            print(f"{Colors.RED}  ❌ ตัวเลือกไม่ถูกต้อง{Colors.RESET}")
            continue

        if not ports:
            print(f"{Colors.RED}  ❌ ไม่มี port ที่จะสแกน{Colors.RESET}")
            continue

        # ตั้ง timeout
        timeout = 1.5
        if len(ports) > 1000:
            timeout_input = input(f"\n  {Colors.BOLD}Timeout ต่อ port (default=1.0s, กด Enter): {Colors.RESET}").strip()
            if timeout_input:
                try:
                    timeout = float(timeout_input)
                except ValueError:
                    timeout = 1.0
            else:
                timeout = 1.0

        # ตั้งจำนวน threads
        thread_count = 200
        if len(ports) > 5000:
            thread_input = input(f"  {Colors.BOLD}จำนวน threads (default=500, max=1000): {Colors.RESET}").strip()
            if thread_input.isdigit():
                thread_count = min(int(thread_input), 1000)
            else:
                thread_count = 500

        # สแกนแต่ละ target
        all_results = {}
        for t in targets:
            results = run_port_scan(t, ports, max_threads=thread_count, timeout=timeout)
            print_results_table(t, results)
            all_results[t] = results

        # ถามว่าต้องการ export
        has_results = any(len(r) > 0 for r in all_results.values())
        if has_results:
            export_choice = input(f"\n  {Colors.BOLD}ต้องการบันทึกผลลัพธ์? [y/N]: {Colors.RESET}").strip().lower()
            if export_choice == 'y':
                filename = input(f"  {Colors.BOLD}ชื่อไฟล์ (default: port_scan_result.csv): {Colors.RESET}").strip()
                if not filename:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"port_scan_{timestamp}.csv"

                # export ทุก target ลงไฟล์เดียว
                if filename.endswith('.json'):
                    data = {
                        "scan_time": datetime.now().isoformat(),
                        "targets": {}
                    }
                    for t, r in all_results.items():
                        data["targets"][t] = r
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    print(f"\n{Colors.GREEN}  ✅ ผลลัพธ์ถูกบันทึกไปที่: {filename}{Colors.RESET}")
                else:
                    if not filename.endswith('.csv'):
                        filename += '.csv'
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write("Target,Port,State,Service,Banner\n")
                        for t, results in all_results.items():
                            for r in results:
                                banner = r['banner'].replace('"', '""') if r['banner'] else ""
                                f.write(f'{t},{r["port"]},{r["state"]},{r["service"]},"{banner}"\n')
                    print(f"\n{Colors.GREEN}  ✅ ผลลัพธ์ถูกบันทึกไปที่: {filename}{Colors.RESET}")

        # ถามว่าจะสแกนต่อหรือไม่
        print()
        cont = input(f"  {Colors.BOLD}สแกนต่อหรือไม่? [Y/n]: {Colors.RESET}").strip().lower()
        if cont == 'n':
            print(f"\n{Colors.CYAN}  👋 ขอบคุณที่ใช้งาน Port Scanner!{Colors.RESET}\n")
            break


def cli_mode(args):
    """โหมด Command-line"""
    print_banner()

    targets = parse_targets(args.target)
    if not targets:
        print(f"{Colors.RED}  ❌ Invalid target: {args.target}{Colors.RESET}")
        sys.exit(1)

    # กำหนด ports
    if args.ports:
        if args.ports.lower() == 'camera':
            ports = CAMERA_PORTS
        elif args.ports.lower() == 'web':
            ports = WEB_PORTS
        elif args.ports.lower() == 'common':
            ports = COMMON_PORTS
        elif args.ports.lower() == 'quick':
            ports = QUICK_PORTS
        elif args.ports.lower() == 'db' or args.ports.lower() == 'database':
            ports = DATABASE_PORTS
        elif args.ports.lower() == 'remote':
            ports = REMOTE_PORTS
        elif args.ports.lower() == 'full':
            ports = list(range(1, 65536))
        else:
            ports = parse_ports(args.ports)
    else:
        ports = COMMON_PORTS

    if not ports:
        print(f"{Colors.RED}  ❌ No valid ports to scan{Colors.RESET}")
        sys.exit(1)

    timeout = args.timeout if args.timeout else 1.5
    threads = args.threads if args.threads else 200

    all_results = {}
    for t in targets:
        results = run_port_scan(t, ports, max_threads=threads, timeout=timeout)
        print_results_table(t, results)
        all_results[t] = results

    # Export
    if args.output:
        for t, results in all_results.items():
            if results:
                export_results(t, results, args.output)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Port Scanner - สแกน port ที่เปิดอยู่บนอุปกรณ์เป้าหมาย",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 port_scanner.py                              # Interactive mode
  python3 port_scanner.py -t 192.168.1.1               # Scan common ports
  python3 port_scanner.py -t 192.168.1.1 -p 80,443     # Scan specific ports
  python3 port_scanner.py -t 192.168.1.1 -p 1-1000     # Scan port range
  python3 port_scanner.py -t 192.168.1.1 -p camera     # Scan camera ports
  python3 port_scanner.py -t 192.168.1.1 -p web        # Scan web ports
  python3 port_scanner.py -t 192.168.1.1,192.168.1.2 -p quick
  python3 port_scanner.py -t 192.168.1.1 -p 1-65535 -o scan.csv

Port Presets:
  quick     Top 20 ports
  common    100+ common ports
  web       Web service ports
  camera    IP Camera/CCTV ports (RTSP, HTTP, etc.)
  database  Database ports (MySQL, PostgreSQL, Redis, etc.)
  remote    Remote access ports (SSH, RDP, VNC, etc.)
  full      All ports 1-65535
        """
    )
    parser.add_argument('-t', '--target', help='Target IP(s) - comma separated or range')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 80,443 or 1-1000 or camera)')
    parser.add_argument('-o', '--output', help='Output file (CSV or JSON)')
    parser.add_argument('--timeout', type=float, default=1.5, help='Timeout per port (default: 1.5s)')
    parser.add_argument('--threads', type=int, default=200, help='Max threads (default: 200)')

    args = parser.parse_args()

    if args.target:
        cli_mode(args)
    else:
        interactive_mode()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n{Colors.CYAN}  👋 ขอบคุณที่ใช้งาน Port Scanner!{Colors.RESET}\n")
        sys.exit(0)
