#!/usr/bin/env python3
"""
Vulnerability Scanner Tool
===========================
สแกนช่องโหว่พื้นฐานของอุปกรณ์เป้าหมาย
- ตรวจ Default Credentials (Hikvision, Dahua, Router, etc.)
- ตรวจ HTTP Security Headers
- ตรวจ SSL/TLS Weakness
- ตรวจ RTSP Authentication Bypass
- ตรวจ Service Version สำหรับ Known CVEs
- ตรวจ Common Misconfigurations

Usage:
    python3 vuln_scanner.py
    python3 vuln_scanner.py -t 192.168.1.1
    python3 vuln_scanner.py -t 192.168.1.1 -m all
    python3 vuln_scanner.py -t 192.168.1.1 -m camera

⚠️  ใช้เพื่อตรวจสอบเครือข่ายของตัวเองเท่านั้น
"""

import socket
import ssl
import sys
import time
import os
import re
import json
import base64
import argparse
import concurrent.futures
import urllib.request
import urllib.error
from datetime import datetime
from collections import OrderedDict

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
    BG_RED = '\033[41m'
    BG_YELLOW = '\033[43m'
    BG_GREEN = '\033[42m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'

# ─── Severity Levels ───────────────────────────────────────────────


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_COLORS = {
    Severity.CRITICAL: f"{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD}",
    Severity.HIGH: f"{Colors.RED}{Colors.BOLD}",
    Severity.MEDIUM: f"{Colors.YELLOW}{Colors.BOLD}",
    Severity.LOW: f"{Colors.BLUE}{Colors.BOLD}",
    Severity.INFO: f"{Colors.CYAN}",
}

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "ℹ️ ",
}

# ─── Default Credentials Database ──────────────────────────────────
DEFAULT_CREDS = {
    "hikvision": [
        ("admin", "12345"),
        ("admin", "admin12345"),
        ("admin", "a]12345"),
        ("admin", "Admin12345"),
        ("admin", "admin"),
        ("admin", "123456"),
        ("admin", "1234"),
        ("admin", "password"),
        ("admin", "abcd1234"),
        ("admin", "hiklinux"),
    ],
    "dahua": [
        ("admin", "admin"),
        ("admin", "Admin123"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("admin", "888888"),
        ("admin", "666666"),
        ("888888", "888888"),
        ("666666", "666666"),
        ("default", "default"),
    ],
    "axis": [
        ("root", "pass"),
        ("root", "root"),
        ("root", "admin"),
        ("admin", "admin"),
        ("root", "camera"),
    ],
    "uniview": [
        ("admin", "123456"),
        ("admin", "admin"),
        ("admin", "admin123"),
    ],
    "generic_camera": [
        ("admin", "admin"),
        ("admin", "12345"),
        ("admin", "123456"),
        ("admin", "1234"),
        ("admin", "password"),
        ("admin", ""),
        ("root", "root"),
        ("root", "pass"),
        ("root", "admin"),
        ("user", "user"),
        ("guest", "guest"),
        ("admin", "camera"),
    ],
    "router": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", "12345"),
        ("admin", "123456"),
        ("admin", ""),
        ("root", "root"),
        ("root", "admin"),
        ("root", "password"),
        ("root", ""),
        ("user", "user"),
        ("cisco", "cisco"),
        ("ubnt", "ubnt"),
        ("admin", "admin1234"),
        ("admin", "default"),
    ],
    "ssh": [
        ("root", "root"),
        ("root", "toor"),
        ("root", "password"),
        ("root", "admin"),
        ("root", "123456"),
        ("root", "12345"),
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("user", "user"),
        ("test", "test"),
        ("pi", "raspberry"),
        ("ubnt", "ubnt"),
    ],
    "database": [
        ("root", ""),
        ("root", "root"),
        ("root", "password"),
        ("root", "admin"),
        ("root", "123456"),
        ("sa", ""),
        ("sa", "sa"),
        ("sa", "password"),
        ("postgres", "postgres"),
        ("admin", "admin"),
    ],
    "web_admin": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("admin", "12345"),
        ("admin", ""),
        ("root", "root"),
        ("administrator", "administrator"),
        ("administrator", "password"),
        ("test", "test"),
        ("guest", "guest"),
    ],
}

# ─── Known CVE Database (ตาม Service/Version) ─────────────────────
KNOWN_CVES = {
    "hikvision": [
        {
            "cve": "CVE-2021-36260",
            "severity": Severity.CRITICAL,
            "description": "Hikvision Command Injection - RCE ผ่าน HTTP ไม่ต้อง login",
            "affected": "Hikvision firmware < Build 210628",
            "check_type": "http_path",
            "path": "/SDK/webLanguage",
            "method": "PUT",
        },
        {
            "cve": "CVE-2017-7921",
            "severity": Severity.CRITICAL,
            "description": "Hikvision Auth Bypass - เข้าถึง config โดยไม่ต้อง login",
            "affected": "Hikvision firmware < 5.4.5",
            "check_type": "http_path",
            "path": "/System/configurationFile?auth=YWRtaW46MTEK",
            "method": "GET",
        },
        {
            "cve": "CVE-2017-7920",
            "severity": Severity.HIGH,
            "description": "Hikvision Improper Authentication - ดู snapshot โดยไม่ login",
            "affected": "Hikvision firmware < 5.4.5",
            "check_type": "http_path",
            "path": "/onvif-http/snapshot?auth=YWRtaW46MTEK",
            "method": "GET",
        },
        {
            "cve": "CVE-2023-28808",
            "severity": Severity.CRITICAL,
            "description": "Hikvision Access Control Bypass",
            "affected": "DS-K1T804/DS-K1A804 series",
            "check_type": "banner_match",
            "pattern": r"DS-K1[AT]804",
        },
    ],
    "dahua": [
        {
            "cve": "CVE-2021-33044",
            "severity": Severity.CRITICAL,
            "description": "Dahua Authentication Bypass - login ได้โดยไม่ต้องรหัส",
            "affected": "Dahua firmware < 2021-07",
            "check_type": "http_path",
            "path": "/cgi-bin/magicBox.cgi?action=getMachineName",
            "method": "GET",
        },
        {
            "cve": "CVE-2021-33045",
            "severity": Severity.CRITICAL,
            "description": "Dahua Auth Bypass via Cookie",
            "affected": "Dahua firmware < 2021-07",
            "check_type": "http_path",
            "path": "/cgi-bin/configManager.cgi?action=getConfig&name=Network",
            "method": "GET",
        },
        {
            "cve": "CVE-2020-25078",
            "severity": Severity.HIGH,
            "description": "Dahua Admin Password Disclosure",
            "affected": "Dahua DH-IPC-HXXXX",
            "check_type": "http_path",
            "path": "/cgi-bin/credentials.cgi",
            "method": "GET",
        },
    ],
    "generic": [
        {
            "cve": "CVE-2014-0160",
            "severity": Severity.CRITICAL,
            "description": "Heartbleed - OpenSSL memory leak",
            "affected": "OpenSSL 1.0.1 - 1.0.1f",
            "check_type": "banner_match",
            "pattern": r"OpenSSL/1\.0\.1[a-f]?\b",
        },
        {
            "cve": "CVE-2014-6271",
            "severity": Severity.CRITICAL,
            "description": "Shellshock - Bash remote code execution",
            "affected": "GNU Bash < 4.3",
            "check_type": "banner_match",
            "pattern": r"bash",
        },
    ],
}

# ─── Security Headers ที่ควรมี ─────────────────────────────────────
SECURITY_HEADERS = OrderedDict([
    ("Strict-Transport-Security", {
        "severity": Severity.MEDIUM,
        "description": "ป้องกัน downgrade attack จาก HTTPS เป็น HTTP",
        "fix": "เพิ่ม Header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    }),
    ("X-Content-Type-Options", {
        "severity": Severity.LOW,
        "description": "ป้องกัน MIME-type sniffing",
        "fix": "เพิ่ม Header: X-Content-Type-Options: nosniff",
    }),
    ("X-Frame-Options", {
        "severity": Severity.MEDIUM,
        "description": "ป้องกัน Clickjacking attack",
        "fix": "เพิ่ม Header: X-Frame-Options: DENY หรือ SAMEORIGIN",
    }),
    ("X-XSS-Protection", {
        "severity": Severity.LOW,
        "description": "ป้องกัน XSS (Cross-Site Scripting) ใน browser เก่า",
        "fix": "เพิ่ม Header: X-XSS-Protection: 1; mode=block",
    }),
    ("Content-Security-Policy", {
        "severity": Severity.MEDIUM,
        "description": "ป้องกัน XSS และ code injection",
        "fix": "เพิ่ม Header: Content-Security-Policy: default-src 'self'",
    }),
    ("Referrer-Policy", {
        "severity": Severity.LOW,
        "description": "ควบคุมข้อมูล Referrer ที่ส่งออกไป",
        "fix": "เพิ่ม Header: Referrer-Policy: strict-origin-when-cross-origin",
    }),
    ("Permissions-Policy", {
        "severity": Severity.LOW,
        "description": "ควบคุม Feature/Permission ของ Browser API",
        "fix": "เพิ่ม Header: Permissions-Policy: geolocation=(), camera=()",
    }),
])

# ─── Dangerous Headers ที่ไม่ควรเปิด ───────────────────────────────
DANGEROUS_HEADERS = {
    "Server": {
        "severity": Severity.LOW,
        "description": "เปิดเผยข้อมูล Web Server version",
        "fix": "ซ่อน Server header หรือลดข้อมูลที่แสดง",
    },
    "X-Powered-By": {
        "severity": Severity.LOW,
        "description": "เปิดเผยข้อมูล Framework/Technology ที่ใช้",
        "fix": "ลบ X-Powered-By header ออก",
    },
    "X-AspNet-Version": {
        "severity": Severity.LOW,
        "description": "เปิดเผยเวอร์ชัน ASP.NET",
        "fix": "ลบ X-AspNet-Version header ออก",
    },
}


# ─── ฟังก์ชันหลัก ──────────────────────────────────────────────────

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    banner = f"""
{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗                       ║
║     ██║   ██║██║   ██║██║     ████╗  ██║                       ║
║     ██║   ██║██║   ██║██║     ██╔██╗ ██║                       ║
║     ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║                       ║
║      ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║                       ║
║       ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝                       ║
║      ███████╗ ██████╗ █████╗ ███╗   ██╗                         ║
║      ██╔════╝██╔════╝██╔══██╗████╗  ██║                         ║
║      ███████╗██║     ███████║██╔██╗ ██║                         ║
║      ╚════██║██║     ██╔══██║██║╚██╗██║                         ║
║      ███████║╚██████╗██║  ██║██║ ╚████║                         ║
║      ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                         ║
║                                                                  ║
║           {Colors.YELLOW}Vulnerability Scanner v1.0{Colors.RED}                          ║
║           {Colors.DIM}{Colors.WHITE}Scan · Detect · Report{Colors.RESET}{Colors.RED}{Colors.BOLD}                          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.YELLOW}  ⚠️  ใช้เพื่อตรวจสอบเครือข่ายของตนเองเท่านั้น{Colors.RESET}
{Colors.DIM}  การสแกนอุปกรณ์โดยไม่ได้รับอนุญาตถือเป็นสิ่งผิดกฎหมาย{Colors.RESET}
"""
    print(banner)


def print_severity(severity, text):
    """แสดงข้อความพร้อม severity"""
    color = SEVERITY_COLORS.get(severity, Colors.RESET)
    emoji = SEVERITY_EMOJI.get(severity, "")
    print(f"  {emoji} {color}[{severity}]{Colors.RESET} {text}")


def is_port_open(ip, port, timeout=2):
    """เช็คว่า port เปิดหรือไม่"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_banner(ip, port, timeout=3):
    """ดึง banner จาก port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        http_ports = [80, 81, 82, 83, 84, 85, 443, 888, 8000, 8001, 8008, 8080,
                      8081, 8082, 8088, 8443, 8554, 8888, 9000, 9090]

        if port in http_ports:
            sock.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
        elif port == 554:
            sock.sendall(f"OPTIONS rtsp://{ip} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
        else:
            pass  # จะ recv banner ที่ server ส่งมาเอง

        data = sock.recv(2048)
        sock.close()
        return data.decode('utf-8', errors='ignore')
    except Exception:
        return ""


def http_request(ip, port, path="/", method="GET", timeout=5, auth=None, headers=None):
    """ส่ง HTTP request ไปยังเป้าหมาย"""
    scheme = "https" if port in [443, 8443] else "http"
    url = f"{scheme}://{ip}:{port}{path}"

    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
        req.add_header("Connection", "close")

        if auth:
            credentials = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            req.add_header("Authorization", f"Basic {credentials}")

        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        response = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return {
            "status": response.status,
            "headers": dict(response.headers),
            "body": response.read(8192).decode('utf-8', errors='ignore'),
            "url": url,
        }
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "headers": dict(e.headers) if hasattr(e, 'headers') else {},
            "body": e.read(4096).decode('utf-8', errors='ignore') if hasattr(e, 'read') else "",
            "url": url,
        }
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════
# ─── โมดูลตรวจสอบ ──────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════

def check_open_ports(ip, findings):
    """สแกน port ที่เปิดอยู่"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}  ── [1/7] สแกน Port ที่เปิดอยู่ ──{Colors.RESET}")

    # Port ที่ต้องเช็ค
    ports_to_check = [
        21, 22, 23, 25, 53, 80, 81, 82, 83, 84, 85,
        110, 111, 135, 139, 143, 161, 443, 445, 502,
        554, 555, 587, 623, 631, 993, 995,
        1433, 1521, 1723, 1883,
        2049, 2082, 2083, 2222, 2375,
        3000, 3128, 3306, 3389, 3478,
        4443, 4786, 4899,
        5000, 5060, 5432, 5555, 5601, 5672, 5900, 5984, 5985,
        6379, 6443,
        7001, 7443, 7474, 7547,
        8000, 8001, 8008, 8009, 8080, 8081, 8088, 8090,
        8123, 8139, 8291, 8443, 8554, 8834, 8888,
        9000, 9042, 9090, 9100, 9200, 9418, 9443, 9527, 9600,
        10000, 10050, 10250, 11211,
        27017, 34567, 37777,
        49152, 50000, 55553, 60443,
    ]

    open_ports = []
    total = len(ports_to_check)

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(is_port_open, ip, port): port for port in ports_to_check}
        done_count = 0
        for future in concurrent.futures.as_completed(future_to_port):
            done_count += 1
            port = future_to_port[future]
            if future.result():
                open_ports.append(port)
            if done_count % 20 == 0:
                print(f"  {Colors.DIM}  [{done_count}/{total}] ({done_count*100//total}%) scanning...{Colors.RESET}")

    open_ports.sort()
    print(f"  {Colors.GREEN}  พบ {len(open_ports)} port(s) เปิดอยู่{Colors.RESET}")

    # ตรวจ port อันตราย
    dangerous_ports = {
        23: ("Telnet", "ข้อมูลส่งแบบ plaintext ไม่เข้ารหัส ควรใช้ SSH แทน"),
        21: ("FTP", "ข้อมูลส่งแบบ plaintext ควรใช้ SFTP แทน"),
        25: ("SMTP", "อาจถูกใช้ส่ง spam ถ้าเป็น open relay"),
        135: ("MSRPC", "เสี่ยงต่อ exploit เช่น EternalBlue"),
        139: ("NetBIOS", "เปิดเผยข้อมูลระบบ อาจถูก exploit"),
        445: ("SMB", "เสี่ยงต่อ WannaCry/EternalBlue ถ้าไม่อัพเดท"),
        502: ("Modbus", "Industrial protocol ไม่มี authentication"),
        161: ("SNMP", "อาจมี community string เป็น public/private"),
        623: ("IPMI", "เสี่ยงต่อ password hash disclosure"),
        2375: ("Docker", "Docker API ไม่มี authentication! RCE ได้ทันที"),
        5555: ("ADB", "Android Debug Bridge เปิดอยู่ RCE ได้"),
        6379: ("Redis", "มักไม่มี authentication เสี่ยง RCE"),
        9200: ("Elasticsearch", "มักไม่มี auth เข้าถึงข้อมูลได้"),
        11211: ("Memcached", "ไม่มี auth อาจใช้ DDoS amplification"),
        27017: ("MongoDB", "มักไม่มี auth เข้าถึง database ได้"),
        4786: ("Cisco Smart Install", "เสี่ยง RCE ถ้าเปิดอยู่"),
        7547: ("TR-069/CWMP", "เสี่ยงต่อ remote management exploit"),
        10250: ("Kubelet", "Kubernetes API อาจไม่มี auth"),
    }

    for port in open_ports:
        if port in dangerous_ports:
            name, desc = dangerous_ports[port]
            findings.append({
                "module": "Port Scan",
                "severity": Severity.HIGH if port in [2375, 6379, 27017, 11211, 445, 502] else Severity.MEDIUM,
                "title": f"Port {port} ({name}) เปิดอยู่",
                "description": desc,
                "recommendation": f"ปิด port {port} ถ้าไม่จำเป็น หรือจำกัดการเข้าถึงด้วย Firewall",
            })
            print_severity(
                Severity.HIGH if port in [2375, 6379, 27017, 11211, 445, 502] else Severity.MEDIUM,
                f"Port {port} ({name}) - {desc}"
            )

    return open_ports


def check_default_credentials(ip, open_ports, findings):
    """ตรวจสอบ Default Credentials"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}  ── [2/7] ตรวจสอบ Default Credentials ──{Colors.RESET}")

    checked = 0
    found = 0

    # HTTP/HTTPS Basic Auth
    http_ports = [p for p in open_ports if p in [80, 81, 82, 83, 84, 85, 443, 8000, 8001, 8008,
                                                 8080, 8081, 8088, 8443, 8554, 8888, 9000, 9090]]

    if http_ports:
        # ตรวจก่อนว่าเป็นอุปกรณ์อะไร
        device_type = "generic_camera"
        for port in http_ports[:2]:
            resp = http_request(ip, port, "/")
            if resp:
                body_lower = resp.get("body", "").lower()
                headers_str = str(resp.get("headers", {})).lower()

                if "hikvision" in body_lower or "hikvision" in headers_str or "webcolors_hik" in body_lower:
                    device_type = "hikvision"
                    break
                elif "dahua" in body_lower or "dahua" in headers_str or "dhwebclientlib" in body_lower:
                    device_type = "dahua"
                    break
                elif "axis" in body_lower or "axis" in headers_str:
                    device_type = "axis"
                    break
                elif "uniview" in body_lower or "uniview" in headers_str:
                    device_type = "uniview"
                    break

        print(f"  {Colors.DIM}  ตรวจพบอุปกรณ์ประเภท: {device_type}{Colors.RESET}")

        cred_lists_to_try = [device_type]
        if device_type != "generic_camera":
            cred_lists_to_try.append("generic_camera")
        cred_lists_to_try.append("web_admin")

        for cred_type in cred_lists_to_try:
            creds = DEFAULT_CREDS.get(cred_type, [])
            for port in http_ports[:3]:  # ลองไม่เกิน 3 ports
                for username, password in creds:
                    checked += 1
                    # HTTP Basic Auth
                    resp = http_request(ip, port, "/", auth=(username, password))
                    if resp and resp.get("status") in [200, 301, 302]:
                        # ตรวจว่าไม่ใช่หน้า login อีก
                        body = resp.get("body", "").lower()
                        if "login" not in body or "welcome" in body or "dashboard" in body or "config" in body:
                            found += 1
                            disp_pass = password if password else "(empty)"
                            findings.append({
                                "module": "Default Credentials",
                                "severity": Severity.CRITICAL,
                                "title": f"Default credentials ใช้งานได้ที่ port {port}",
                                "description": f"Username: {username} / Password: {disp_pass} (Type: {cred_type})",
                                "recommendation": "เปลี่ยนรหัสผ่านทันที! ใช้รหัสที่ซับซ้อน >=8 ตัวอักษร ผสมตัวใหญ่ เล็ก ตัวเลข สัญลักษณ์",
                            })
                            print_severity(Severity.CRITICAL,
                                           f"Port {port} - login สำเร็จ: {Colors.RED}{Colors.BOLD}{username}:{disp_pass}{Colors.RESET} ({cred_type})")
                            break  # ไม่ต้องลองอีก
                if found > 0:
                    break
            if found > 0:
                break

    # RTSP Default Credentials (port 554)
    if 554 in open_ports:
        print(f"  {Colors.DIM}  ตรวจ RTSP credentials...{Colors.RESET}")
        rtsp_creds = DEFAULT_CREDS.get("hikvision", []) + DEFAULT_CREDS.get("generic_camera", [])
        seen = set()
        for username, password in rtsp_creds:
            key = f"{username}:{password}"
            if key in seen:
                continue
            seen.add(key)
            checked += 1
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, 554))
                # DESCRIBE with auth
                cred_b64 = base64.b64encode(f"{username}:{password}".encode()).decode()
                req = (f"DESCRIBE rtsp://{ip}:554/ RTSP/1.0\r\n"
                       f"CSeq: 2\r\n"
                       f"Authorization: Basic {cred_b64}\r\n\r\n")
                sock.sendall(req.encode())
                resp = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()

                if "200 OK" in resp:
                    disp_pass = password if password else "(empty)"
                    found += 1
                    findings.append({
                        "module": "Default Credentials",
                        "severity": Severity.CRITICAL,
                        "title": "RTSP Default credentials ใช้งานได้ (port 554)",
                        "description": f"Username: {username} / Password: {disp_pass}",
                        "recommendation": "เปลี่ยนรหัส RTSP ทันที! สามารถดู live video ได้",
                    })
                    print_severity(Severity.CRITICAL,
                                   f"RTSP - login สำเร็จ: {Colors.RED}{Colors.BOLD}{username}:{disp_pass}{Colors.RESET}")
                    break
            except Exception:
                pass

    # SSH (port 22) - ลองแค่บางตัว
    if 22 in open_ports:
        print(f"  {Colors.DIM}  ตรวจ SSH credentials (limited)...{Colors.RESET}")
        ssh_creds = DEFAULT_CREDS.get("ssh", [])[:5]  # ลองแค่ 5 ตัวแรก
        for username, password in ssh_creds:
            checked += 1
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, 22))
                banner = sock.recv(256).decode('utf-8', errors='ignore')
                sock.close()
                # SSH ต้องใช้ library paramiko เพื่อ login จริงๆ
                # เราแค่ดึง banner แจ้งเตือน
                if banner:
                    findings.append({
                        "module": "Service Info",
                        "severity": Severity.INFO,
                        "title": f"SSH Banner ที่ port 22",
                        "description": f"Banner: {banner.strip()[:100]}",
                        "recommendation": "ตรวจสอบว่า SSH version เป็นปัจจุบัน ปิด root login ใช้ key-based auth",
                    })
                    print_severity(Severity.INFO, f"SSH Banner: {banner.strip()[:60]}")
                break
            except Exception:
                pass

    if found == 0 and checked > 0:
        print(f"  {Colors.GREEN}  ✓ ไม่พบ default credentials ที่ใช้งานได้ ({checked} ชุดที่ทดสอบ){Colors.RESET}")
    elif checked == 0:
        print(f"  {Colors.DIM}  ⊘ ไม่มี port ที่ต้องเช็ค{Colors.RESET}")


def check_http_security(ip, open_ports, findings):
    """ตรวจสอบ HTTP Security Headers"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}  ── [3/7] ตรวจสอบ HTTP Security ──{Colors.RESET}")

    http_ports = [p for p in open_ports if p in [80, 81, 443, 8000, 8080, 8081, 8443, 8888, 9000]]

    if not http_ports:
        print(f"  {Colors.DIM}  ⊘ ไม่มี HTTP port ที่เปิดอยู่{Colors.RESET}")
        return

    for port in http_ports[:2]:
        print(f"  {Colors.DIM}  ตรวจ port {port}...{Colors.RESET}")
        resp = http_request(ip, port, "/")
        if not resp:
            continue

        headers = resp.get("headers", {})
        body = resp.get("body", "")

        # ตรวจ Missing Security Headers
        missing_count = 0
        for header_name, info in SECURITY_HEADERS.items():
            header_found = False
            for h in headers:
                if h.lower() == header_name.lower():
                    header_found = True
                    break
            if not header_found:
                missing_count += 1
                if info["severity"] in [Severity.MEDIUM, Severity.HIGH]:
                    findings.append({
                        "module": "HTTP Security",
                        "severity": info["severity"],
                        "title": f"Missing Header: {header_name} (port {port})",
                        "description": info["description"],
                        "recommendation": info["fix"],
                    })
                    print_severity(info["severity"], f"Missing: {header_name} - {info['description']}")

        # ตรวจ Dangerous Headers (info disclosure)
        for header_name, info in DANGEROUS_HEADERS.items():
            for h, v in headers.items():
                if h.lower() == header_name.lower():
                    findings.append({
                        "module": "HTTP Security",
                        "severity": info["severity"],
                        "title": f"Information Disclosure: {header_name}: {v} (port {port})",
                        "description": info["description"],
                        "recommendation": info["fix"],
                    })
                    print_severity(info["severity"], f"Info Leak: {header_name}: {v}")

        # ตรวจ HTTP เปิดบน HTTPS port
        if port not in [443, 8443]:
            findings.append({
                "module": "HTTP Security",
                "severity": Severity.MEDIUM,
                "title": f"HTTP ไม่เข้ารหัสที่ port {port}",
                "description": "ข้อมูลรวมถึง credentials ถูกส่งแบบ plaintext",
                "recommendation": "เปิดใช้ HTTPS (TLS) และ redirect HTTP ไปยัง HTTPS",
            })

        # ตรวจ Directory Listing
        if "<title>Index of" in body or "Directory listing for" in body:
            findings.append({
                "module": "HTTP Security",
                "severity": Severity.MEDIUM,
                "title": f"Directory Listing เปิดอยู่ที่ port {port}",
                "description": "ผู้โจมตีสามารถดูรายการไฟล์ทั้งหมดในเว็บ",
                "recommendation": "ปิด Directory Listing ใน Web Server config",
            })
            print_severity(Severity.MEDIUM, "Directory Listing เปิดอยู่!")

        # ตรวจ Default/Error Pages ที่เปิดเผยข้อมูล
        error_patterns = [
            (r"Apache/[\d.]+", "Apache version disclosure"),
            (r"nginx/[\d.]+", "Nginx version disclosure"),
            (r"Microsoft-IIS/[\d.]+", "IIS version disclosure"),
            (r"PHP/[\d.]+", "PHP version disclosure"),
            (r"Tomcat/[\d.]+", "Tomcat version disclosure"),
        ]
        for pattern, desc in error_patterns:
            match = re.search(pattern, body + str(headers))
            if match:
                findings.append({
                    "module": "HTTP Security",
                    "severity": Severity.LOW,
                    "title": f"{desc}: {match.group()} (port {port})",
                    "description": "เปิดเผย version ทำให้ attacker ค้นหา exploit ได้ง่ายขึ้น",
                    "recommendation": "ซ่อน version information ใน server config",
                })
                print_severity(Severity.LOW, f"{desc}: {match.group()}")

        if missing_count == 0:
            print(f"  {Colors.GREEN}  ✓ Security headers ครบถ้วนที่ port {port}{Colors.RESET}")


def check_ssl_tls(ip, open_ports, findings):
    """ตรวจสอบ SSL/TLS"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}  ── [4/7] ตรวจสอบ SSL/TLS ──{Colors.RESET}")

    ssl_ports = [p for p in open_ports if p in [443, 8443, 993, 995, 465, 636, 3389]]

    if not ssl_ports:
        # ตรวจว่า HTTP ports ไม่มี HTTPS
        http_only = [p for p in open_ports if p in [80, 8080, 8000, 8888]]
        if http_only:
            findings.append({
                "module": "SSL/TLS",
                "severity": Severity.MEDIUM,
                "title": "ไม่มี HTTPS/TLS ที่เปิดอยู่",
                "description": "พบเฉพาะ HTTP (plaintext) ไม่มีการเข้ารหัส",
                "recommendation": "เปิดใช้ HTTPS (port 443) พร้อม TLS certificate",
            })
            print_severity(Severity.MEDIUM, "ไม่พบ HTTPS/TLS - ใช้แค่ HTTP plaintext")
        else:
            print(f"  {Colors.DIM}  ⊘ ไม่มี SSL/TLS port ที่เปิดอยู่{Colors.RESET}")
        return

    for port in ssl_ports[:2]:
        print(f"  {Colors.DIM}  ตรวจ SSL/TLS port {port}...{Colors.RESET}")
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=ip
            )
            conn.settimeout(5)
            conn.connect((ip, port))

            # ดึงข้อมูล
            cert = conn.getpeercert(binary_form=True)
            protocol_version = conn.version()
            cipher = conn.cipher()
            conn.close()

            # ตรวจ protocol version
            if protocol_version:
                weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]
                if protocol_version in weak_protocols:
                    findings.append({
                        "module": "SSL/TLS",
                        "severity": Severity.HIGH,
                        "title": f"Weak SSL/TLS Protocol: {protocol_version} (port {port})",
                        "description": f"{protocol_version} มีช่องโหว่ที่ทราบแล้ว (POODLE, BEAST, etc.)",
                        "recommendation": "ปิด SSLv2/v3/TLSv1.0/1.1 ใช้ TLSv1.2 หรือ TLSv1.3 เท่านั้น",
                    })
                    print_severity(Severity.HIGH, f"Weak protocol: {protocol_version}")
                else:
                    print_severity(Severity.INFO, f"Protocol: {protocol_version} ✓")

            # ตรวจ cipher
            if cipher:
                cipher_name = cipher[0]
                weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
                if any(wc in cipher_name.upper() for wc in weak_ciphers):
                    findings.append({
                        "module": "SSL/TLS",
                        "severity": Severity.HIGH,
                        "title": f"Weak Cipher: {cipher_name} (port {port})",
                        "description": "Cipher suite ที่ใช้มีช่องโหว่",
                        "recommendation": "ปิด weak ciphers ใช้ AES-GCM หรือ ChaCha20",
                    })
                    print_severity(Severity.HIGH, f"Weak cipher: {cipher_name}")
                else:
                    print_severity(Severity.INFO, f"Cipher: {cipher_name} ✓")

            # ตรวจ Self-Signed cert
            try:
                context2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context2.check_hostname = True
                context2.verify_mode = ssl.CERT_REQUIRED
                context2.load_default_certs()
                conn2 = context2.wrap_socket(
                    socket.socket(socket.AF_INET),
                    server_hostname=ip
                )
                conn2.settimeout(5)
                conn2.connect((ip, port))
                conn2.close()
            except ssl.SSLCertVerificationError:
                findings.append({
                    "module": "SSL/TLS",
                    "severity": Severity.LOW,
                    "title": f"Self-Signed/Invalid SSL Certificate (port {port})",
                    "description": "Certificate ไม่ได้ sign โดย trusted CA หรือ hostname ไม่ตรง",
                    "recommendation": "ใช้ certificate จาก trusted CA (เช่น Let's Encrypt)",
                })
                print_severity(Severity.LOW, "Self-signed / Invalid certificate")
            except Exception:
                pass

        except Exception as e:
            print(f"  {Colors.DIM}  ⚠ ไม่สามารถเชื่อมต่อ SSL/TLS port {port}: {str(e)[:60]}{Colors.RESET}")


def check_rtsp_vuln(ip, open_ports, findings):
    """ตรวจสอบ RTSP Vulnerabilities"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}  ── [5/7] ตรวจสอบ RTSP ──{Colors.RESET}")

    rtsp_ports = [p for p in open_ports if p in [554, 555, 8554, 8555]]

    if not rtsp_ports:
        print(f"  {Colors.DIM}  ⊘ ไม่มี RTSP port ที่เปิดอยู่{Colors.RESET}")
        return

    for port in rtsp_ports:
        print(f"  {Colors.DIM}  ตรวจ RTSP port {port}...{Colors.RESET}")

        # 1. ตรวจว่า RTSP ไม่ต้อง auth
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))

            # OPTIONS ไม่ต้อง auth ปกติ
            sock.sendall(f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
            resp = sock.recv(1024).decode('utf-8', errors='ignore')

            server_match = re.search(r'Server:\s*(.+)', resp, re.IGNORECASE)
            if server_match:
                server = server_match.group(1).strip()
                print_severity(Severity.INFO, f"RTSP Server: {server}")

            sock.close()

            # DESCRIBE โดยไม่มี auth
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(5)
            sock2.connect((ip, port))

            # ลอง common RTSP paths
            rtsp_paths = [
                "/",
                "/Streaming/Channels/101",      # Hikvision
                "/Streaming/Channels/1",         # Hikvision
                "/cam/realmonitor?channel=1&subtype=0",  # Dahua
                "/live/ch0",
                "/live/main",
                "/stream1",
                "/h264",
                "/video1",
                "/media/video1",
            ]

            for path in rtsp_paths:
                try:
                    sock_t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock_t.settimeout(3)
                    sock_t.connect((ip, port))
                    sock_t.sendall(
                        f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                        f"CSeq: 2\r\n\r\n".encode()
                    )
                    resp_t = sock_t.recv(1024).decode('utf-8', errors='ignore')
                    sock_t.close()

                    if "200 OK" in resp_t:
                        findings.append({
                            "module": "RTSP",
                            "severity": Severity.CRITICAL,
                            "title": f"RTSP ไม่มี Authentication ที่ port {port}",
                            "description": f"สามารถดู video stream ได้โดยไม่ต้อง login: rtsp://{ip}:{port}{path}",
                            "recommendation": "เปิดใช้ RTSP authentication ทันที!",
                        })
                        print_severity(Severity.CRITICAL,
                                       f"RTSP No Auth! ดู stream ได้: rtsp://{ip}:{port}{path}")
                        break
                    elif "401" in resp_t:
                        # ดี - ต้อง auth
                        pass
                except Exception:
                    pass

            sock2.close()

        except Exception as e:
            print(f"  {Colors.DIM}  ⚠ Error: {str(e)[:60]}{Colors.RESET}")


def check_known_cves(ip, open_ports, findings):
    """ตรวจสอบ Known CVEs"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}  ── [6/7] ตรวจสอบ Known CVEs ──{Colors.RESET}")

    http_ports = [p for p in open_ports if p in [80, 81, 443, 8000, 8080, 8443]]

    if not http_ports:
        print(f"  {Colors.DIM}  ⊘ ไม่มี HTTP port สำหรับตรวจ CVE{Colors.RESET}")
        return

    # ระบุ device type
    device_type = None
    for port in http_ports[:2]:
        resp = http_request(ip, port, "/")
        if resp:
            combined = resp.get("body", "").lower() + str(resp.get("headers", {})).lower()
            if "hikvision" in combined or "webcolors_hik" in combined or "doc/page/login" in combined:
                device_type = "hikvision"
                break
            elif "dahua" in combined or "dhwebclientlib" in combined:
                device_type = "dahua"
                break

    if device_type:
        print(f"  {Colors.DIM}  ตรวจพบ: {device_type.upper()}{Colors.RESET}")

    # ตรวจ CVE ตาม device type
    cve_lists = ["generic"]
    if device_type:
        cve_lists.insert(0, device_type)

    for cve_type in cve_lists:
        cves = KNOWN_CVES.get(cve_type, [])
        for cve in cves:
            if cve["check_type"] == "http_path":
                for port in http_ports[:2]:
                    try:
                        resp = http_request(ip, port, cve["path"], method=cve.get("method", "GET"))
                        if resp and resp.get("status") in [200]:
                            body = resp.get("body", "")
                            # ตรวจสอบว่า response มีเนื้อหาจริงๆ
                            if len(body) > 10 and "404" not in body.lower() and "not found" not in body.lower():
                                findings.append({
                                    "module": "Known CVE",
                                    "severity": cve["severity"],
                                    "title": f"{cve['cve']} - {cve['description']}",
                                    "description": f"Affected: {cve['affected']}. "
                                                   f"Path: {cve['path']} ส่งกลับ HTTP 200",
                                    "recommendation": f"อัพเดท firmware ทันที! ดูรายละเอียดที่ https://nvd.nist.gov/vuln/detail/{cve['cve']}",
                                })
                                print_severity(cve["severity"],
                                               f"{cve['cve']}: {cve['description']}")
                    except Exception:
                        pass

            elif cve["check_type"] == "banner_match":
                for port in http_ports[:2]:
                    banner = get_banner(ip, port)
                    if banner and re.search(cve["pattern"], banner, re.IGNORECASE):
                        findings.append({
                            "module": "Known CVE",
                            "severity": cve["severity"],
                            "title": f"{cve['cve']} - {cve['description']}",
                            "description": f"Affected: {cve['affected']}. "
                                           f"Pattern matched in banner",
                            "recommendation": f"อัพเดทซอฟต์แวร์! ดูรายละเอียดที่ https://nvd.nist.gov/vuln/detail/{cve['cve']}",
                        })
                        print_severity(cve["severity"],
                                       f"{cve['cve']}: {cve['description']}")

    if not any(f["module"] == "Known CVE" for f in findings):
        print(f"  {Colors.GREEN}  ✓ ไม่พบ Known CVE ที่ตรงกัน (ควรอัพเดท firmware เป็นประจำ){Colors.RESET}")


def check_common_misconfig(ip, open_ports, findings):
    """ตรวจสอบ Common Misconfigurations"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}  ── [7/7] ตรวจสอบ Misconfiguration ──{Colors.RESET}")

    http_ports = [p for p in open_ports if p in [80, 81, 443, 8000, 8080, 8081, 8443, 8888, 9000]]

    # 1. ตรวจ SNMP default community
    if 161 in open_ports:
        findings.append({
            "module": "Misconfiguration",
            "severity": Severity.HIGH,
            "title": "SNMP (port 161) เปิดอยู่",
            "description": "SNMP มักใช้ community string เป็น 'public' หรือ 'private' ซึ่งเข้าถึงข้อมูลอุปกรณ์ได้ทั้งหมด",
            "recommendation": "เปลี่ยน community string / ใช้ SNMPv3 ที่มี auth + encryption / ปิดถ้าไม่ใช้",
        })
        print_severity(Severity.HIGH, "SNMP เปิดอยู่ - ตรวจสอบ community string")

    # 2. ตรวจ Telnet
    if 23 in open_ports:
        findings.append({
            "module": "Misconfiguration",
            "severity": Severity.HIGH,
            "title": "Telnet (port 23) เปิดอยู่",
            "description": "Telnet ส่งข้อมูลและรหัสผ่านแบบ plaintext",
            "recommendation": "ปิด Telnet ใช้ SSH แทน",
        })
        print_severity(Severity.HIGH, "Telnet เปิดอยู่ - ข้อมูลส่งแบบ plaintext!")

    # 3. ตรวจ HTTP paths ที่อาจเข้าถึงได้
    sensitive_paths = [
        ("/admin", "Admin Panel"),
        ("/administrator", "Admin Panel"),
        ("/config", "Configuration"),
        ("/configuration", "Configuration"),
        ("/setup", "Setup Page"),
        ("/install", "Installation Page"),
        ("/phpinfo.php", "PHP Info (เปิดเผย config ทั้งหมด)"),
        ("/info.php", "PHP Info"),
        ("/server-status", "Apache Server Status"),
        ("/server-info", "Apache Server Info"),
        ("/.env", "Environment Variables (อาจมี credentials)"),
        ("/.git/config", "Git Repository Config"),
        ("/.git/HEAD", "Git Repository"),
        ("/wp-login.php", "WordPress Login"),
        ("/wp-admin", "WordPress Admin"),
        ("/phpmyadmin", "phpMyAdmin"),
        ("/pma", "phpMyAdmin"),
        ("/doc/page/login.asp", "Hikvision Login"),
        ("/cgi-bin/magicBox.cgi?action=getSystemInfo", "Dahua System Info"),
        ("/ISAPI/System/deviceInfo", "Hikvision Device Info (ISAPI)"),
        ("/onvif/device_service", "ONVIF Device Service"),
    ]

    if http_ports:
        port = http_ports[0]
        print(f"  {Colors.DIM}  ตรวจ sensitive paths บน port {port}...{Colors.RESET}")

        for path, desc in sensitive_paths:
            try:
                resp = http_request(ip, port, path)
                if resp and resp.get("status") in [200]:
                    body = resp.get("body", "")
                    # Filter false positives
                    if len(body) > 50 and "404" not in body.lower() and "not found" not in body.lower():
                        sev = Severity.HIGH if any(
                            kw in path for kw in [
                                ".env",
                                ".git",
                                "phpinfo",
                                "server-status",
                                "credentials"]) else Severity.MEDIUM
                        findings.append({
                            "module": "Misconfiguration",
                            "severity": sev,
                            "title": f"Accessible: {path} ({desc}) port {port}",
                            "description": f"{desc} สามารถเข้าถึงได้ อาจเปิดเผยข้อมูลสำคัญ",
                            "recommendation": f"จำกัดการเข้าถึง {path} หรือลบออก",
                        })
                        print_severity(sev, f"Accessible: {path} ({desc})")
            except Exception:
                pass

    # 4. ตรวจว่ามี port ที่ไม่ควรเปิดสู่ภายนอก
    internal_only_ports = {
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
        9200: "Elasticsearch",
        11211: "Memcached",
        5984: "CouchDB",
        9042: "Cassandra",
        2375: "Docker API",
        2376: "Docker API SSL",
        10250: "Kubelet",
        9090: "Prometheus",
        5601: "Kibana",
        8086: "InfluxDB",
        15672: "RabbitMQ Management",
    }

    for port in open_ports:
        if port in internal_only_ports:
            name = internal_only_ports[port]
            findings.append({
                "module": "Misconfiguration",
                "severity": Severity.HIGH,
                "title": f"{name} (port {port}) เปิดสู่ภายนอก",
                "description": f"{name} ไม่ควรเปิดสู่เครือข่ายภายนอก เสี่ยงถูกเข้าถึงข้อมูล",
                "recommendation": f"จำกัด {name} ให้เข้าถึงจาก localhost หรือ VPN เท่านั้น",
            })
            print_severity(Severity.HIGH, f"{name} (port {port}) เปิดสู่ภายนอก!")


# ═══════════════════════════════════════════════════════════════════
# ─── รายงานผลลัพธ์ ─────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════

def print_report(ip, findings, elapsed):
    """แสดงรายงานสรุป"""
    # นับ severity
    counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 0,
    }
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    total = len(findings)
    risk_score = (counts[Severity.CRITICAL] * 40 +
                  counts[Severity.HIGH] * 20 +
                  counts[Severity.MEDIUM] * 10 +
                  counts[Severity.LOW] * 5)

    if risk_score == 0:
        risk_level = f"{Colors.GREEN}{Colors.BOLD}LOW ✓{Colors.RESET}"
    elif risk_score < 50:
        risk_level = f"{Colors.YELLOW}{Colors.BOLD}MEDIUM ⚠{Colors.RESET}"
    elif risk_score < 100:
        risk_level = f"{Colors.RED}{Colors.BOLD}HIGH ⚠{Colors.RESET}"
    else:
        risk_level = f"{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} CRITICAL ☠ {Colors.RESET}"

    w = 75
    print(f"\n\n{'='*w}")
    print(f"{Colors.BOLD}{Colors.CYAN}  📋 VULNERABILITY SCAN REPORT{Colors.RESET}")
    print(f"{'='*w}")
    print(f"  Target     : {Colors.BOLD}{ip}{Colors.RESET}")
    print(f"  Scan Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Duration   : {elapsed:.1f} seconds")
    print(f"  Risk Level : {risk_level}")
    print(f"{'─'*w}")

    # Summary bar
    print(f"\n  {Colors.BOLD}สรุปช่องโหว่:{Colors.RESET}")
    print(f"  🔴 Critical: {Colors.RED}{Colors.BOLD}{counts[Severity.CRITICAL]}{Colors.RESET}"
          f"  🟠 High: {Colors.RED}{counts[Severity.HIGH]}{Colors.RESET}"
          f"  🟡 Medium: {Colors.YELLOW}{counts[Severity.MEDIUM]}{Colors.RESET}"
          f"  🔵 Low: {Colors.BLUE}{counts[Severity.LOW]}{Colors.RESET}"
          f"  ℹ️  Info: {Colors.CYAN}{counts[Severity.INFO]}{Colors.RESET}"
          f"  │ Total: {Colors.BOLD}{total}{Colors.RESET}")

    # Detailed findings
    if findings:
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

        for sev in severity_order:
            sev_findings = [f for f in findings if f["severity"] == sev]
            if not sev_findings:
                continue

            color = SEVERITY_COLORS[sev]
            emoji = SEVERITY_EMOJI[sev]
            print(f"\n{'─'*w}")
            print(f"  {emoji} {color}{sev}{Colors.RESET} ({len(sev_findings)})")
            print(f"{'─'*w}")

            for i, f in enumerate(sev_findings, 1):
                print(f"\n  {color}[{sev[0]}#{i}]{Colors.RESET} {Colors.BOLD}{f['title']}{Colors.RESET}")
                print(f"       Module : {f['module']}")
                print(f"       Detail : {f['description']}")
                print(f"       {Colors.GREEN}Fix    : {f['recommendation']}{Colors.RESET}")

    print(f"\n{'='*w}")

    # แนะนำสิ่งที่ควรทำ
    if counts[Severity.CRITICAL] > 0 or counts[Severity.HIGH] > 0:
        print(f"\n{Colors.RED}{Colors.BOLD}  ⚠️  พบช่องโหว่ร้ายแรง! แนะนำให้ดำเนินการทันที:{Colors.RESET}")
        print(f"  {Colors.YELLOW}1. อัพเดท firmware/software ให้เป็นเวอร์ชันล่าสุด{Colors.RESET}")
        print(f"  {Colors.YELLOW}2. เปลี่ยน default passwords ทันที{Colors.RESET}")
        print(f"  {Colors.YELLOW}3. ปิด port/service ที่ไม่จำเป็น{Colors.RESET}")
        print(f"  {Colors.YELLOW}4. จำกัดการเข้าถึงด้วย Firewall/ACL{Colors.RESET}")
        print(f"  {Colors.YELLOW}5. เปิดใช้ HTTPS/TLS สำหรับทุก service{Colors.RESET}")


def export_report(ip, findings, elapsed, filename):
    """Export รายงานเป็น JSON หรือ CSV"""
    if filename.endswith('.json'):
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        data = {
            "target": ip,
            "scan_time": datetime.now().isoformat(),
            "duration_seconds": round(elapsed, 1),
            "summary": counts,
            "total_findings": len(findings),
            "findings": findings,
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    else:
        if not filename.endswith('.csv'):
            filename += '.csv'
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("Target,Severity,Module,Title,Description,Recommendation\n")
            for finding in findings:
                desc = finding['description'].replace('"', '""')
                title = finding['title'].replace('"', '""')
                rec = finding['recommendation'].replace('"', '""')
                f.write(f'"{ip}","{finding["severity"]}","{finding["module"]}","{title}","{desc}","{rec}"\n')

    print(f"\n{Colors.GREEN}  ✅ รายงานบันทึกไปที่: {filename}{Colors.RESET}")


# ═══════════════════════════════════════════════════════════════════
# ─── Main ──────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════

def run_full_scan(ip):
    """รัน vulnerability scan ทั้งหมด"""
    findings = []
    start_time = time.time()

    print(f"\n{'='*65}")
    print(f"{Colors.BOLD}{Colors.CYAN}  🎯 Target: {Colors.GREEN}{ip}{Colors.RESET}")
    print(f"  {Colors.DIM}Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print(f"{'='*65}")

    # 1. Port Scan
    open_ports = check_open_ports(ip, findings)

    if not open_ports:
        print(f"\n{Colors.RED}  ❌ ไม่พบ port ที่เปิดอยู่ - host อาจ offline หรือมี firewall{Colors.RESET}")
        elapsed = time.time() - start_time
        print_report(ip, findings, elapsed)
        return findings

    # 2. Default Credentials
    check_default_credentials(ip, open_ports, findings)

    # 3. HTTP Security
    check_http_security(ip, open_ports, findings)

    # 4. SSL/TLS
    check_ssl_tls(ip, open_ports, findings)

    # 5. RTSP
    check_rtsp_vuln(ip, open_ports, findings)

    # 6. Known CVEs
    check_known_cves(ip, open_ports, findings)

    # 7. Misconfiguration
    check_common_misconfig(ip, open_ports, findings)

    elapsed = time.time() - start_time
    print_report(ip, findings, elapsed)

    return findings


def show_menu():
    """แสดงเมนูหลัก"""
    print(f"""
{Colors.BOLD}  🎯 เลือกโหมดการสแกน:{Colors.RESET}
  {Colors.CYAN}┌──────────────────────────────────────────────────────────────┐{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[1]{Colors.RESET} 🔍 Full Scan        ── ตรวจสอบทุกอย่าง                {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[2]{Colors.RESET} 📹 Camera Scan      ── เน้นกล้อง (Hikvision/Dahua)     {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[3]{Colors.RESET} 🔑 Credential Check ── ตรวจ Default Password            {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[4]{Colors.RESET} 🌐 Web Security     ── ตรวจ HTTP Headers/Config         {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[5]{Colors.RESET} 🔒 SSL/TLS Check    ── ตรวจ Certificate/Protocol        {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[0]{Colors.RESET} ❌ ออกจากโปรแกรม                                        {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}└──────────────────────────────────────────────────────────────┘{Colors.RESET}
""")


def interactive_mode():
    """โหมด Interactive"""
    clear_screen()
    print_banner()

    while True:
        show_menu()
        choice = input(f"  {Colors.BOLD}เลือก [{Colors.CYAN}0-5{Colors.RESET}{Colors.BOLD}]: {Colors.RESET}").strip()

        if choice == '0':
            print(f"\n{Colors.CYAN}  👋 ขอบคุณที่ใช้งาน Vuln Scanner!{Colors.RESET}\n")
            sys.exit(0)

        # รับ target
        print(f"\n{Colors.BOLD}  📡 ใส่ IP เป้าหมาย:{Colors.RESET}")
        ip = input(f"  {Colors.BOLD}Target IP: {Colors.RESET}").strip()
        if not ip:
            continue

        # Validate IP
        try:
            socket.inet_aton(ip)
        except socket.error:
            try:
                ip = socket.gethostbyname(ip)
                print(f"  {Colors.DIM}  Resolved to: {ip}{Colors.RESET}")
            except Exception:
                print(f"  {Colors.RED}  ❌ Invalid IP / Hostname{Colors.RESET}")
                continue

        findings = []
        start_time = time.time()

        if choice == '1':
            findings = run_full_scan(ip)
        elif choice == '2':
            # Camera focused scan
            print(f"\n{'='*65}")
            print(f"{Colors.BOLD}{Colors.CYAN}  📹 Camera Scan: {Colors.GREEN}{ip}{Colors.RESET}")
            print(f"{'='*65}")
            open_ports = check_open_ports(ip, findings)
            if open_ports:
                check_default_credentials(ip, open_ports, findings)
                check_rtsp_vuln(ip, open_ports, findings)
                check_known_cves(ip, open_ports, findings)
            elapsed = time.time() - start_time
            print_report(ip, findings, elapsed)
        elif choice == '3':
            print(f"\n{'='*65}")
            print(f"{Colors.BOLD}{Colors.CYAN}  🔑 Credential Check: {Colors.GREEN}{ip}{Colors.RESET}")
            print(f"{'='*65}")
            open_ports = check_open_ports(ip, findings)
            if open_ports:
                check_default_credentials(ip, open_ports, findings)
            elapsed = time.time() - start_time
            print_report(ip, findings, elapsed)
        elif choice == '4':
            print(f"\n{'='*65}")
            print(f"{Colors.BOLD}{Colors.CYAN}  🌐 Web Security: {Colors.GREEN}{ip}{Colors.RESET}")
            print(f"{'='*65}")
            open_ports = check_open_ports(ip, findings)
            if open_ports:
                check_http_security(ip, open_ports, findings)
                check_common_misconfig(ip, open_ports, findings)
            elapsed = time.time() - start_time
            print_report(ip, findings, elapsed)
        elif choice == '5':
            print(f"\n{'='*65}")
            print(f"{Colors.BOLD}{Colors.CYAN}  🔒 SSL/TLS Check: {Colors.GREEN}{ip}{Colors.RESET}")
            print(f"{'='*65}")
            open_ports = check_open_ports(ip, findings)
            if open_ports:
                check_ssl_tls(ip, open_ports, findings)
            elapsed = time.time() - start_time
            print_report(ip, findings, elapsed)
        else:
            print(f"  {Colors.RED}❌ ตัวเลือกไม่ถูกต้อง{Colors.RESET}")
            continue

        # Export
        if findings:
            export_choice = input(f"\n  {Colors.BOLD}ต้องการบันทึกรายงาน? [y/N]: {Colors.RESET}").strip().lower()
            if export_choice == 'y':
                filename = input(f"  {Colors.BOLD}ชื่อไฟล์ (default: vuln_report.json): {Colors.RESET}").strip()
                if not filename:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"vuln_report_{ip}_{timestamp}.json"
                elapsed = time.time() - start_time
                export_report(ip, findings, elapsed, filename)

        print()


def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Scanner - ตรวจสอบช่องโหว่พื้นฐาน",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 vuln_scanner.py                              # Interactive mode
  python3 vuln_scanner.py -t 192.168.1.1               # Full scan
  python3 vuln_scanner.py -t 192.168.1.1 -m camera     # Camera focused
  python3 vuln_scanner.py -t 192.168.1.1 -m cred       # Credential check
  python3 vuln_scanner.py -t 192.168.1.1 -o report.json

Scan Modes:
  all       Full vulnerability scan (default)
  camera    IP Camera focused (Hikvision, Dahua, RTSP)
  cred      Default credential check only
  web       Web security headers & misconfig
  ssl       SSL/TLS certificate & protocol check

⚠️  ใช้เพื่อตรวจสอบเครือข่ายของตนเองเท่านั้น
        """
    )
    parser.add_argument('-t', '--target', help='Target IP address')
    parser.add_argument('-m', '--mode', default='all',
                        choices=['all', 'camera', 'cred', 'web', 'ssl'],
                        help='Scan mode (default: all)')
    parser.add_argument('-o', '--output', help='Output file (JSON or CSV)')

    args = parser.parse_args()

    if args.target:
        # CLI mode
        print_banner()
        ip = args.target

        try:
            socket.inet_aton(ip)
        except socket.error:
            try:
                ip = socket.gethostbyname(ip)
            except Exception:
                print(f"  {Colors.RED}❌ Invalid target: {args.target}{Colors.RESET}")
                sys.exit(1)

        findings = []
        start_time = time.time()

        if args.mode == 'all':
            findings = run_full_scan(ip)
        elif args.mode == 'camera':
            open_ports = check_open_ports(ip, findings)
            if open_ports:
                check_default_credentials(ip, open_ports, findings)
                check_rtsp_vuln(ip, open_ports, findings)
                check_known_cves(ip, open_ports, findings)
            elapsed = time.time() - start_time
            print_report(ip, findings, elapsed)
        elif args.mode == 'cred':
            open_ports = check_open_ports(ip, findings)
            if open_ports:
                check_default_credentials(ip, open_ports, findings)
            elapsed = time.time() - start_time
            print_report(ip, findings, elapsed)
        elif args.mode == 'web':
            open_ports = check_open_ports(ip, findings)
            if open_ports:
                check_http_security(ip, open_ports, findings)
                check_common_misconfig(ip, open_ports, findings)
            elapsed = time.time() - start_time
            print_report(ip, findings, elapsed)
        elif args.mode == 'ssl':
            open_ports = check_open_ports(ip, findings)
            if open_ports:
                check_ssl_tls(ip, open_ports, findings)
            elapsed = time.time() - start_time
            print_report(ip, findings, elapsed)

        if args.output and findings:
            elapsed = time.time() - start_time
            export_report(ip, findings, elapsed, args.output)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
