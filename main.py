#!/usr/bin/env python3
"""
NE_Scan - Network Security Toolkit (Main Launcher)
═══════════════════════════════════════════════════
รวมเครื่องมือสแกนและตรวจสอบความปลอดภัยเครือข่ายทั้งหมดไว้ในที่เดียว

Tools ที่รวมอยู่:
1. Network Scanner    → สแกนหาอุปกรณ์ในเครือข่าย (IP, MAC, Vendor)
2. Port Scanner       → สแกน Port ที่เปิดอยู่ + Service Detection
3. Vuln Scanner       → ตรวจสอบช่องโหว่ (CVE, Default Creds, SNMP)
4. Network Device Audit → ตรวจสอบ Router/Switch/Firewall
5. Windows Audit      → ตรวจสอบ Security Settings บน Windows

Usage:
    python3 main.py
    python3 main.py -t 192.168.1.1             # Full scan target
    python3 main.py -t 192.168.1.0/24 -m net   # Network scan only
"""

import os
import sys
import argparse
import subprocess
import ipaddress
import json
import socket
import time
import concurrent.futures
import re
import platform
import base64
import ssl
import urllib.request
import urllib.error
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
    RESET = '\033[0m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    WHITE = '\033[97m'


# ── ตรวจสอบว่ามี script ครบหรือไม่ ───────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REQUIRED_SCRIPTS = {
    "network_scanner.py": "Network Scanner (ค้นหาอุปกรณ์ในเครือข่าย)",
    "port_scanner.py": "Port Scanner (ตรวจ Port ที่เปิดอยู่)",
    "vuln_scanner.py": "Vulnerability Scanner (ตรวจช่องโหว่)",
    "net_device_audit.py": "Network Device Audit (ตรวจ Router/Switch)",
    "windows_audit.py": "Windows Security Audit",
}


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ███╗   ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗         ║
║   ████╗  ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║         ║
║   ██╔██╗ ██║█████╗      ███████╗██║     ███████║██╔██╗ ██║         ║
║   ██║╚██╗██║██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║         ║
║   ██║ ╚████║███████╗    ███████║╚██████╗██║  ██║██║ ╚████║         ║
║   ╚═╝  ╚═══╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝         ║
║                                                                      ║
║           {Colors.YELLOW}Network Security Toolkit — All-in-One{Colors.CYAN}               ║
║           {Colors.DIM}Network · Port · Vulnerability · Audit{Colors.RESET}{Colors.CYAN}{Colors.BOLD}         ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)


def check_scripts():
    """ตรวจสอบว่ามี script ครบหรือไม่"""
    missing = []
    for script in REQUIRED_SCRIPTS:
        path = os.path.join(SCRIPT_DIR, script)
        if not os.path.exists(path):
            missing.append(script)
    return missing


def run_script(script_name, args_list=[]):
    """รัน script อื่นใน process แยก"""
    script_path = os.path.join(SCRIPT_DIR, script_name)
    cmd = [sys.executable, script_path] + args_list
    subprocess.run(cmd)


def run_sudo_script(script_name, args_list=[]):
    """รัน script ด้วย sudo บน Unix/Mac หรือรันตรงๆ บน Windows (พร้อมแนะนำ Administrator)"""
    script_path = os.path.join(SCRIPT_DIR, script_name)
    if platform.system().lower() == "windows":
        cmd = [sys.executable, script_path] + args_list
    else:
        cmd = ["sudo", sys.executable, script_path] + args_list
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass
    except FileNotFoundError as e:
        print(f"  {Colors.RED}❌ Error running script: {e}{Colors.RESET}")


def show_main_menu():
    """แสดงเมนูหลัก"""

    # ตรวจสอบ script ที่มีอยู่
    missing = check_scripts()

    print(f"\n{Colors.BOLD}  🧰 เลือกเครื่องมือที่ต้องการใช้งาน:{Colors.RESET}")
    print(f"  {Colors.CYAN}┌──────────────────────────────────────────────────────────────────┐{Colors.RESET}")

    tools = [
        ("1", "🌐 Network Scanner", "network_scanner.py", "ค้นหา IP/MAC/Vendor/OS ของอุปกรณ์ในเครือข่าย"),
        ("2", "🔍 Port Scanner", "port_scanner.py", "สแกน Port ที่เปิดอยู่ + UDP + Service Detection"),
        ("3", "🛡️  Vulnerability Scan", "vuln_scanner.py", "ตรวจช่องโหว่ CVE/SNMP/Default Creds"),
        ("4", "🌐 Network Device Audit", "net_device_audit.py", "ตรวจ Router/Switch/Firewall Security"),
        ("5", "🪟 Windows Audit", "windows_audit.py", "ตรวจ Windows Security Hardening"),
        ("6", "⚡ Quick Full Scan", None, "สแกน + ตรวจช่องโหว่ IP เดียวอัตโนมัติ"),
        ("7", "📊 Subnet Full Scan", None, "สแกนทุกอุปกรณ์ใน Subnet แล้วตรวจช่องโหว่"),
        ("8", "🔭 Continuous Monitor", "monitor.py", "เฝ้าระวังเครือข่าย Real-time แจ้งเตือนอุปกรณ์ใหม่"),
        ("9", "📊 HTML Report", "report_generator.py", "สร้าง HTML Report จากไฟล์ JSON ผลสแกน"),
        ("A", "📡 Broadcast Monitor", "bcast_simple.py", "ตรวจจับ Broadcast Storm/ARP Flood Real-time (sudo)"),
    ]

    for num, name, script, desc in tools:
        ok = "✓" if (script is None or os.path.exists(os.path.join(SCRIPT_DIR, script or ""))) else "✗"
        color = Colors.GREEN if ok == "✓" else Colors.RED
        print(
            f"  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[{num}]{Colors.RESET} {name:<25} {Colors.DIM}{desc}{Colors.RESET}")

    print(f"  {Colors.CYAN}│{Colors.RESET}")
    print(f"  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[0]{Colors.RESET} ❌ ออกจากโปรแกรม")
    print(f"  {Colors.CYAN}└──────────────────────────────────────────────────────────────────┘{Colors.RESET}")

    if missing:
        print(f"\n  {Colors.YELLOW}⚠️  Script ที่ยังไม่มี: {', '.join(missing)}{Colors.RESET}")


# ─── Quick Full Scan (ฟังก์ชันรวม Port + Vuln สำหรับ IP เดียว) ────

def quick_full_scan(ip):
    """รัน Port Scan → Vulnerability Scan แบบต่อเนื่อง"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}⚡ Quick Full Scan เป้าหมาย: {Colors.GREEN}{ip}{Colors.RESET}")
    print(f"{'═'*60}")
    print(f"  {Colors.BOLD}ขั้นตอนที่ 1/2: Port Scanner{Colors.RESET}")
    run_script("port_scanner.py", ["-t", ip, "-p", "common"])
    print(f"\n  {Colors.BOLD}ขั้นตอนที่ 2/2: Vulnerability Scanner{Colors.RESET}")
    run_script("vuln_scanner.py", ["-t", ip])


# ─── Subnet Full Scan (ทุกอุปกรณ์ใน Subnet) ─────────────────────

def ping_host(ip, timeout=1):
    """Ping เช็คว่าออนไลน์ไหม (พร้อม fallback ตรวจสอบ TCP port และ ARP)"""
    sys_platform = platform.system().lower()
    if sys_platform == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    elif sys_platform == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2)
        if result.returncode == 0:
            return True
    except Exception:
        pass

    # Fallback 1: TCP Port Probe สำหรับเครื่องที่บล็อก ICMP Ping
    for p in (80, 443, 554, 8000, 37777, 8080, 445, 22, 139):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                if s.connect_ex((ip, p)) == 0:
                    return True
        except Exception:
            pass

    # Fallback 2: ตรวจสอบ ARP table บน LAN
    mac = get_mac(ip)
    if mac != "N/A" and mac != "00:00:00:00:00:00":
        return True

    return False


def get_mac(ip):
    """ดึง MAC จาก ARP"""
    try:
        result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=3)
        match = re.search(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}", result.stdout)
        if match:
            parts = re.split(r'[:-]', match.group(0).upper())
            return ":".join(p.zfill(2) for p in parts)
    except Exception:
        pass
    return "N/A"


def is_port_open(ip, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        res = s.connect_ex((ip, port))
        s.close()
        return res == 0
    except Exception:
        return False


def get_service(port):
    """คืนชื่อ Service พื้นฐาน"""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        161: "SNMP", 443: "HTTPS", 445: "SMB", 554: "RTSP",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt",
        8080: "HTTP-Proxy", 8291: "Winbox", 8443: "HTTPS-Alt",
        8554: "RTSP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
        37777: "Dahua-NVR",
    }
    return services.get(port, "Unknown")


def subnet_full_scan(subnet_str):
    """สแกนอุปกรณ์ทุกตัวใน Subnet + Port + แสดงสรุป"""
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError:
        print(f"  {Colors.RED}❌ Invalid subnet: {subnet_str}{Colors.RESET}")
        return

    hosts = list(network.hosts())
    total = len(hosts)

    print(f"\n{Colors.CYAN}{Colors.BOLD}📊 Subnet Full Scan: {subnet_str} ({total} hosts){Colors.RESET}")
    print(f"{'═'*70}")

    # Common ports ที่สแกน
    SCAN_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 443, 445,
        554, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379,
        8000, 8080, 8291, 8443, 8554, 9200, 27017, 37777
    ]

    # ─── Phase 1: ค้นหา host ที่ออนไลน์ ─────────────────────────
    print(f"\n  {Colors.BOLD}Phase 1/2: ค้นหา Host ที่ออนไลน์...{Colors.RESET}\n")
    online_hosts = []
    scanned = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {executor.submit(ping_host, str(ip)): str(ip) for ip in hosts}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            scanned += 1
            if future.result():
                online_hosts.append(ip)
                print(f"  {Colors.GREEN}✓{Colors.RESET} Online: {Colors.GREEN}{ip}{Colors.RESET}")
            if scanned % max(1, total // 10) == 0:
                print(f"  {Colors.DIM}  [{scanned}/{total}] ({scanned*100//total}%) scanning...{Colors.RESET}")

    print(f"\n  {Colors.GREEN}พบ {len(online_hosts)} hosts ออนไลน์{Colors.RESET}")

    if not online_hosts:
        print(f"  {Colors.YELLOW}ไม่พบอุปกรณ์ออนไลน์{Colors.RESET}")
        return

    # ─── Phase 2: สแกน Port + รวบรวมข้อมูล ──────────────────────
    print(f"\n  {Colors.BOLD}Phase 2/2: สแกน Port อุปกรณ์ที่ออนไลน์...{Colors.RESET}\n")

    all_results = []
    for ip in sorted(online_hosts, key=lambda x: [int(p) for p in x.split('.')]):
        mac = get_mac(ip)
        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(is_port_open, ip, port): port for port in SCAN_PORTS}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                if future.result():
                    open_ports.append(port)

        open_ports.sort()
        port_display = ", ".join([f"{p}({get_service(p)})" for p in open_ports]) or "-"

        result = {"ip": ip, "mac": mac, "open_ports": open_ports}
        all_results.append(result)

        print(f"  {Colors.GREEN}{ip:<18}{Colors.RESET} {Colors.YELLOW}{mac:<18}{Colors.RESET}")
        if open_ports:
            print(f"    {Colors.CYAN}Ports:{Colors.RESET} {port_display}")
        print()

    # ─── Export ──────────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"subnet_scan_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump({
            "subnet": subnet_str,
            "scan_time": datetime.now().isoformat(),
            "total_hosts": total,
            "online_hosts": len(online_hosts),
            "results": all_results
        }, f, indent=2, ensure_ascii=False)

    print(f"\n{'─'*70}")
    print(f"  {Colors.GREEN}✅ สแกนเสร็จสิ้น | Online: {len(online_hosts)}/{total} hosts | บันทึกที่: {filename}{Colors.RESET}")

    # แจ้งเตือน port อันตรายที่พบ
    dangerous = {23: "Telnet", 21: "FTP", 445: "SMB", 3389: "RDP",
                 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
                 161: "SNMP", 5900: "VNC"}

    warnings = []
    for r in all_results:
        for p in r["open_ports"]:
            if p in dangerous:
                warnings.append(f"{r['ip']}:{p} ({dangerous[p]})")

    if warnings:
        print(f"\n  {Colors.RED}{Colors.BOLD}⚠️  Port อันตรายที่พบ:{Colors.RESET}")
        for w in warnings:
            print(f"    {Colors.RED}• {w}{Colors.RESET}")


# ─── Interactive Menu ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NE_Scan - Network Security Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py                             # Interactive menu
  python3 main.py -t 192.168.1.1             # Quick full scan (Port+Vuln)
  python3 main.py -t 192.168.1.0/24 -m net   # Subnet scan
  python3 main.py -t 192.168.1.1 -m port     # Port scan only
  python3 main.py -t 192.168.1.1 -m vuln     # Vulnerability scan only
  python3 main.py -t 192.168.1.1 -m net-dev  # Network device audit

Modes (-m):
  net       Network scan (find devices)
  port      Port scan
  vuln      Vulnerability scan
  net-dev   Network device audit
  win       Windows security audit
  full      Port + Vuln scan (default)
        """
    )
    parser.add_argument('-t', '--target', help='Target IP หรือ Subnet (เช่น 192.168.1.1 หรือ 192.168.1.0/24)')
    parser.add_argument('-m', '--mode', default='full',
                        choices=['net', 'port', 'vuln', 'net-dev', 'win', 'full'],
                        help='โหมดการสแกน (default: full)')

    if platform.system().lower() == "windows":
        os.system("")  # Enable ANSI color codes on Windows CMD/PowerShell

    clear_screen()
    print_banner()

    if args.target:
        # ─── CLI Mode ─────────────────────────────────────────────
        target = args.target
        mode = args.mode

        if mode == 'net':
            if '/' in target:
                subnet_full_scan(target)
            else:
                run_script("network_scanner.py")
        elif mode == 'port':
            run_script("port_scanner.py", ["-t", target])
        elif mode == 'vuln':
            run_script("vuln_scanner.py", ["-t", target])
        elif mode == 'net-dev':
            run_script("net_device_audit.py", ["-t", target])
        elif mode == 'win':
            run_script("windows_audit.py")
        elif mode == 'full':
            if '/' in target:
                subnet_full_scan(target)
            else:
                quick_full_scan(target)
        return

    # ─── Interactive Mode ──────────────────────────────────────────
    while True:
        show_main_menu()
        choice = input(
            f"\n  {Colors.BOLD}เลือก [{Colors.CYAN}0-9 / A{Colors.RESET}{Colors.BOLD}]: {Colors.RESET}").strip().upper()

        if choice == '0':
            print(f"\n{Colors.CYAN}  👋 ขอบคุณที่ใช้งาน NE_Scan!{Colors.RESET}\n")
            break

        elif choice == '1':
            run_script("network_scanner.py")

        elif choice == '2':
            ip = input(f"  {Colors.BOLD}Target IP: {Colors.RESET}").strip()
            if ip:
                run_script("port_scanner.py", ["-t", ip])

        elif choice == '3':
            ip = input(f"  {Colors.BOLD}Target IP: {Colors.RESET}").strip()
            if ip:
                run_script("vuln_scanner.py", ["-t", ip])

        elif choice == '4':
            ip = input(f"  {Colors.BOLD}Target IP (Router/Switch): {Colors.RESET}").strip()
            if ip:
                run_script("net_device_audit.py", ["-t", ip])

        elif choice == '5':
            run_script("windows_audit.py")

        elif choice == '6':
            ip = input(f"  {Colors.BOLD}Target IP: {Colors.RESET}").strip()
            if ip:
                quick_full_scan(ip)

        elif choice == '7':
            print(f"\n  {Colors.BOLD}ใส่ Subnet ที่ต้องการสแกน:{Colors.RESET}")
            print(f"  {Colors.DIM}รูปแบบ: 192.168.1.0/24 หรือ 10.0.0.0/16{Colors.RESET}")
            subnet = input(f"  {Colors.BOLD}Subnet: {Colors.RESET}").strip()
            if subnet:
                subnet_full_scan(subnet)

        elif choice == '8':
            run_script("monitor.py")

        elif choice == '9':
            run_script("report_generator.py")

        elif choice == 'A':
            print(f"\n  {Colors.CYAN}📡 เปิด Broadcast Monitor (ต้องการ sudo)...{Colors.RESET}")
            run_sudo_script("bcast_simple.py")

        else:
            print(f"  {Colors.RED}❌ ตัวเลือกไม่ถูกต้อง{Colors.RESET}")

        input(f"\n  {Colors.DIM}กด Enter เพื่อกลับเมนูหลัก...{Colors.RESET}")
        clear_screen()
        print_banner()


if __name__ == "__main__":
    main()
