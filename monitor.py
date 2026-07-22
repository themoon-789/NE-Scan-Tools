#!/usr/bin/env python3
"""
Network Continuous Monitor
===========================
เฝ้าระวังเครือข่ายแบบ Real-time — แจ้งเตือนเมื่อมีอุปกรณ์ใหม่เชื่อมต่อ
หรืออุปกรณ์ที่รู้จักหายไปจากเครือข่าย

Usage:
    python3 monitor.py
    python3 monitor.py -n 192.168.1.0/24
    python3 monitor.py -n 192.168.1.0/24 -i 30
"""

import socket
import sys
import os
import re
import json
import time
import platform
import argparse
import subprocess
import concurrent.futures
from datetime import datetime

class Colors:
    CYAN    = '\033[96m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    RED     = '\033[91m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'
    MAGENTA = '\033[35m'
    BG_GREEN = '\033[42m'
    BG_RED   = '\033[41m'
    WHITE    = '\033[97m'


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     🔭 NE Scan — Network Continuous Monitor                      ║
║     เฝ้าระวังเครือข่ายแบบ Real-time                             ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}""")


def ping_host(ip, timeout=1):
    """Ping เช็คว่าออนไลน์"""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2)
        return result.returncode == 0
    except Exception:
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


def get_hostname(ip):
    """Reverse DNS"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def detect_os_ttl(ip):
    """ระบุ OS จาก TTL"""
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        elif system == "darwin":
            cmd = ["ping", "-c", "1", "-W", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        output = result.stdout.decode('utf-8', errors='ignore')
        match = re.search(r'ttl[=\s](\d+)', output, re.IGNORECASE)
        if match:
            ttl = int(match.group(1))
            if ttl <= 64:   return "Linux/Unix"
            elif ttl <= 128: return "Windows"
            elif ttl <= 255: return "Network Device"
    except Exception:
        pass
    return "Unknown"


def scan_network(subnet_str, max_workers=150):
    """สแกนทั้ง Subnet คืน dict ของ IP → info"""
    import ipaddress
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
    except ValueError:
        print(f"  {Colors.RED}❌ Invalid subnet: {subnet_str}{Colors.RESET}")
        return {}

    online = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            if future.result():
                mac = get_mac(ip)
                online[ip] = {
                    "mac": mac,
                    "hostname": get_hostname(ip),
                    "os": detect_os_ttl(ip),
                    "first_seen": datetime.now().isoformat(),
                    "last_seen": datetime.now().isoformat(),
                }
    return online


def save_baseline(baseline, filename="monitor_baseline.json"):
    """บันทึก baseline"""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(baseline, f, indent=2, ensure_ascii=False)


def load_baseline(filename="monitor_baseline.json"):
    """โหลด baseline"""
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def print_device_info(ip, info, label="", color=Colors.GREEN):
    """แสดงข้อมูลอุปกรณ์ 1 บรรทัด"""
    os_info = info.get('os', 'Unknown')
    mac = info.get('mac', 'N/A')
    hostname = info.get('hostname', 'N/A')[:30]
    ts = info.get('last_seen', info.get('first_seen', '-'))[:19]
    print(f"  {color}{label:<12}{Colors.RESET} "
          f"{Colors.GREEN}{ip:<18}{Colors.RESET} "
          f"{Colors.YELLOW}{mac:<18}{Colors.RESET} "
          f"{Colors.CYAN}{os_info:<15}{Colors.RESET} "
          f"{Colors.DIM}{hostname:<30}{Colors.RESET} "
          f"{Colors.DIM}{ts}{Colors.RESET}")


def run_monitor(subnet, interval=60, baseline_file="monitor_baseline.json"):
    """เริ่มการเฝ้าระวังแบบ Real-time"""
    print(f"\n  {Colors.BOLD}🎯 Monitoring Subnet: {Colors.CYAN}{subnet}{Colors.RESET}")
    print(f"  {Colors.BOLD}⏱️  Scan Interval: {Colors.CYAN}{interval}s{Colors.RESET}")
    print(f"  {Colors.DIM}กด Ctrl+C เพื่อหยุด{Colors.RESET}\n")

    # โหลด baseline หรือสร้างใหม่
    baseline = load_baseline(baseline_file)
    if not baseline:
        print(f"  {Colors.YELLOW}📋 ไม่พบ baseline — สแกนครั้งแรกเพื่อสร้าง baseline...{Colors.RESET}")
        print(f"  {Colors.DIM}  กรุณารอสักครู่...{Colors.RESET}\n")
        baseline = scan_network(subnet)
        save_baseline(baseline, baseline_file)
        print(f"\n  {Colors.GREEN}✅ Baseline สร้างเสร็จ — พบ {len(baseline)} อุปกรณ์{Colors.RESET}")

        print(f"\n  {Colors.BOLD}{'Event':<12} {'IP':<18} {'MAC':<18} {'OS':<15} {'Hostname':<30} {'Time'}{Colors.RESET}")
        print(f"  {'─'*110}")
        for ip, info in sorted(baseline.items()):
            print_device_info(ip, info, "BASELINE", Colors.DIM)
    else:
        print(f"  {Colors.GREEN}✅ โหลด Baseline — {len(baseline)} อุปกรณ์{Colors.RESET}")

    scan_count = 0
    event_log = []

    try:
        while True:
            scan_count += 1
            ts_now = datetime.now().strftime('%H:%M:%S')
            print(f"\n  {Colors.DIM}{'─'*55}{Colors.RESET}")
            print(f"  {Colors.CYAN}🔍 Scan #{scan_count} @ {ts_now}{Colors.RESET}")
            print(f"  {Colors.DIM}กำลังสแกน {subnet}...{Colors.RESET}")

            current = scan_network(subnet)

            # หาอุปกรณ์ใหม่
            new_devices = {ip: info for ip, info in current.items() if ip not in baseline}
            # หาอุปกรณ์ที่หายไป
            gone_devices = {ip: info for ip, info in baseline.items() if ip not in current}
            # อุปกรณ์ที่ยังอยู่
            still_online = {ip for ip in current if ip in baseline}

            print(f"  {Colors.GREEN}Online: {len(current)}{Colors.RESET}  "
                  f"{Colors.GREEN}Known: {len(still_online)}{Colors.RESET}  "
                  f"{Colors.RED}{'New: '+str(len(new_devices)) if new_devices else ''}{Colors.RESET}  "
                  f"{Colors.YELLOW}{'Gone: '+str(len(gone_devices)) if gone_devices else ''}{Colors.RESET}")

            if new_devices:
                print(f"\n  {Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} 🚨 พบอุปกรณ์ใหม่! {Colors.RESET}")
                print(f"  {Colors.BOLD}{'Event':<12} {'IP':<18} {'MAC':<18} {'OS':<15} {'Hostname':<30} {'Time'}{Colors.RESET}")
                print(f"  {'─'*110}")
                for ip, info in sorted(new_devices.items()):
                    info['last_seen'] = datetime.now().isoformat()
                    info['first_seen'] = datetime.now().isoformat()
                    print_device_info(ip, info, "🔴 NEW", Colors.RED)
                    event_log.append({"event": "NEW_DEVICE", "ip": ip, "info": info, "time": datetime.now().isoformat()})
                    baseline[ip] = info
                save_baseline(baseline, baseline_file)

            if gone_devices:
                print(f"\n  {Colors.YELLOW}⚠️  อุปกรณ์ที่หายไป:{Colors.RESET}")
                print(f"  {Colors.BOLD}{'Event':<12} {'IP':<18} {'MAC':<18} {'OS':<15} {'Hostname':<30} {'Time'}{Colors.RESET}")
                print(f"  {'─'*110}")
                for ip, info in sorted(gone_devices.items()):
                    print_device_info(ip, info, "🟡 GONE", Colors.YELLOW)
                    event_log.append({"event": "DEVICE_GONE", "ip": ip, "info": info, "time": datetime.now().isoformat()})

            if not new_devices and not gone_devices:
                print(f"  {Colors.GREEN}  ✓ ไม่มีการเปลี่ยนแปลง — เครือข่ายปกติ{Colors.RESET}")

            # อัปเดต last_seen ของอุปกรณ์ที่ยังออนไลน์
            for ip in still_online:
                baseline[ip]['last_seen'] = datetime.now().isoformat()
            save_baseline(baseline, baseline_file)

            # รอ interval ถัดไป
            print(f"\n  {Colors.DIM}รอ {interval}s ก่อนสแกนครั้งถัดไป... (Ctrl+C เพื่อหยุด){Colors.RESET}")
            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n\n  {Colors.CYAN}👋 หยุดการเฝ้าระวัง{Colors.RESET}")

        # สรุป events
        if event_log:
            print(f"\n  {Colors.BOLD}📋 สรุป Events ที่พบ ({len(event_log)} รายการ):{Colors.RESET}")
            for evt in event_log:
                evt_color = Colors.RED if evt['event'] == 'NEW_DEVICE' else Colors.YELLOW
                label = "NEW" if evt['event'] == 'NEW_DEVICE' else "GONE"
                ip = evt['ip']
                ts = evt['time'][:19]
                print(f"  {evt_color}[{label}]{Colors.RESET} {Colors.GREEN}{ip}{Colors.RESET} — {Colors.DIM}{ts}{Colors.RESET}")

            # Export
            export_choice = input(f"\n  {Colors.BOLD}บันทึก Event Log? [y/N]: {Colors.RESET}").strip().lower()
            if export_choice == 'y':
                ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"monitor_events_{ts_str}.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(event_log, f, indent=2, ensure_ascii=False)
                print(f"  {Colors.GREEN}✅ บันทึก: {filename}{Colors.RESET}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Network Continuous Monitor")
    parser.add_argument('-n', '--network', help='Subnet (เช่น 192.168.1.0/24)')
    parser.add_argument('-i', '--interval', type=int, default=60, help='ช่วงเวลาสแกน (วินาที, default=60)')
    args = parser.parse_args()

    clear_screen()
    print_banner()

    if args.network:
        subnet = args.network
    else:
        # Auto detect subnet
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            parts = local_ip.split('.')
            default_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            default_subnet = "192.168.1.0/24"

        print(f"\n  {Colors.BOLD}📡 ใส่ Subnet ที่ต้องการเฝ้าระวัง:{Colors.RESET}")
        print(f"  {Colors.DIM}  เครื่องนี้: {local_ip if 'local_ip' in dir() else '-'} → Subnet: {default_subnet}{Colors.RESET}")
        subnet = input(f"  {Colors.BOLD}Subnet [{default_subnet}]: {Colors.RESET}").strip()
        if not subnet:
            subnet = default_subnet

    run_monitor(subnet, interval=args.interval)


if __name__ == "__main__":
    main()
