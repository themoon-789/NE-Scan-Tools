#!/usr/bin/env python3
"""
Broadcast Traffic Analyzer & Storm Detector
=============================================
ตรวจจับและวิเคราะห์ Broadcast/Multicast Traffic บนเครือข่าย
ช่วยหา:
  - Broadcast Storm (อุปกรณ์ส่ง broadcast เยอะผิดปกติ)
  - ARP Flooding (อาจเป็น ARP Spoofing หรืออุปกรณ์เสีย)
  - Top Broadcast Talkers (ใครส่ง broadcast เยอะที่สุด)
  - Protocol Distribution (ARP, DHCP, SSDP, mDNS ฯลฯ)

ต้องการ: sudo / Administrator
          tcpdump (macOS/Linux) หรือ Npcap (Windows)

Usage:
    sudo python3 broadcast_monitor.py
    sudo python3 broadcast_monitor.py -i en0 -t 120 --threshold 100
"""

import os
import sys
import re
import time
import signal
import argparse
import platform
import subprocess
import threading
import collections
from datetime import datetime

# ─── สี Terminal ────────────────────────────────────────────────────
class Colors:
    CYAN    = '\033[96m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    RED     = '\033[91m'
    MAGENTA = '\033[35m'
    BLUE    = '\033[94m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'
    BG_RED  = '\033[41m'
    BG_YEL  = '\033[43m'
    WHITE   = '\033[97m'

# ─── ค่า Default ─────────────────────────────────────────────────────
DEFAULT_INTERFACE   = "en0"       # macOS default (ใช้ eth0 บน Linux)
ALERT_THRESHOLD     = 50          # pps (packets per second) ต่อ source
STORM_THRESHOLD     = 200         # pps ทั้งหมด — เข้าสู่สถานะ Storm
UPDATE_INTERVAL     = 3.0         # วินาที — refresh dashboard
CAPTURE_DURATION    = 0           # 0 = ไม่มีกำหนด (Ctrl+C เพื่อหยุด)

# ─── Protocol Patterns ───────────────────────────────────────────────
PROTOCOL_PATTERNS = {
    "ARP":        re.compile(r'\barp\b', re.IGNORECASE),
    "DHCP":       re.compile(r'\bbootp|dhcp\b', re.IGNORECASE),
    "mDNS":       re.compile(r'\bmdns\b|5353', re.IGNORECASE),
    "SSDP/UPnP":  re.compile(r'\bssdp\b|239\.255\.255\.250', re.IGNORECASE),
    "NetBIOS":    re.compile(r'\bnetbios\b|137|138', re.IGNORECASE),
    "LLMNR":      re.compile(r'\bllmnr\b|5355', re.IGNORECASE),
    "IGMP":       re.compile(r'\bigmp\b', re.IGNORECASE),
    "OSPF":       re.compile(r'\bospf\b|224\.0\.0\.5|224\.0\.0\.6', re.IGNORECASE),
    "HSRP":       re.compile(r'\bhsrp\b|224\.0\.0\.2', re.IGNORECASE),
    "CDP/LLDP":   re.compile(r'\bcdp\b|\bldp\b|\bllpd\b', re.IGNORECASE),
    "STP":        re.compile(r'\bstp\b|\brstp\b', re.IGNORECASE),
}

# ─── ข้อมูลสถิติ ──────────────────────────────────────────────────────
class BroadcastStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.total_packets    = 0
            self.broadcast_pkts   = 0
            self.multicast_pkts   = 0
            self.source_counts    = collections.Counter()   # IP → จำนวน packets
            self.protocol_counts  = collections.Counter()   # Protocol → จำนวน
            self.source_pps       = collections.Counter()   # IP → pps (per window)
            self.alerts           = []                       # รายการแจ้งเตือน
            self.start_time       = time.time()
            self.window_start     = time.time()
            self.window_packets   = 0
            self.window_src       = collections.Counter()
            self.storm_active     = False
            self.storm_start      = None
            self.storm_peak_pps   = 0

    def add_packet(self, src_ip, pkt_type, protocol, raw_line):
        with self.lock:
            self.total_packets   += 1
            self.window_packets  += 1
            if src_ip:
                self.source_counts[src_ip] += 1
                self.window_src[src_ip]    += 1
            if pkt_type == "broadcast":
                self.broadcast_pkts += 1
            elif pkt_type == "multicast":
                self.multicast_pkts += 1
            if protocol:
                self.protocol_counts[protocol] += 1

    def compute_window(self):
        """คำนวณ pps ของ window ปัจจุบัน"""
        with self.lock:
            now = time.time()
            elapsed = now - self.window_start
            if elapsed <= 0:
                return 0

            total_pps = self.window_packets / elapsed

            # อัปเดต pps ต่อ source
            self.source_pps.clear()
            for src, cnt in self.window_src.items():
                self.source_pps[src] = cnt / elapsed

            # เช็ค Storm
            if total_pps >= STORM_THRESHOLD:
                if not self.storm_active:
                    self.storm_active = True
                    self.storm_start  = datetime.now()
                self.storm_peak_pps = max(self.storm_peak_pps, total_pps)
            else:
                if self.storm_active:
                    self.alerts.append({
                        "type": "STORM_END",
                        "time": datetime.now().isoformat(),
                        "peak_pps": self.storm_peak_pps,
                    })
                self.storm_active = False

            # เช็ค per-source threshold
            for src, pps in self.source_pps.items():
                if pps >= ALERT_THRESHOLD:
                    self.alerts.append({
                        "type": "HIGH_BROADCAST",
                        "src": src,
                        "pps": round(pps, 1),
                        "time": datetime.now().isoformat(),
                    })

            # reset window
            self.window_start   = now
            self.window_packets = 0
            self.window_src.clear()

            return total_pps

    def snapshot(self):
        with self.lock:
            return {
                "total":       self.total_packets,
                "broadcast":   self.broadcast_pkts,
                "multicast":   self.multicast_pkts,
                "sources":     dict(self.source_counts.most_common(20)),
                "source_pps":  dict(self.source_pps.most_common(10)),
                "protocols":   dict(self.protocol_counts.most_common(10)),
                "alerts":      list(self.alerts[-20:]),
                "storm":       self.storm_active,
                "elapsed":     time.time() - self.start_time,
                "storm_peak":  self.storm_peak_pps,
            }


stats = BroadcastStats()
stop_event = threading.Event()


# ─── Parser ──────────────────────────────────────────────────────────

def parse_tcpdump_line(line):
    """แยก src_ip, pkt_type, protocol จาก tcpdump output"""
    line = line.strip()
    if not line or line.startswith('tcpdump') or line.startswith('listening'):
        return None, None, None

    src_ip   = None
    pkt_type = None
    protocol = None

    # ดึง source IP
    # tcpdump format: "HH:MM:SS.us IP src > dst: ..."
    ip_match = re.search(r'IP\s+(\d{1,3}(?:\.\d{1,3}){3})', line)
    if ip_match:
        src_ip = ip_match.group(1)

    # ระบุ broadcast vs multicast
    if re.search(r'ff:ff:ff:ff:ff:ff|broadcast|\.255\s|\.255:', line, re.IGNORECASE):
        pkt_type = "broadcast"
    elif re.search(r'224\.\d+\.\d+\.\d+|239\.\d+\.\d+\.\d+|multicast|01:00:5e', line, re.IGNORECASE):
        pkt_type = "multicast"
    else:
        pkt_type = "broadcast"  # ถูกกรองมาแล้วโดย tcpdump filter

    # ระบุ protocol
    for proto, pattern in PROTOCOL_PATTERNS.items():
        if pattern.search(line):
            protocol = proto
            break
    if not protocol:
        if 'UDP' in line or 'udp' in line:
            protocol = "UDP-Other"
        elif 'TCP' in line or 'tcp' in line:
            protocol = "TCP-Other"
        else:
            protocol = "Other"

    return src_ip, pkt_type, protocol


# ─── Capture Thread ──────────────────────────────────────────────────

def capture_thread(interface, duration=0):
    """รัน tcpdump แล้ว parse output"""
    # tcpdump filter: broadcast และ multicast เท่านั้น
    bcast_filter = (
        "broadcast or multicast or "
        "arp or "
        "(udp and (port 5353 or port 5355 or port 137 or port 138 or "
        "port 67 or port 68 or port 1900 or port 631))"
    )

    cmd = [
        "tcpdump",
        "-i", interface,
        "-n",           # ไม่ resolve hostname (เร็วกว่า)
        "-l",           # line-buffered
        "-q",           # brief output
        "--immediate-mode",
        bcast_filter,
    ]

    if duration > 0:
        cmd += ["-G", str(duration), "-W", "1"]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        while not stop_event.is_set():
            line = proc.stdout.readline()
            if not line:
                break
            src_ip, pkt_type, protocol = parse_tcpdump_line(line)
            if pkt_type:
                stats.add_packet(src_ip, pkt_type, protocol, line)

        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()

    except FileNotFoundError:
        print(f"\n{Colors.RED}  ❌ ไม่พบ tcpdump กรุณาติดตั้ง:{Colors.RESET}")
        print(f"  macOS : brew install tcpdump")
        print(f"  Linux : sudo apt install tcpdump")
        stop_event.set()
    except PermissionError:
        print(f"\n{Colors.RED}  ❌ ต้องรันด้วย sudo{Colors.RESET}")
        stop_event.set()
    except Exception as e:
        print(f"\n{Colors.RED}  ❌ Error: {e}{Colors.RESET}")
        stop_event.set()


# ─── Dashboard ───────────────────────────────────────────────────────

def format_bar(value, max_val, width=20, color=Colors.CYAN):
    if max_val <= 0:
        max_val = 1
    filled = int((value / max_val) * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"{color}{bar}{Colors.RESET}"


def print_dashboard(snap, total_pps, interface):
    """แสดง Dashboard แบบ Real-time"""
    os.system('cls' if os.name == 'nt' else 'clear')

    elapsed = snap['elapsed']
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)
    storm = snap['storm']

    # Header
    storm_indicator = (
        f"{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} ⚡ BROADCAST STORM DETECTED! Peak: {snap['storm_peak']:.0f} pps {Colors.RESET}"
        if storm else
        f"{Colors.GREEN}{Colors.BOLD} ✓ Normal{Colors.RESET}"
    )

    print(f"""
{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════════════════╗
║   📡 Broadcast Traffic Analyzer & Storm Detector                        ║
╚══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
  Interface : {Colors.BOLD}{interface}{Colors.RESET}   Elapsed: {Colors.BOLD}{mins:02d}:{secs:02d}{Colors.RESET}   Status: {storm_indicator}""")

    # Overall Stats
    total = snap['total']
    bcast = snap['broadcast']
    mcast = snap['multicast']
    bcast_pct = (bcast / total * 100) if total > 0 else 0
    mcast_pct = (mcast / total * 100) if total > 0 else 0

    pps_color = Colors.RED if total_pps >= STORM_THRESHOLD else (Colors.YELLOW if total_pps >= ALERT_THRESHOLD else Colors.GREEN)

    print(f"""
{Colors.BOLD}  ── Overall Traffic ──────────────────────────────────────────────────────{Colors.RESET}
  Total Packets : {Colors.BOLD}{total:,}{Colors.RESET}
  Broadcast     : {Colors.YELLOW}{bcast:,}{Colors.RESET} ({bcast_pct:.1f}%)  {format_bar(bcast, total, 25, Colors.YELLOW)}
  Multicast     : {Colors.BLUE}{mcast:,}{Colors.RESET} ({mcast_pct:.1f}%)  {format_bar(mcast, total, 25, Colors.BLUE)}
  Current Rate  : {pps_color}{Colors.BOLD}{total_pps:.1f} pps{Colors.RESET}  (Alert>{ALERT_THRESHOLD} Storm>{STORM_THRESHOLD})""")

    # Protocol Distribution
    print(f"\n{Colors.BOLD}  ── Protocol Distribution ───────────────────────────────────────────────{Colors.RESET}")
    protocols = snap['protocols']
    max_proto = max(protocols.values()) if protocols else 1
    for proto, cnt in list(protocols.items())[:8]:
        pct = (cnt / total * 100) if total > 0 else 0
        bar = format_bar(cnt, max_proto, 18)
        proto_color = Colors.RED if proto == "ARP" else (Colors.YELLOW if proto == "DHCP" else Colors.CYAN)
        print(f"  {proto_color}{proto:<12}{Colors.RESET}  {bar}  {Colors.BOLD}{cnt:>6,}{Colors.RESET} ({pct:.1f}%)")

    # Top Broadcast Talkers
    print(f"\n{Colors.BOLD}  ── Top Broadcast Sources (IP → Total / Current pps) ──────────────────{Colors.RESET}")
    sources    = snap['sources']
    source_pps = snap['source_pps']
    max_src    = max(sources.values()) if sources else 1

    if not sources:
        print(f"  {Colors.DIM}  ยังไม่มีข้อมูล...{Colors.RESET}")
    else:
        print(f"  {Colors.BOLD}{'Rank':<5} {'Source IP':<18} {'Packets':>8}  {'Rate':>8}  {'Bar'}{Colors.RESET}")
        print(f"  {'─'*65}")
        for rank, (ip, cnt) in enumerate(sorted(sources.items(), key=lambda x: -x[1])[:15], 1):
            pps_val    = source_pps.get(ip, 0)
            bar        = format_bar(cnt, max_src, 20)
            src_color  = Colors.RED if pps_val >= ALERT_THRESHOLD else (Colors.YELLOW if pps_val >= ALERT_THRESHOLD / 2 else Colors.GREEN)
            pps_badge  = f"{Colors.RED}{Colors.BOLD}{pps_val:>5.1f} pps{Colors.RESET}" if pps_val >= ALERT_THRESHOLD else f"{Colors.DIM}{pps_val:>5.1f} pps{Colors.RESET}"
            print(f"  {Colors.DIM}{rank:>3}.{Colors.RESET}  {src_color}{ip:<18}{Colors.RESET}  {cnt:>8,}  {pps_badge}  {bar}")

    # Recent Alerts
    alerts = snap['alerts']
    if alerts:
        print(f"\n{Colors.BOLD}  ── ⚠️  Recent Alerts ────────────────────────────────────────────────────{Colors.RESET}")
        # แสดงแค่ 8 alerts ล่าสุด ไม่ซ้ำ src
        seen_recent = set()
        shown = 0
        for a in reversed(alerts):
            if shown >= 8:
                break
            if a['type'] == 'HIGH_BROADCAST':
                key = a['src']
                if key in seen_recent:
                    continue
                seen_recent.add(key)
                ts = a['time'][11:19]
                print(f"  {Colors.RED}🔴 [{ts}] HIGH BROADCAST{Colors.RESET}  "
                      f"{Colors.YELLOW}{a['src']:<18}{Colors.RESET}  "
                      f"{Colors.RED}{Colors.BOLD}{a['pps']} pps{Colors.RESET}")
            elif a['type'] == 'STORM_END':
                ts = a['time'][11:19]
                print(f"  {Colors.YELLOW}🟡 [{ts}] STORM ENDED{Colors.RESET}  "
                      f"Peak: {Colors.BOLD}{a['peak_pps']:.0f} pps{Colors.RESET}")
            shown += 1
    else:
        print(f"\n  {Colors.GREEN}✓ ไม่มี Alert ในขณะนี้{Colors.RESET}")

    # Tips
    print(f"""
{Colors.DIM}  ── Legend ──────────────────────────────────────────────────────────────
  ARP Flood   : อาจเป็น ARP Spoofing, loop, หรืออุปกรณ์ที่เสีย
  DHCP Flood  : DHCP Starvation หรือ รีบูต loop
  SSDP/UPnP   : อุปกรณ์ IoT ส่ง discovery เยอะ
  mDNS        : Apple/Bonjour devices
  Storm>200pps: Broadcast Storm — อาจทำให้ Network หยุดทำงาน
{Colors.RESET}  {Colors.DIM}กด Ctrl+C เพื่อหยุดและดูสรุปผล{Colors.RESET}""")


# ─── Export ───────────────────────────────────────────────────────────

def export_report(snap, interface, filename=None):
    """Export สรุปผลเป็น JSON"""
    import json
    if not filename:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"broadcast_report_{ts}.json"

    data = {
        "interface": interface,
        "capture_time": datetime.now().isoformat(),
        "duration_seconds": round(snap['elapsed'], 1),
        "statistics": {
            "total_packets":     snap['total'],
            "broadcast_packets": snap['broadcast'],
            "multicast_packets": snap['multicast'],
        },
        "top_sources":   snap['sources'],
        "protocols":     snap['protocols'],
        "alerts":        snap['alerts'],
        "storm_detected": snap['storm'],
        "storm_peak_pps": round(snap['storm_peak'], 1),
        "thresholds": {
            "alert_pps": ALERT_THRESHOLD,
            "storm_pps": STORM_THRESHOLD,
        },
        "recommendations": []
    }

    # สร้างคำแนะนำอัตโนมัติ
    recs = data["recommendations"]
    if snap['storm']:
        recs.append("CRITICAL: พบ Broadcast Storm — ตรวจสอบ STP Loop หรืออุปกรณ์ที่เสียทันที")

    sources = snap['sources']
    if sources:
        top_ip, top_cnt = max(sources.items(), key=lambda x: x[1])
        if top_cnt > 1000:
            recs.append(f"HIGH: {top_ip} ส่ง broadcast {top_cnt} packets — ตรวจสอบอุปกรณ์นี้")

    protocols = snap['protocols']
    if protocols.get('ARP', 0) > snap['total'] * 0.5:
        recs.append("MEDIUM: ARP traffic เกิน 50% ของทั้งหมด — อาจมี ARP Spoofing หรือ Network Loop")
    if protocols.get('DHCP', 0) > 500:
        recs.append("MEDIUM: DHCP traffic สูงผิดปกติ — ตรวจสอบ DHCP Starvation หรืออุปกรณ์ที่ขอ IP บ่อยเกิน")

    if not recs:
        recs.append("INFO: ไม่พบสัญญาณผิดปกติ เครือข่ายทำงานปกติ")

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return filename


# ─── Main ─────────────────────────────────────────────────────────────

def get_default_interface():
    """หา Network Interface หลัก"""
    system = platform.system().lower()
    try:
        if system == "darwin":
            result = subprocess.run(
                ["route", "get", "default"],
                capture_output=True, text=True
            )
            match = re.search(r'interface:\s+(\S+)', result.stdout)
            if match:
                return match.group(1)
            return "en0"
        elif system == "linux":
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True
            )
            match = re.search(r'dev\s+(\S+)', result.stdout)
            if match:
                return match.group(1)
            return "eth0"
        else:
            return "Ethernet"
    except Exception:
        return "en0"


def get_iface_ip_mac():
    """ดึง IP และ MAC ของแต่ละ interface จาก ifconfig หรือ ip addr"""
    iface_info = {}   # iface_name → {"ip": ..., "mac": ...}
    system = platform.system().lower()
    try:
        if system in ["darwin", "linux"]:
            cmd = ["ifconfig"] if system == "darwin" else ["ip", "addr"]
            out = subprocess.run(cmd, capture_output=True, text=True).stdout

            if system == "darwin":
                # แยกแต่ละ block ของ interface
                blocks = re.split(r'\n(?=\S)', out)
                for block in blocks:
                    name_m = re.match(r'^(\S+):', block)
                    if not name_m:
                        continue
                    name = name_m.group(1).rstrip(':')
                    ip_m  = re.search(r'inet\s+(\d{1,3}(?:\.\d{1,3}){3})', block)
                    mac_m = re.search(r'ether\s+([0-9a-f:]{17})', block, re.I)
                    iface_info[name] = {
                        "ip":  ip_m.group(1)  if ip_m  else "-",
                        "mac": mac_m.group(1).upper() if mac_m else "-",
                    }
            else:  # linux
                blocks = re.split(r'\n(?=\d+:)', out)
                for block in blocks:
                    name_m = re.match(r'\d+:\s+(\S+):', block)
                    if not name_m:
                        continue
                    name = name_m.group(1).split('@')[0]
                    ip_m  = re.search(r'inet\s+(\d{1,3}(?:\.\d{1,3}){3})', block)
                    mac_m = re.search(r'link/ether\s+([0-9a-f:]{17})', block, re.I)
                    iface_info[name] = {
                        "ip":  ip_m.group(1)  if ip_m  else "-",
                        "mac": mac_m.group(1).upper() if mac_m else "-",
                    }
    except Exception:
        pass
    return iface_info


def list_interfaces():
    """แสดง network interfaces พร้อม IP address และ MAC"""
    system = platform.system().lower()
    try:
        if system in ["darwin", "linux"]:
            # ดึงรายการจาก tcpdump -D
            result = subprocess.run(["tcpdump", "-D"], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')

            # ดึง IP+MAC จาก ifconfig
            iface_info = get_iface_ip_mac()

            print(f"\n{Colors.BOLD}  {'No.':<5} {'Interface':<12} {'Status':<40} {'IP Address':<18} {'MAC Address'}{Colors.RESET}")
            print(f"  {'─'*100}")

            for line in lines:
                # format: "2.en0 [Up, Running, Wireless, Associated]"
                m = re.match(r'(\d+)\.([\w]+)\s+(.*)', line)
                if not m:
                    print(f"  {Colors.DIM}{line}{Colors.RESET}")
                    continue

                num   = m.group(1)
                name  = m.group(2)
                flags = m.group(3).strip()

                info  = iface_info.get(name, {})
                ip    = info.get("ip",  "-")
                mac   = info.get("mac", "-")

                # เลือกสีตาม status
                if "Associated" in flags or "Connected" in flags:
                    status_color = Colors.GREEN
                    name_color   = Colors.GREEN
                elif "Up, Running" in flags and ip != "-":
                    status_color = Colors.CYAN
                    name_color   = Colors.CYAN
                elif "Disconnected" in flags or "none" in flags.lower():
                    status_color = Colors.DIM
                    name_color   = Colors.DIM
                else:
                    status_color = Colors.YELLOW
                    name_color   = Colors.YELLOW

                ip_display  = f"{Colors.GREEN}{ip:<18}{Colors.RESET}" if ip != "-" else f"{Colors.DIM}{'-':<18}{Colors.RESET}"
                mac_display = f"{Colors.YELLOW}{mac}{Colors.RESET}"   if mac != "-" else f"{Colors.DIM}-{Colors.RESET}"
                flags_short = flags[:38]

                print(f"  {Colors.DIM}{num:>3}.{Colors.RESET} "
                      f"{name_color}{name:<12}{Colors.RESET} "
                      f"{status_color}{flags_short:<40}{Colors.RESET} "
                      f"{ip_display} "
                      f"{mac_display}")

            print(f"\n  {Colors.DIM}✦ Interface ที่มี IP address คือตัวที่ Active อยู่{Colors.RESET}")
            print(f"  {Colors.DIM}✦ ใช้ชื่อ interface กับ -i เช่น: sudo python3 broadcast_monitor.py -i en0{Colors.RESET}\n")

        else:
            print(f"  {Colors.DIM}(Windows: ใช้ชื่อ interface เช่น 'Ethernet' หรือ 'Wi-Fi'){Colors.RESET}")
    except Exception as e:
        print(f"  {Colors.RED}Error: {e}{Colors.RESET}")


def main():
    global ALERT_THRESHOLD, STORM_THRESHOLD

    parser = argparse.ArgumentParser(
        description="Broadcast Traffic Analyzer & Storm Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 broadcast_monitor.py                         # Auto-detect interface
  sudo python3 broadcast_monitor.py -i en0                  # macOS Wi-Fi
  sudo python3 broadcast_monitor.py -i eth0                 # Linux Ethernet
  sudo python3 broadcast_monitor.py -i en0 -t 60            # Capture 60 วินาที
  sudo python3 broadcast_monitor.py -i en0 --threshold 30   # Alert ที่ 30 pps
  sudo python3 broadcast_monitor.py --list-interfaces       # ดูรายการ Interface
        """
    )
    parser.add_argument('-i', '--interface', help='Network Interface (default: auto-detect)')
    parser.add_argument('-t', '--time', type=int, default=0, help='ระยะเวลาเก็บข้อมูล (วินาที, 0=ไม่จำกัด)')
    parser.add_argument('--threshold', type=int, default=ALERT_THRESHOLD,
                        help=f'Alert threshold pps ต่อ source (default: {ALERT_THRESHOLD})')
    parser.add_argument('--storm', type=int, default=STORM_THRESHOLD,
                        help=f'Storm threshold pps รวม (default: {STORM_THRESHOLD})')
    parser.add_argument('--list-interfaces', action='store_true', help='แสดง Network Interface ที่ใช้ได้')
    parser.add_argument('-o', '--output', help='Export JSON ไปยังไฟล์ที่กำหนด')
    args = parser.parse_args()

    ALERT_THRESHOLD = args.threshold
    STORM_THRESHOLD = args.storm

    if args.list_interfaces:
        list_interfaces()
        return

    # Auto-detect interface
    interface = args.interface or get_default_interface()

    # ตรวจสอบว่าเป็น root/sudo
    if os.name != 'nt' and os.geteuid() != 0:
        print(f"\n{Colors.RED}  ❌ ต้องรันด้วย sudo:{Colors.RESET}")
        print(f"  {Colors.BOLD}sudo python3 broadcast_monitor.py{Colors.RESET}\n")
        sys.exit(1)

    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║   📡 Broadcast Traffic Analyzer & Storm Detector                        ║
╚══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

  {Colors.BOLD}Interface    :{Colors.RESET} {Colors.GREEN}{interface}{Colors.RESET}
  {Colors.BOLD}Alert Threshold:{Colors.RESET} {Colors.YELLOW}{ALERT_THRESHOLD} pps{Colors.RESET} ต่อ source
  {Colors.BOLD}Storm Threshold:{Colors.RESET} {Colors.RED}{STORM_THRESHOLD} pps{Colors.RESET} รวมทั้งหมด
  {Colors.BOLD}Duration     :{Colors.RESET} {'ไม่จำกัด' if args.time == 0 else f'{args.time} วินาที'}
  {Colors.DIM}กด Ctrl+C เพื่อหยุดและดูสรุปผล{Colors.RESET}
""")

    # เริ่ม capture thread
    cap_thread = threading.Thread(
        target=capture_thread,
        args=(interface, args.time),
        daemon=True
    )
    cap_thread.start()

    time.sleep(1.5)  # รอ tcpdump เริ่ม

    total_pps = 0

    def handle_sigint(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    try:
        while not stop_event.is_set():
            time.sleep(UPDATE_INTERVAL)
            total_pps = stats.compute_window()
            snap = stats.snapshot()
            print_dashboard(snap, total_pps, interface)

            if args.time > 0 and snap['elapsed'] >= args.time:
                stop_event.set()

    except Exception as e:
        pass
    finally:
        stop_event.set()

    # ─── สรุปผล ────────────────────────────────────────────────────────
    os.system('cls' if os.name == 'nt' else 'clear')
    snap = stats.snapshot()

    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║   📊 Broadcast Analysis Summary                                         ║
╚══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

  {Colors.BOLD}Interface   :{Colors.RESET} {interface}
  {Colors.BOLD}Duration    :{Colors.RESET} {snap['elapsed']:.1f} วินาที
  {Colors.BOLD}Total Pkts  :{Colors.RESET} {Colors.BOLD}{snap['total']:,}{Colors.RESET}
  {Colors.BOLD}Broadcast   :{Colors.RESET} {Colors.YELLOW}{snap['broadcast']:,}{Colors.RESET}
  {Colors.BOLD}Multicast   :{Colors.RESET} {Colors.BLUE}{snap['multicast']:,}{Colors.RESET}
  {Colors.BOLD}Storm Detected:{Colors.RESET} {'🔴 YES' if snap['storm'] else '🟢 NO'}
  {Colors.BOLD}Storm Peak  :{Colors.RESET} {snap['storm_peak']:.1f} pps
""")

    if snap['sources']:
        print(f"  {Colors.BOLD}Top Broadcast Sources:{Colors.RESET}")
        for ip, cnt in sorted(snap['sources'].items(), key=lambda x: -x[1])[:10]:
            print(f"    {Colors.GREEN}{ip:<18}{Colors.RESET} → {Colors.BOLD}{cnt:,}{Colors.RESET} packets")

    if snap['protocols']:
        print(f"\n  {Colors.BOLD}Protocol Breakdown:{Colors.RESET}")
        total = snap['total'] or 1
        for proto, cnt in sorted(snap['protocols'].items(), key=lambda x: -x[1]):
            pct = cnt / total * 100
            print(f"    {Colors.CYAN}{proto:<14}{Colors.RESET} {cnt:>6,} ({pct:.1f}%)")

    # คำแนะนำ
    print(f"\n  {Colors.BOLD}Recommendations:{Colors.RESET}")
    recommendations = []
    if snap['storm']:
        recommendations.append((Colors.RED, "CRITICAL: พบ Broadcast Storm! ตรวจสอบ STP Loop หรืออุปกรณ์ที่ผิดปกติทันที"))

    sources = snap['sources']
    if sources:
        top_ip, top_cnt = max(sources.items(), key=lambda x: x[1])
        avg_per_src = snap['total'] / len(sources) if sources else 0
        if top_cnt > avg_per_src * 5:
            recommendations.append((Colors.YELLOW, f"HIGH: {top_ip} ส่ง broadcast มากผิดปกติ ({top_cnt:,} pkts) — ตรวจสอบอุปกรณ์นี้"))

    protos = snap['protocols']
    if protos.get('ARP', 0) > snap['total'] * 0.4:
        recommendations.append((Colors.YELLOW, "MEDIUM: ARP traffic >40% — เปิดใช้ Dynamic ARP Inspection บน Switch"))
    if protos.get('DHCP', 0) > 200:
        recommendations.append((Colors.YELLOW, "MEDIUM: DHCP traffic สูง — เปิดใช้ DHCP Snooping บน Switch"))
    if not recommendations:
        recommendations.append((Colors.GREEN, "INFO: เครือข่ายทำงานปกติ ไม่พบสัญญาณผิดปกติ"))

    for color, msg in recommendations:
        print(f"    {color}• {msg}{Colors.RESET}")

    # Export
    print()
    export_choice = input(f"  {Colors.BOLD}บันทึกรายงาน JSON? [y/N]: {Colors.RESET}").strip().lower()
    if export_choice == 'y':
        filename = export_report(snap, interface, args.output)
        print(f"  {Colors.GREEN}✅ บันทึก: {filename}{Colors.RESET}")
        print(f"  {Colors.DIM}  สามารถนำเข้า report_generator.py เพื่อสร้าง HTML Report ได้{Colors.RESET}")
    print()


if __name__ == "__main__":
    main()
