#!/usr/bin/env python3
"""
Broadcast Storm Detector — Easy Mode
=====================================
ใช้งานง่าย ออกแบบ UI สวยงาม พอดีหน้าจอ ไม่ตกขอบ
ดักจับ IP, MAC (จาก Packet Header), Vendor, Device Type, Port และ Service ได้ทันที

Usage:
    sudo python3 bcast_simple.py
"""

import os
import sys
import re
import time
import subprocess
import threading
import collections
import platform
from datetime import datetime

C = {
    "R": "\033[91m", "G": "\033[92m", "Y": "\033[93m",
    "C": "\033[96m", "B": "\033[94m", "M": "\033[35m",
    "W": "\033[97m", "D": "\033[2m", "X": "\033[0m", "N": "\033[1m",
    "BG_R": "\033[41m", "BG_G": "\033[42m", "BG_Y": "\033[43m",
}

# ── ฐานข้อมูล ────────────────────────────────────────────────────────
pkt_lock = threading.Lock()
src_count = collections.Counter()                          # IP → จำนวน packet
proto_count = collections.Counter()                          # Protocol → จำนวน
port_count = collections.Counter()                          # Port/Service → จำนวน
src_services = collections.defaultdict(collections.Counter)  # IP → {Port/Service: count}
window_src = collections.Counter()                          # IP → จำนวนใน window
total_pkts = [0]
bcast_pkts = [0]
mcast_pkts = [0]
window_pkts = [0]
alerts = []
storm_flag = [False]
stop_flag = threading.Event()

ALERT_PPS = 50    # pps ต่อ source → alert
STORM_PPS = 200   # pps รวม → storm

PROTO_PAT = {
    "ARP": re.compile(r'\barp\b', re.I),
    "DHCP": re.compile(r'\bbootp|dhcp\b', re.I),
    "mDNS": re.compile(r'5353', re.I),
    "SSDP": re.compile(r'1900|ssdp', re.I),
    "NetBIOS": re.compile(r'137|138|netbios', re.I),
    "IGMP": re.compile(r'\bigmp\b', re.I),
    "NTP": re.compile(r'\bntp\b|port 123', re.I),
    "Syslog": re.compile(r'port 514|\bsyslog\b', re.I),
}

# ── Port & Service Database ──────────────────────────────────────────
PORT_SERVICES = {
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    123: "NTP (Time)",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    161: "SNMP",
    162: "SNMP Trap",
    250: "Game/DirectPlay",
    445: "SMB/CIFS",
    514: "Syslog",
    631: "IPP Printer",
    1900: "SSDP (UPnP)",
    3702: "WS-Discovery",
    5353: "mDNS (Bonjour)",
    5355: "LLMNR",
    5557: "Video Stream",
    5683: "CoAP (IoT)",
    10001: "Ubiquiti Disc",
    15600: "TP-Link Disc",
    32410: "Plex Media",
    32412: "Plex Media",
    32414: "Plex Media",
    37777: "Dahua Discovery",
    37778: "Dahua Discovery",
    40000: "Hikvision SADP",
    50000: "IP Cam Discovery",
}

# ── OUI Vendor Database (Prefix 3 octets → Vendor) ─────────────────
OUI_DB = {
    # ─── IP Camera / NVR ───────────────────────────────────────────
    # ─── Hikvision / EZVIZ / HiLook (133 OUI blocks) ───────────────
    "00:0C:E5": "Hikvision", "00:BC:99": "Hikvision", "04:03:12": "Hikvision",
    "04:EE:CD": "Hikvision", "08:3B:C1": "Hikvision", "08:54:11": "Hikvision",
    "08:A1:89": "Hikvision", "08:CC:81": "Hikvision", "0C:75:D2": "Hikvision",
    "0C:A6:4C": "Hikvision", "10:12:FB": "Hikvision", "18:68:CB": "Hikvision",
    "18:80:25": "Hikvision", "20:BB:BC": "Hikvision", "24:0F:9B": "Hikvision",
    "24:28:FD": "Hikvision", "24:32:AE": "Hikvision", "24:48:45": "Hikvision",
    "24:B1:05": "Hikvision", "28:57:BE": "Hikvision", "2C:A5:9C": "Hikvision",
    "34:09:62": "Hikvision", "34:C6:DD": "Hikvision", "3C:1B:F8": "Hikvision",
    "40:AC:BF": "Hikvision", "40:B5:70": "Hikvision", "44:19:B6": "Hikvision",
    "44:47:CC": "Hikvision", "44:A6:42": "Hikvision", "48:78:5B": "Hikvision",
    "4C:1F:86": "Hikvision", "4C:62:DF": "Hikvision", "4C:BD:8F": "Hikvision",
    "4C:F5:DC": "Hikvision", "50:E5:38": "Hikvision", "54:8C:81": "Hikvision",
    "54:C4:15": "Hikvision", "54:D6:0D": "Hikvision", "58:03:FB": "Hikvision",
    "58:50:ED": "Hikvision", "58:8F:CF": "Hikvision", "5C:34:5B": "Hikvision",
    "5C:DD:70": "Hikvision", "60:08:91": "Hikvision", "64:24:4D": "Hikvision",
    "64:7E:B0": "Hikvision", "64:DB:8B": "Hikvision", "64:F2:FB": "Hikvision",
    "68:6D:BC": "Hikvision", "6C:EF:C6": "Hikvision", "70:2E:80": "Hikvision",
    "74:3F:C2": "Hikvision", "74:DA:88": "Hikvision", "78:07:54": "Hikvision",
    "78:A6:A0": "Hikvision", "78:C1:AE": "Hikvision", "7C:09:12": "Hikvision",
    "7C:F3:4A": "Hikvision", "80:48:9F": "Hikvision", "80:7C:62": "Hikvision",
    "80:A2:35": "Hikvision", "80:BE:AF": "Hikvision", "80:F5:AE": "Hikvision",
    "84:94:59": "Hikvision", "84:9A:40": "Hikvision", "84:E0:F4": "Hikvision",
    "88:40:33": "Hikvision", "88:DE:39": "Hikvision", "8C:22:D2": "Hikvision",
    "8C:E7:48": "Hikvision", "90:02:A9": "Hikvision", "94:E1:AC": "Hikvision",
    "94:EC:13": "Hikvision", "98:0D:67": "Hikvision", "98:8B:0A": "Hikvision",
    "98:9D:E5": "Hikvision", "98:DF:82": "Hikvision", "98:F1:12": "Hikvision",
    "98:F6:21": "Hikvision", "A0:CC:2B": "Hikvision", "A0:FF:0C": "Hikvision",
    "A4:14:37": "Hikvision", "A4:29:02": "Hikvision", "A4:4B:D9": "Hikvision",
    "A4:A4:59": "Hikvision", "A4:D5:C2": "Hikvision", "AC:1C:26": "Hikvision",
    "AC:1D:DF": "Hikvision", "AC:B9:2F": "Hikvision", "AC:CB:51": "Hikvision",
    "B0:3A:F2": "Hikvision", "B4:A3:82": "Hikvision", "BC:29:78": "Hikvision",
    "BC:5E:33": "Hikvision", "BC:9B:5E": "Hikvision", "BC:AD:28": "Hikvision",
    "BC:BA:C2": "Hikvision", "C0:2C:5C": "Hikvision", "C0:51:7E": "Hikvision",
    "C0:56:E3": "Hikvision", "C0:6D:ED": "Hikvision", "C4:2F:90": "Hikvision",
    "C4:A3:6E": "Hikvision", "C8:A7:02": "Hikvision", "CC:13:F3": "Hikvision",
    "CC:D3:9D": "Hikvision", "D0:67:26": "Hikvision", "D4:6D:6D": "Hikvision",
    "D4:E8:53": "Hikvision", "D8:E0:E1": "Hikvision", "DC:07:F8": "Hikvision",
    "DC:D2:6A": "Hikvision", "DC:E5:33": "Hikvision", "E0:2B:96": "Hikvision",
    "E0:50:8B": "Hikvision", "E0:BA:AD": "Hikvision", "E0:CA:3C": "Hikvision",
    "E0:DF:13": "Hikvision", "E4:3E:D7": "Hikvision", "E4:D5:8B": "Hikvision",
    "E8:A0:ED": "Hikvision", "EC:3E:F7": "Hikvision", "EC:72:40": "Hikvision",
    "EC:97:E0": "Hikvision", "EC:A9:71": "Hikvision", "EC:C8:9C": "Hikvision",
    "F4:66:0E": "Hikvision", "F4:70:18": "Hikvision", "F8:36:9B": "Hikvision",
    "F8:4D:FC": "Hikvision", "FC:24:22": "Hikvision", "FC:8B:97": "Hikvision",
    "FC:9F:FD": "Hikvision",
    # ─── Fortinet ───────────────────────────────────────────────────
    "04:01:A1": "Fortinet", "70:4C:A5": "Fortinet", "00:09:0F": "Fortinet",
    # ─── Dahua ──────────────────────────────────────────────────────
    "3C:EF:8C": "Dahua", "4C:11:BF": "Dahua", "90:02:A9": "Dahua",
    "A0:BD:1D": "Dahua", "B0:A7:B9": "Dahua", "BC:32:5F": "Dahua",
    "E4:24:6C": "Dahua", "F8:4D:FC": "Dahua", "FC:5A:1D": "Dahua",
    "00:40:8C": "Axis Comm", "AC:CC:8E": "Axis Comm", "B8:A4:4F": "Axis Comm",
    "54:F0:06": "Uniview", "70:2D:84": "Uniview",
    "20:88:10": "Dell",
    "68:DA:73:AB": "Haiyingzhilian", "68:DA:73:A": "Haiyingzhilian", "68:DA:73": "Haiyingzhilian",
    # ─── Cisco / Network Gear ──────────────────────────────────────
    "00:00:0C": "Cisco", "00:1A:A1": "Cisco", "00:1B:54": "Cisco",
    "00:1C:57": "Cisco", "00:1D:70": "Cisco", "00:21:A0": "Cisco",
    "00:22:BD": "Cisco", "00:23:04": "Cisco", "00:24:14": "Cisco",
    "00:25:B5": "Cisco", "00:26:98": "Cisco", "00:27:0D": "Cisco",
    "00:00:5E": "Cisco/VRRP", "00:04:E2": "Cisco Linksys",
    "B0:AA:77": "Cisco Meraki", "CC:16:7E": "Cisco Meraki", "88:15:44": "Cisco Meraki",
    "00:18:E7": "Mikrotik", "48:8F:5A": "Mikrotik", "74:4D:28": "Mikrotik",
    "D4:CA:6D": "Mikrotik", "E4:8D:8C": "Mikrotik", "B8:69:F4": "Mikrotik",
    "CC:2D:E0": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti",
    "24:A4:3C": "Ubiquiti", "44:D9:E7": "Ubiquiti", "68:72:51": "Ubiquiti",
    "00:07:7D": "Netgear", "00:09:5B": "Netgear", "00:0F:B5": "Netgear",
    "00:14:6C": "Netgear", "00:18:4D": "Netgear", "C0:FF:D4": "Netgear",
    "14:DD:A9": "Netgear", "A0:04:60": "Netgear",
    "B0:75:0C": "TP-Link", "54:C8:0F": "TP-Link", "F4:F2:6D": "TP-Link",
    "6C:5A:B0": "TP-Link", "EC:08:6B": "TP-Link", "50:D4:F7": "TP-Link",
    "A8:57:4E": "TP-Link", "98:DA:C4": "TP-Link", "18:D6:C7": "TP-Link",
    "10:BF:48": "TP-Link",
    "00:26:BB": "Apple", "08:66:98": "Apple", "10:40:F3": "Apple",
    "14:10:9F": "Apple", "18:9E:FC": "Apple", "1C:AB:A7": "Apple",
    "20:A2:E4": "Apple", "28:37:37": "Apple", "2C:F0:EE": "Apple",
    "34:15:9E": "Apple", "38:B5:4D": "Apple", "40:A6:D9": "Apple",
    "44:D8:84": "Apple", "48:43:7C": "Apple", "4C:32:75": "Apple",
    "50:EA:D6": "Apple", "54:E4:3A": "Apple", "58:55:CA": "Apple",
    "5C:96:9D": "Apple", "60:F4:45": "Apple", "68:96:7B": "Apple",
    "6C:72:E7": "Apple", "70:11:24": "Apple", "74:E1:B6": "Apple",
    "78:31:C1": "Apple", "80:EA:96": "Apple", "98:01:A7": "Apple",
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "52:54:00": "QEMU/KVM", "08:00:27": "VirtualBox",
    "00:03:47": "Intel", "00:07:E9": "Intel", "00:0E:35": "Intel",
    "00:13:E8": "Intel", "00:16:EA": "Intel", "00:1B:21": "Intel",
    "00:1E:65": "Intel", "00:21:6A": "Intel", "00:23:14": "Intel",
    "00:26:C7": "Intel", "00:27:10": "Intel",
    "B4:96:91": "Samsung", "C8:19:F7": "Samsung", "F4:42:8F": "Samsung",
    "00:1A:8A": "Samsung", "00:16:6B": "Samsung", "18:67:B0": "Samsung",
    "50:CC:F8": "Huawei", "D0:7A:B5": "Huawei", "E4:7E:66": "Huawei",
    "00:46:4B": "Huawei", "48:46:FB": "Huawei", "6C:C3:14": "Huawei",
    "9C:28:EF": "Huawei", "B0:E5:ED": "Huawei",
    "00:E0:4C": "Realtek", "52:54:00": "Realtek Virt",
    "00:08:E1": "STMicro", "00:80:E1": "STMicro",
    "00:1C:C0": "ASUS", "00:23:54": "ASUS", "2C:56:DC": "ASUS",
    "AC:22:0B": "ASUS", "F8:32:E4": "ASUS",
    "00:0D:61": "D-Link", "00:11:95": "D-Link", "00:13:46": "D-Link",
    "00:15:E9": "D-Link", "00:17:9A": "D-Link", "00:19:5B": "D-Link",
    "00:1B:11": "D-Link", "00:1C:F0": "D-Link", "00:22:B0": "D-Link",
    "B8:A3:86": "D-Link", "C8:BE:19": "D-Link", "F0:7D:68": "D-Link",
    # ─── Printers ──────────────────────────────────────────────────
    "00:00:48": "Epson", "00:26:AB": "Epson", "40:1C:83": "Epson",
    "AC:18:26": "Epson",
    "00:00:AA": "HP", "00:01:E6": "HP", "00:0F:61": "HP",
    "00:17:A4": "HP", "00:1A:4B": "HP", "00:21:5A": "HP",
    "70:5A:0F": "HP", "84:34:97": "HP", "94:57:A5": "HP",
    "00:00:F0": "Samsung Print", "00:15:99": "Samsung Print",
    "00:1D:4F": "Canon", "08:00:46": "Canon", "90:F6:52": "Canon",
}

mac_cache = {}   # IP → MAC string


def get_mac_arp(ip):
    """คืน MAC ของ IP (จาก cache หรือ arp command)"""
    if ip in mac_cache and mac_cache[ip] != "N/A":
        return mac_cache[ip]
    try:
        result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=1)
        m = re.search(r"([0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2}", result.stdout)
        if m:
            parts = re.split(r'[:\-]', m.group(0).upper())
            mac = ":".join(p.zfill(2) for p in parts)
            mac_cache[ip] = mac
            return mac
    except Exception:
        pass
    return mac_cache.get(ip, "N/A")


def lookup_vendor(mac):
    """ค้นหา Vendor จาก OUI (รองรับ 4, 3.5, 3 และ 2 octets)"""
    if not mac or mac == "N/A":
        return "Unknown"
    mac_upper = mac.upper()
    for length in (11, 10, 8, 5):
        prefix = mac_upper[:length]
        if prefix in OUI_DB:
            return OUI_DB[prefix]
    return "Unknown"


def get_device_type(vendor):
    """แปลง vendor name เป็นประเภทอุปกรณ์"""
    v = vendor.lower()
    if any(x in v for x in ["hikvision", "hilook", "dahua", "axis", "uniview", "reolink", "amcrest"]):
        return ("📹 Camera", C["M"])
    if any(x in v for x in ["cisco", "mikrotik", "ubiquiti", "netgear", "tp-link", "d-link", "zyxel", "meraki"]):
        return ("🌐 NetDev", C["B"])
    if any(x in v for x in ["apple"]):
        return ("💻 Apple", C["C"])
    if any(x in v for x in ["samsung", "huawei", "oppo", "xiaomi"]):
        return ("📱 Mobile", C["G"])
    if any(x in v for x in ["vmware", "qemu", "virtualbox"]):
        return ("🖥️ VM", C["Y"])
    if any(x in v for x in ["hp", "epson", "canon", "brother", "samsung print"]):
        return ("🖨️ Printer", C["D"])
    if any(x in v for x in ["intel", "realtek", "asus"]):
        return ("💻 PC", C["G"])
    return ("❓ Unknown", C["D"])


def detect_iface():
    """หา interface หลักอัตโนมัติ"""
    sys_name = platform.system().lower()
    try:
        if sys_name == "darwin":
            out = subprocess.run(["route", "get", "default"], capture_output=True, text=True).stdout
            m = re.search(r'interface:\s+(\S+)', out)
            return m.group(1) if m else "en0"
        elif sys_name == "linux":
            out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout
            m = re.search(r'dev\s+(\S+)', out)
            return m.group(1) if m else "eth0"
    except Exception:
        pass
    return "en0"


def get_all_interfaces():
    """ดึง interface ทั้งหมดพร้อม IP และ MAC (รองรับ Windows 11, macOS, Linux)"""
    sys_name = platform.system().lower()
    ifaces = []
    ip_mac = {}

    if sys_name == "windows":
        try:
            cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                   "Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, InterfaceDescription, MacAddress | ConvertTo-Json"]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
            if out and "Error" not in out:
                data = json.loads(out)
                items = data if isinstance(data, list) else [data]
                for idx, item in enumerate(items, 1):
                    name = item.get("Name", f"Interface {idx}")
                    mac = item.get("MacAddress", "-")
                    if mac and mac != "-":
                        mac = mac.replace("-", ":").upper()

                    ip_ps = f"(Get-NetIPAddress -InterfaceAlias '{name}' -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress"
                    ip_out = subprocess.run(["powershell", "-NoProfile", "-Command", ip_ps], capture_output=True, text=True, timeout=3).stdout.strip()
                    ip_val = ip_out.splitlines()[0] if ip_out else "-"

                    ifaces.append({
                        "num": str(idx),
                        "name": name,
                        "flags": item.get("InterfaceDescription", "Active"),
                        "ip": ip_val,
                        "mac": mac
                    })
                if ifaces:
                    return ifaces
        except Exception:
            pass

    try:
        if sys_name in ["darwin", "linux"]:
            out = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout
            blocks = re.split(r'\n(?=\S)', out)
            for block in blocks:
                nm = re.match(r'^(\S+):', block)
                if not nm:
                    continue
                name = nm.group(1).rstrip(':')
                ip_m = re.search(r'inet\s+(\d{1,3}(?:\.\d{1,3}){3})', block)
                mac_m = re.search(r'ether\s+([0-9a-f:]{17})', block, re.I)
                ip_mac[name] = {
                    "ip": ip_m.group(1) if ip_m else "-",
                    "mac": mac_m.group(1).upper() if mac_m else "-",
                }
    except Exception:
        pass

    try:
        out = subprocess.run(["tcpdump", "-D"], capture_output=True, text=True).stdout
        for line in out.strip().split('\n'):
            m = re.match(r'(\d+)\.([\w]+)\s+(.*)', line)
            if not m:
                continue
            num = m.group(1)
            name = m.group(2)
            flags = m.group(3).strip()
            info = ip_mac.get(name, {"ip": "-", "mac": "-"})
            ifaces.append({
                "num": num,
                "name": name,
                "flags": flags,
                "ip": info["ip"],
                "mac": info["mac"],
            })
    except Exception:
        pass

    return ifaces


def pick_interface(default_iface):
    """แสดงรายการ Interface พร้อม IP ให้ผู้ใช้เลือก"""
    ifaces = get_all_interfaces()

    if not ifaces:
        iface_input = input(
            f"  {C['N']}ใส่ Interface (กด Enter ใช้ '{default_iface}'): {C['X']}"
        ).strip()
        return iface_input if iface_input else default_iface

    print(f"\n  {C['N']}{'No.':<4} {'Interface':<10} {'IP Address':<16} {'MAC Address':<18} Status{C['X']}")
    print(f"  {'─'*72}")

    for iface in ifaces:
        ip = iface["ip"]
        mac = iface["mac"]
        name = iface["name"]
        flags = iface["flags"]

        is_active = ip != "-"
        is_loopback = "Loopback" in flags or name == "lo0"
        is_disconnected = "Disconnected" in flags or "none" in flags.lower()

        if is_disconnected and ip == "-":
            continue

        color = C['D'] if is_loopback else (C['G'] if is_active else C['Y'])

        ip_disp = f"{C['G']}{ip:<16}{C['X']}" if ip != "-" else f"{C['D']}{'-':<16}{C['X']}"
        mac_disp = f"{C['Y']}{mac:<18}{C['X']}" if mac != "-" else f"{C['D']}{'-':<18}{C['X']}"
        flag_short = flags[:22]
        marker = f" {C['C']}← default{C['X']}" if name == default_iface else ""

        print(f"  {C['D']}{iface['num']:>2}.{C['X']} "
              f"{color}{name:<10}{C['X']} "
              f"{ip_disp} "
              f"{mac_disp} "
              f"{C['D']}{flag_short}{C['X']}{marker}")

    print()
    print(f"  {C['D']}พิมพ์เลขหรือชื่อ interface  |  กด Enter เพื่อใช้ '{default_iface}'{C['X']}")
    iface_input = input(f"  {C['N']}เลือก Interface: {C['X']}").strip()

    if not iface_input:
        return default_iface

    if iface_input.isdigit():
        matching = [f for f in ifaces if f["num"] == iface_input]
        if matching:
            return matching[0]["name"]

    return iface_input


def parse_line(line):
    src_ip = None
    src_mac = None
    ptype = "broadcast"
    proto = "Other"
    port_str = "-"
    service_str = "Other"

    # 1. ดึง MAC address จาก tcpdump -e output (e.g. "80:be:af:10:09:e6 > ff:ff:ff:ff:ff:ff")
    m_mac = re.search(r'([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\s+>', line)
    if m_mac:
        parts = re.split(r'[:-]', m_mac.group(1).upper())
        src_mac = ":".join(p.zfill(2) for p in parts)

    # 2. ดึง IP และ Port จาก tcpdump output (รองรับทั้งแบบมี/ไม่มีคำว่า "IP" นำหน้า)
    m_ip = re.search(
        r'(?:IP6?\s+)?(\d{1,3}(?:\.\d{1,3}){3})(?:\.(\d+))?\s+>\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\.(\d+))?:',
        line)
    if m_ip:
        src_ip = m_ip.group(1)
        src_port = int(m_ip.group(2)) if m_ip.group(2) else None
        dst_ip = m_ip.group(3)
        dst_port = int(m_ip.group(4)) if m_ip.group(4) else None

        target_port = dst_port or src_port
        if target_port:
            transport = "UDP" if ("UDP" in line or "udp" in line) else (
                "TCP" if ("TCP" in line or "tcp" in line) else "")
            port_str = f"{target_port}/{transport}" if transport else f"{target_port}"
            if target_port in PORT_SERVICES:
                service_str = PORT_SERVICES[target_port]
            else:
                service_str = f"Port {target_port}"
        else:
            if "IGMP" in line or "igmp" in line:
                service_str = "IGMP (Multicast)"
                proto = "IGMP"
                port_str = "L3/IGMP"
            elif "ICMP" in line or "icmp" in line:
                service_str = "ICMP"
                proto = "ICMP"
                port_str = "L3/ICMP"
            elif "VRRP" in line or "vrrp" in line or "224.0.0.18" in line:
                service_str = "VRRP (Router)"
                proto = "VRRP"
                port_str = "L3/VRRP"
            elif "OSPF" in line or "ospf" in line:
                service_str = "OSPF"
                proto = "OSPF"
                port_str = "L3/OSPF"
            else:
                service_str = "IP Traffic"
                port_str = "L3/IP"
    else:
        # Non-IP frames (ARP, STP, ฯลฯ)
        m_src = re.search(r'(?:tell|from|at)\s+(\d{1,3}(?:\.\d{1,3}){3})', line)
        if m_src:
            src_ip = m_src.group(1)
        else:
            m_gen = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
            if m_gen:
                src_ip = m_gen.group(1)

        if "arp" in line.lower():
            proto = "ARP"
            service_str = "ARP"
            port_str = "L2/ARP"
        elif "stp" in line.lower():
            proto = "STP"
            service_str = "STP"
            port_str = "L2/STP"

    if re.search(r'224\.|239\.|ff02::|multicast|01:00:5e', line, re.I):
        ptype = "multicast"

    if proto == "Other":
        for name, pat in PROTO_PAT.items():
            if pat.search(line):
                proto = name
                if service_str == "Other":
                    service_str = name
                break

    return src_ip, src_mac, ptype, proto, port_str, service_str


def capture_loop(iface):
    bcast_filter = "broadcast or multicast or arp"
    # เพิ่ม -e เพื่อดึง MAC Address จาก Ethernet header
    cmd = ["tcpdump", "-i", iface, "-e", "-n", "-l", "-q", "--immediate-mode", bcast_filter]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1)
        while not stop_flag.is_set():
            line = proc.stdout.readline()
            if not line:
                break
            src_ip, src_mac, ptype, proto, port_str, service_str = parse_line(line)
            with pkt_lock:
                total_pkts[0] += 1
                window_pkts[0] += 1
                if ptype == "broadcast":
                    bcast_pkts[0] += 1
                else:
                    mcast_pkts[0] += 1

                if src_ip:
                    if src_mac:
                        mac_cache[src_ip] = src_mac
                    src_count[src_ip] += 1
                    window_src[src_ip] += 1
                    svc_item = f"{port_str} ({service_str})"
                    src_services[src_ip][svc_item] += 1

                proto_count[proto] += 1
                svc_key = f"{port_str:<10} ({service_str})"
                port_count[svc_key] += 1
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except BaseException:
            proc.kill()
    except FileNotFoundError:
        print(f"\n  {C['R']}❌ ไม่พบ tcpdump{C['X']}")
        print(f"  ติดตั้ง: brew install tcpdump\n")
        stop_flag.set()
    except Exception as e:
        print(f"\n  {C['R']}❌ Error: {e}{C['X']}")
        stop_flag.set()


def bar(val, max_val, w=10, color=C["C"]):
    if max_val <= 0:
        max_val = 1
    n = int(val / max_val * w)
    return f"{color}{'█'*n}{'░'*(w-n)}{C['X']}"


def draw(iface, elapsed, total_pps):
    os.system("clear")

    total = total_pkts[0]
    bcast = bcast_pkts[0]
    mcast = mcast_pkts[0]
    storm = storm_flag[0]
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)

    # ── สถานะ Storm ───────────────────────────────────────────────
    if storm:
        status = f"{C['BG_R']}{C['W']}{C['N']} ⚡ BROADCAST STORM! {C['X']}"
    elif total_pps >= ALERT_PPS:
        status = f"{C['BG_Y']}{C['N']} ⚠ HIGH BROADCAST {C['X']}"
    else:
        status = f"{C['BG_G']}{C['N']} ✓ NORMAL {C['X']}"

    pps_color = C['R'] if total_pps >= STORM_PPS else (C['Y'] if total_pps >= ALERT_PPS else C['G'])

    # ── Header (ความกว้าง 74 ช่อง พอดีหน้าจอ) ─────────────────────
    print(f"""
{C['C']}{C['N']}╔══════════════════════════════════════════════════════════════════════════╗
║  📡 Broadcast Storm Detector — Easy Mode                                 ║
╚══════════════════════════════════════════════════════════════════════════╝{C['X']}
  Interface : {C['N']}{iface}{C['X']}   Time: {C['N']}{mins:02d}:{secs:02d}{C['X']}   Status: {status}
  Rate      : {pps_color}{C['N']}{total_pps:.1f} pps{C['X']}  (Alert≥{ALERT_PPS}  Storm≥{STORM_PPS})""")

    # ── ภาพรวม ────────────────────────────────────────────────────
    print(f"""
{C['N']}  ─ Traffic Overview ──────────────────────────────────────────────────────{C['X']}
  Total     : {C['N']}{total:>8,}{C['X']} packets
  Broadcast : {C['Y']}{bcast:>8,}{C['X']}  {bar(bcast, total, 16, C['Y'])}
  Multicast : {C['B']}{mcast:>8,}{C['X']}  {bar(mcast, total, 16, C['B'])}""")

    # ── Top Ports & Services Breakdown ────────────────────────────
    print(f"\n{C['N']}  ─ Top Ports & Services ──────────────────────────────────────────────────{C['X']}")
    top_ports = port_count.most_common(5)
    max_p = top_ports[0][1] if top_ports else 1
    if top_ports:
        for port_info, cnt in top_ports:
            pct = cnt / total * 100 if total else 0
            pc = C['R'] if "ARP" in port_info or "DHCP" in port_info else C['C']
            print(
                f"  {pc}{port_info[:28]:<28}{C['X']}  {bar(cnt, max_p, 14, pc)}  {C['N']}{cnt:>6,}{C['X']} ({pct:.1f}%)")
    else:
        print(f"  {C['D']}  รอรับข้อมูล...{C['X']}")

    # ── Top Broadcast Sources (แสดงจำนวนอุปกรณ์ทั้งหมดที่พบ) ───────
    total_devs = len(src_count)
    top_limit = 15
    top_src = src_count.most_common(top_limit)
    sub_title = f"Top Broadcast Sources (แสดง {len(top_src)} จาก {total_devs} อุปกรณ์ที่พบ)"
    print(f"\n{C['N']}  ─ {sub_title:<71}{C['X']}")
    print(f"  {C['N']}{'#':<3} {'IP Address':<15} {'MAC / Vendor':<22} {'Main Service':<18} {'Pkts':>6}  Bar{C['X']}")
    print(f"  {'─'*73}")
    max_s = top_src[0][1] if top_src else 1
    if top_src:
        for rank, (ip, cnt) in enumerate(top_src, 1):
            mac = get_mac_arp(ip)
            vendor = lookup_vendor(mac)
            dev_type, dev_color = get_device_type(vendor)

            # รวม MAC และ Vendor ให้อ่านง่ายในช่องเดียว
            if vendor != "Unknown":
                mac_vend_str = f"{vendor} ({dev_type.split()[0]})"
            elif mac != "N/A":
                mac_vend_str = mac
            else:
                mac_vend_str = "Unknown"

            top_svc = src_services[ip].most_common(1)[0][0] if src_services[ip] else "-"
            ip_color = C['R'] if cnt == max_s and cnt > 500 else C['G']

            mac_disp = f"{C['Y']}{mac_vend_str[:21]:<22}{C['X']}"
            svc_disp = f"{C['C']}{top_svc[:17]:<18}{C['X']}"

            print(f"  {C['D']}{rank:>2}.{C['X']} "
                  f"{ip_color}{ip:<15}{C['X']} "
                  f"{mac_disp} "
                  f"{svc_disp} "
                  f"{C['N']}{cnt:>6,}{C['X']} {bar(cnt, max_s, 7)}")
    else:
        print(f"  {C['D']}  รอรับข้อมูล...{C['X']}")

    # ── Alerts ────────────────────────────────────────────────────
    recent = [a for a in alerts[-4:]]
    if recent:
        print(f"\n{C['N']}  ─ Recent Alerts ─────────────────────────────────────────────────────────{C['X']}")
        for a in reversed(recent):
            ts = a['time'][11:19]
            print(f"  {C['R']}⚠ [{ts}] {a['msg']}{C['X']}")

    # ── Tips ──────────────────────────────────────────────────────
    print(f"""
{C['D']}  ─ Tips ──────────────────────────────────────────────────────────────────
  ARP flood → Loop/Spoof   DHCP flood → Request loop   Syslog → Config error
  กด Ctrl+C เพื่อหยุดและดูสรุปผล{C['X']}""")


def compute_window(win_start):
    """คำนวณ pps แล้ว reset window"""
    now = time.time()
    elapsed = now - win_start
    if elapsed <= 0:
        return 0, now

    with pkt_lock:
        wn = window_pkts[0]
        wsr = dict(window_src)
        window_pkts[0] = 0
        window_src.clear()

    total_pps = wn / elapsed

    was_storm = storm_flag[0]
    storm_flag[0] = total_pps >= STORM_PPS

    if storm_flag[0] and not was_storm:
        alerts.append({"time": datetime.now().isoformat(),
                       "msg": f"STORM STARTED! {total_pps:.0f} pps"})

    for ip, cnt in wsr.items():
        pps = cnt / elapsed
        if pps >= ALERT_PPS:
            alerts.append({"time": datetime.now().isoformat(),
                           "msg": f"{ip} → {pps:.1f} pps (เกิน threshold)"})

    return total_pps, now


def summary(iface, start_time):
    """แสดงสรุปเมื่อกด Ctrl+C"""
    elapsed = time.time() - start_time
    total = total_pkts[0]
    bcast = bcast_pkts[0]
    mcast = mcast_pkts[0]
    total_devs = len(src_count)

    print(f"""
{C['C']}{C['N']}
╔══════════════════════════════════════════════════════════════════════════╗
║   📊 Broadcast Analysis Summary                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{C['X']}
  Interface : {iface}
  Duration  : {elapsed:.0f} วินาที
  Total     : {C['N']}{total:,}{C['X']} packets
  Broadcast : {C['Y']}{bcast:,}{C['X']}
  Multicast : {C['B']}{mcast:,}{C['X']}
  Devices   : {C['G']}{Colors.BOLD if 'Colors' in globals() else C['N']}{total_devs} อุปกรณ์{C['X']}
  Storm     : {'🔴 YES' if storm_flag[0] else '🟢 NO'}
""")

    if src_count:
        show_limit = min(total_devs, 30)
        print(f"  {C['N']}Top Broadcast Sources (แสดง {show_limit} จากทั้งหมด {total_devs} อุปกรณ์):{C['X']}")
        print(f"  {C['N']}  {'#':<3} {'IP Address':<15} {'MAC / Vendor':<22} {'Main Service':<18} {'Pkts':>6}  Avg pps{C['X']}")
        print(f"  {'─'*73}")
        for rank, (ip, cnt) in enumerate(src_count.most_common(show_limit), 1):
            avg_pps = cnt / elapsed if elapsed > 0 else 0
            mac = get_mac_arp(ip)
            vendor = lookup_vendor(mac)
            dev_type, _ = get_device_type(vendor)

            if vendor != "Unknown":
                mac_vend_str = f"{vendor} ({dev_type.split()[0]})"
            elif mac != "N/A":
                mac_vend_str = mac
            else:
                mac_vend_str = "Unknown"

            top_svc = src_services[ip].most_common(1)[0][0] if src_services[ip] else "-"
            print(f"    {rank:>2}. {C['G']}{ip:<15}{C['X']} "
                  f"{C['Y']}{mac_vend_str[:21]:<22}{C['X']} "
                  f"{C['C']}{top_svc[:17]:<18}{C['X']} "
                  f"{cnt:>6,}  ~{avg_pps:.1f} pps")

    if port_count:
        print(f"\n  {C['N']}Top Ports & Services Breakdown:{C['X']}")
        for port_info, cnt in port_count.most_common(10):
            pct = cnt / total * 100 if total else 0
            print(f"    {C['C']}{port_info[:30]:<30}{C['X']} {cnt:>6,}  ({pct:.1f}%)")

    # คำแนะนำ
    print(f"\n  {C['N']}Recommendations:{C['X']}")
    recs = []
    if storm_flag[0]:
        recs.append((C['R'], "CRITICAL: Broadcast Storm! ตรวจสอบ STP Loop ทันที"))
    if src_count:
        top_ip, top_cnt = src_count.most_common(1)[0]
        if top_cnt > total * 0.3:
            recs.append((C['Y'], f"HIGH: {top_ip} ส่ง broadcast เกิน 30% ตรวจสอบด้วย"))
    if proto_count.get("ARP", 0) > total * 0.5:
        recs.append((C['Y'], "MEDIUM: ARP >50% → เปิด Dynamic ARP Inspection"))
    if proto_count.get("DHCP", 0) > 300:
        recs.append((C['Y'], "MEDIUM: DHCP สูง → เปิด DHCP Snooping"))
    if not recs:
        recs.append((C['G'], "INFO: เครือข่ายปกติ ไม่พบสัญญาณผิดปกติ"))

    for color, msg in recs:
        print(f"    {color}• {msg}{C['X']}")
    print()


def main():
    print(f"""
{C['C']}{C['N']}
╔══════════════════════════════════════════════════════════════════════════╗
║  📡 Broadcast Storm Detector — Easy Mode                                 ║
╚══════════════════════════════════════════════════════════════════════════╝{C['X']}""")

    if os.name != 'nt' and os.geteuid() != 0:
        print(f"\n  {C['R']}❌ ต้องรันด้วย sudo:{C['X']}")
        print(f"  {C['N']}sudo python3 bcast_simple.py{C['X']}\n")
        sys.exit(1)

    default_iface = detect_iface()
    iface = pick_interface(default_iface)

    print(f"\n  {C['G']}✓ เริ่มตรวจจับบน {iface}...{C['X']}")
    print(f"  {C['D']}กด Ctrl+C เพื่อหยุด{C['X']}\n")
    time.sleep(1)

    t = threading.Thread(target=capture_loop, args=(iface,), daemon=True)
    t.start()
    time.sleep(1.5)

    start_time = time.time()
    win_start = start_time
    total_pps = 0.0

    try:
        while not stop_flag.is_set():
            time.sleep(3)
            total_pps, win_start = compute_window(win_start)
            draw(iface, time.time() - start_time, total_pps)
    except KeyboardInterrupt:
        pass
    finally:
        stop_flag.set()

    summary(iface, start_time)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        stop_flag.set()
        print(f"\n\n  {C['C']}👋 ออกจาก Broadcast Monitor เรียบร้อย{C['X']}\n")
        sys.exit(0)
