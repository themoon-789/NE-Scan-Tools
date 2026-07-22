#!/usr/bin/env python3
"""
Network Scanner Tool
====================
สแกนเครือข่ายเพื่อค้นหาอุปกรณ์ที่ออนไลน์ แสดง IP, MAC Address,
Hostname และประเภทอุปกรณ์ (Vendor) รองรับการสแกนทั้ง Class A/B/C

ต้องการสิทธิ์ root/admin เพื่อดึง MAC Address ผ่าน ARP

Usage:
    sudo python3 network_scanner.py
"""

import subprocess
import platform
import socket
import ipaddress
import concurrent.futures
import re
import sys
import time
import os
import json
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


# ─── OUI Database (ตัวอย่าง Vendor ยอดนิยม) ────────────────────────
OUI_DATABASE = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:05:69": "VMware",
    "00:1C:14": "VMware",
    "00:0F:4B": "Oracle VirtualBox",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:16:3E": "Xen",
    "00:1A:4A": "Qumranet (KVM)",
    "AC:DE:48": "Private (Docker)",
    "02:42": "Docker Container",
    "00:15:5D": "Microsoft Hyper-V",
    "00:03:FF": "Microsoft Hyper-V",
    "00:1D:D8": "Microsoft",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    "2C:CF:67": "Raspberry Pi",
    "AA:BB:CC": "Apple",
    "00:1B:63": "Apple",
    "3C:22:FB": "Apple",
    "A8:20:66": "Apple",
    "F0:18:98": "Apple",
    "AC:BC:32": "Apple",
    "00:25:00": "Apple",
    "78:7B:8A": "Apple",
    "14:7D:DA": "Apple",
    "FC:FC:48": "Apple",
    "8C:85:90": "Apple",
    "A4:83:E7": "Apple",
    "3C:06:30": "Apple",
    "88:66:A5": "Apple",
    "00:17:F2": "Apple",
    "00:1E:C2": "Apple",
    "00:26:BB": "Apple",
    "40:6C:8F": "Apple",
    "70:56:81": "Apple",
    "C8:69:CD": "Apple",
    "D0:03:4B": "Apple",
    "E0:B9:BA": "Apple",
    "28:6A:BA": "Apple",
    "5C:F9:38": "Apple",
    "00:0D:93": "Apple",
    "00:14:51": "Apple",
    "D4:61:9D": "Apple",
    "84:38:35": "Apple",
    "00:03:93": "Apple",
    "00:0A:95": "Apple",
    "00:1F:F3": "Apple",
    "00:23:12": "Apple",
    "00:24:36": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "10:DD:B1": "Apple",
    "20:C9:D0": "Apple",
    "24:AB:81": "Apple",
    "34:36:3B": "Apple",
    "44:D8:84": "Apple",
    "58:B0:35": "Apple",
    "60:FA:CD": "Apple",
    "68:5B:35": "Apple",
    "7C:D1:C3": "Apple",
    "84:78:8B": "Apple",
    "98:01:A7": "Apple",
    "B0:65:BD": "Apple",
    "C4:2C:03": "Apple",
    "CC:08:E0": "Apple",
    "DC:2B:61": "Apple",
    "E4:CE:8F": "Apple",
    "F4:5C:89": "Apple",
    "00:E0:4C": "Realtek",
    "52:54:00": "Realtek (QEMU)",
    "00:24:D7": "Intel",
    "00:1B:21": "Intel",
    "00:1E:67": "Intel",
    "3C:97:0E": "Intel",
    "68:05:CA": "Intel",
    "A4:4C:C8": "Intel",
    "8C:EC:4B": "Intel",
    "F8:75:A4": "Intel",
    "B4:96:91": "Intel",
    "48:21:0B": "Intel",
    "A0:36:9F": "Intel",
    "80:86:F2": "Intel",
    "00:AA:00": "Intel",
    "00:02:B3": "Intel",
    "00:04:23": "Intel",
    "00:07:E9": "Intel",
    "00:0E:0C": "Intel",
    "00:11:11": "Intel",
    "00:12:F0": "Intel",
    "00:13:02": "Intel",
    "00:13:20": "Intel",
    "00:13:CE": "Intel",
    "00:13:E8": "Intel",
    "00:15:00": "Intel",
    "00:16:6F": "Intel",
    "00:16:76": "Intel",
    "00:18:DE": "Intel",
    "00:19:D1": "Intel",
    "00:19:D2": "Intel",
    "00:1B:77": "Intel",
    "00:1C:BF": "Intel",
    "00:1D:E0": "Intel",
    "00:1E:64": "Intel",
    "00:1F:3B": "Intel",
    "00:1F:3C": "Intel",
    "00:21:5C": "Intel",
    "00:21:6A": "Intel",
    "00:22:FA": "Intel",
    "00:22:FB": "Intel",
    "00:23:14": "Intel",
    "00:24:D6": "Intel",
    "00:26:C6": "Intel",
    "00:26:C7": "Intel",
    "00:27:10": "Intel",
    "A0:88:B4": "Intel",
    "D0:50:99": "ASRock",
    "00:1D:60": "ASUSTek",
    "00:23:54": "ASUSTek",
    "2C:56:DC": "ASUSTek",
    "50:46:5D": "ASUSTek",
    "54:04:A6": "ASUSTek",
    "60:45:CB": "ASUSTek",
    "74:D0:2B": "ASUSTek",
    "AC:22:0B": "ASUSTek",
    "BC:EE:7B": "ASUSTek",
    "1C:87:2C": "ASUSTek",
    "04:D4:C4": "ASUSTek",
    "08:60:6E": "ASUSTek",
    "10:C3:7B": "ASUSTek",
    "14:DA:E9": "ASUSTek",
    "90:E6:BA": "ASUSTek",
    "D8:50:E6": "ASUSTek",
    "20:CF:30": "ASUSTek",
    "30:5A:3A": "ASUSTek",
    "40:B0:34": "ASUSTek",
    "48:5B:39": "ASUSTek",
    "F8:32:E4": "ASUSTek",
    "00:18:F3": "ASUSTek",
    "00:1A:92": "ASUSTek",
    "00:22:15": "ASUSTek",
    "00:24:8C": "ASUSTek",
    "00:26:18": "ASUSTek",
    "00:E0:18": "ASUSTek",
    "00:0C:6E": "ASUSTek",
    "00:0E:A6": "ASUSTek",
    "00:11:2F": "ASUSTek",
    "00:13:D4": "ASUSTek",
    "00:15:F2": "ASUSTek",
    "00:17:31": "ASUSTek",
    "00:1F:C6": "ASUSTek",
    "00:23:54": "ASUSTek",
    "08:62:66": "ASUSTek",
    "B0:6E:BF": "ASUSTek",
    "C8:60:00": "ASUSTek",
    "04:92:26": "ASUSTek",
    "4C:ED:FB": "ASUSTek",
    "E0:3F:49": "ASUSTek",
    "38:D5:47": "ASUSTek",
    "1C:B7:2C": "ASUSTek",
    "88:D7:F6": "ASUSTek",
    "00:40:F4": "Cameo (D-Link)",
    "00:05:5D": "D-Link",
    "00:0D:88": "D-Link",
    "00:0F:3D": "D-Link",
    "00:11:95": "D-Link",
    "00:13:46": "D-Link",
    "00:15:E9": "D-Link",
    "00:17:9A": "D-Link",
    "00:19:5B": "D-Link",
    "00:1B:11": "D-Link",
    "00:1C:F0": "D-Link",
    "00:1E:58": "D-Link",
    "00:21:91": "D-Link",
    "00:22:B0": "D-Link",
    "00:24:01": "D-Link",
    "00:26:5A": "D-Link",
    "00:50:BA": "D-Link",
    "1C:7E:E5": "D-Link",
    "28:10:7B": "D-Link",
    "34:08:04": "D-Link",
    "78:54:2E": "D-Link",
    "84:C9:B2": "D-Link",
    "9C:D6:43": "D-Link",
    "B8:A3:86": "D-Link",
    "C4:A8:1D": "D-Link",
    "F0:7D:68": "D-Link",
    "FC:75:16": "D-Link",
    "14:D6:4D": "D-Link",
    "C8:D3:A3": "D-Link",
    "CC:B2:55": "D-Link",
    "10:62:EB": "D-Link",
    "1C:5F:2B": "D-Link",
    "30:B5:C2": "TP-Link",
    "50:C7:BF": "TP-Link",
    "54:C8:0F": "TP-Link",
    "60:E3:27": "TP-Link",
    "64:70:02": "TP-Link",
    "90:F6:52": "TP-Link",
    "A4:2B:B0": "TP-Link",
    "B0:4E:26": "TP-Link",
    "B0:95:75": "TP-Link",
    "C0:25:E9": "TP-Link",
    "C4:6E:1F": "TP-Link",
    "D8:07:B6": "TP-Link",
    "E8:DE:27": "TP-Link",
    "F4:F2:6D": "TP-Link",
    "F8:1A:67": "TP-Link",
    "EC:08:6B": "TP-Link",
    "14:CC:20": "TP-Link",
    "18:A6:F7": "TP-Link",
    "1C:3B:F3": "TP-Link",
    "24:69:68": "TP-Link",
    "34:E8:94": "TP-Link",
    "40:ED:00": "TP-Link",
    "48:22:54": "TP-Link",
    "5C:E9:31": "TP-Link",
    "6C:5A:B0": "TP-Link",
    "70:4F:57": "TP-Link",
    "78:44:76": "TP-Link",
    "88:25:93": "TP-Link",
    "98:DA:C4": "TP-Link",
    "A0:F3:C1": "TP-Link",
    "AC:84:C6": "TP-Link",
    "B4:B0:24": "TP-Link",
    "BC:46:99": "TP-Link",
    "C0:06:C3": "TP-Link",
    "CC:32:E5": "TP-Link",
    "D4:6E:0E": "TP-Link",
    "D8:47:32": "TP-Link",
    "E4:D3:32": "TP-Link",
    "EC:26:CA": "TP-Link",
    "F0:A7:31": "TP-Link",
    "F4:EC:38": "TP-Link",
    "FC:D7:33": "TP-Link",
    "00:25:9C": "Cisco/Linksys",
    "00:1A:A2": "Cisco",
    "00:0C:41": "Cisco-Linksys",
    "00:14:BF": "Cisco-Linksys",
    "00:18:39": "Cisco-Linksys",
    "00:1C:10": "Cisco-Linksys",
    "00:1E:E5": "Cisco-Linksys",
    "00:21:29": "Cisco-Linksys",
    "00:22:6B": "Cisco-Linksys",
    "00:23:69": "Cisco-Linksys",
    "00:25:9C": "Cisco-Linksys",
    "20:AA:4B": "Cisco-Linksys",
    "58:6D:8F": "Cisco-Linksys",
    "C0:C1:C0": "Cisco-Linksys",
    "C8:D7:19": "Cisco-Linksys",
    "E8:04:62": "Cisco-Linksys",
    "00:00:0C": "Cisco",
    "00:01:42": "Cisco",
    "00:01:43": "Cisco",
    "00:01:63": "Cisco",
    "00:01:64": "Cisco",
    "00:01:96": "Cisco",
    "00:01:97": "Cisco",
    "00:01:C7": "Cisco",
    "00:01:C9": "Cisco",
    "00:02:16": "Cisco",
    "00:02:17": "Cisco",
    "00:02:3D": "Cisco",
    "00:02:4A": "Cisco",
    "00:02:4B": "Cisco",
    "00:02:7D": "Cisco",
    "00:02:7E": "Cisco",
    "00:02:B9": "Cisco",
    "00:02:BA": "Cisco",
    "00:02:FC": "Cisco",
    "00:02:FD": "Cisco",
    "00:03:31": "Cisco",
    "00:03:32": "Cisco",
    "00:03:6B": "Cisco",
    "00:03:6C": "Cisco",
    "00:03:9F": "Cisco",
    "00:03:A0": "Cisco",
    "00:03:E3": "Cisco",
    "00:03:E4": "Cisco",
    "00:03:FD": "Cisco",
    "00:03:FE": "Cisco",
    "00:04:27": "Cisco",
    "00:04:28": "Cisco",
    "00:04:4D": "Cisco",
    "00:04:4E": "Cisco",
    "00:04:6D": "Cisco",
    "00:04:6E": "Cisco",
    "00:04:9A": "Cisco",
    "00:04:9B": "Cisco",
    "00:04:C0": "Cisco",
    "00:04:C1": "Cisco",
    "00:04:DD": "Cisco",
    "00:04:DE": "Cisco",
    "00:05:00": "Cisco",
    "00:05:01": "Cisco",
    "00:05:31": "Cisco",
    "00:05:32": "Cisco",
    "00:05:5E": "Cisco",
    "00:05:5F": "Cisco",
    "00:05:73": "Cisco",
    "00:05:74": "Cisco",
    "00:05:9A": "Cisco",
    "00:05:9B": "Cisco",
    "00:05:DC": "Cisco",
    "00:05:DD": "Cisco",
    "00:06:28": "Cisco",
    "00:06:2A": "Cisco",
    "00:06:52": "Cisco",
    "00:06:53": "Cisco",
    "00:06:7C": "Cisco",
    "00:06:C1": "Cisco",
    "00:06:D6": "Cisco",
    "00:06:D7": "Cisco",
    "00:06:F6": "Cisco",
    "00:07:0D": "Cisco",
    "00:07:0E": "Cisco",
    "00:07:4F": "Cisco",
    "00:07:50": "Cisco",
    "00:07:7D": "Cisco",
    "00:07:85": "Cisco",
    "00:07:B3": "Cisco",
    "00:07:B4": "Cisco",
    "00:07:EB": "Cisco",
    "00:07:EC": "Cisco",
    "00:08:20": "Cisco",
    "00:08:21": "Cisco",
    "00:08:2F": "Cisco",
    "00:08:30": "Cisco",
    "00:08:31": "Cisco",
    "00:08:32": "Cisco",
    "00:08:7C": "Cisco",
    "00:08:7D": "Cisco",
    "00:08:A3": "Cisco",
    "00:08:A4": "Cisco",
    "00:08:C2": "Cisco",
    "00:08:E2": "Cisco",
    "00:08:E3": "Cisco",
    "00:09:11": "Cisco",
    "00:09:12": "Cisco",
    "00:09:43": "Cisco",
    "00:09:44": "Cisco",
    "00:09:7B": "Cisco",
    "00:09:7C": "Cisco",
    "00:09:B6": "Cisco",
    "00:09:B7": "Cisco",
    "00:09:E8": "Cisco",
    "00:09:E9": "Cisco",
    "00:0A:41": "Cisco",
    "00:0A:42": "Cisco",
    "00:0A:8A": "Cisco",
    "00:0A:8B": "Cisco",
    "00:0A:B7": "Cisco",
    "00:0A:B8": "Cisco",
    "00:0A:F3": "Cisco",
    "00:0A:F4": "Cisco",
    "00:0B:45": "Cisco",
    "00:0B:46": "Cisco",
    "00:0B:5F": "Cisco",
    "00:0B:60": "Cisco",
    "00:0B:85": "Cisco",
    "00:0B:BE": "Cisco",
    "00:0B:BF": "Cisco",
    "00:0B:FC": "Cisco",
    "00:0B:FD": "Cisco",
    "00:0C:30": "Cisco",
    "00:0C:31": "Cisco",
    "00:0C:85": "Cisco",
    "00:0C:86": "Cisco",
    "00:0C:CE": "Cisco",
    "00:0C:CF": "Cisco",
    "00:0D:28": "Cisco",
    "00:0D:29": "Cisco",
    "00:0D:65": "Cisco",
    "00:0D:66": "Cisco",
    "00:0D:BC": "Cisco",
    "00:0D:BD": "Cisco",
    "00:0D:EC": "Cisco",
    "00:0D:ED": "Cisco",
    "00:0E:08": "Cisco",
    "00:0E:38": "Cisco",
    "00:0E:39": "Cisco",
    "00:0E:83": "Cisco",
    "00:0E:84": "Cisco",
    "00:0E:D6": "Cisco",
    "00:0E:D7": "Cisco",
    "00:0F:23": "Cisco",
    "00:0F:24": "Cisco",
    "00:0F:34": "Cisco",
    "00:0F:35": "Cisco",
    "00:0F:8F": "Cisco",
    "00:0F:90": "Cisco",
    "00:10:07": "Cisco",
    "00:10:0B": "Cisco",
    "00:10:0D": "Cisco",
    "00:10:11": "Cisco",
    "00:10:14": "Cisco",
    "00:10:1F": "Cisco",
    "00:10:29": "Cisco",
    "00:10:2F": "Cisco",
    "00:10:54": "Cisco",
    "00:10:79": "Cisco",
    "00:10:7B": "Cisco",
    "00:10:A6": "Cisco",
    "00:10:F6": "Cisco",
    "00:10:FF": "Cisco",
    "00:11:20": "Cisco",
    "00:11:21": "Cisco",
    "00:11:5C": "Cisco",
    "00:11:5D": "Cisco",
    "00:11:92": "Cisco",
    "00:11:93": "Cisco",
    "00:11:BB": "Cisco",
    "00:11:BC": "Cisco",
    "00:12:00": "Cisco",
    "00:12:01": "Cisco",
    "00:12:17": "Cisco",
    "00:12:43": "Cisco",
    "00:12:44": "Cisco",
    "00:12:7F": "Cisco",
    "00:12:80": "Cisco",
    "00:12:D9": "Cisco",
    "00:12:DA": "Cisco",
    "00:13:10": "Cisco",
    "00:13:19": "Cisco",
    "00:13:1A": "Cisco",
    "00:13:5F": "Cisco",
    "00:13:60": "Cisco",
    "00:13:7F": "Cisco",
    "00:13:80": "Cisco",
    "00:13:C3": "Cisco",
    "00:13:C4": "Cisco",
    "00:14:1B": "Cisco",
    "00:14:1C": "Cisco",
    "00:14:69": "Cisco",
    "00:14:6A": "Cisco",
    "00:14:A8": "Cisco",
    "00:14:A9": "Cisco",
    "00:14:F1": "Cisco",
    "00:14:F2": "Cisco",
    "00:15:17": "Cisco",
    "00:15:2B": "Cisco",
    "00:15:2C": "Cisco",
    "00:15:62": "Cisco",
    "00:15:63": "Cisco",
    "00:15:C6": "Cisco",
    "00:15:C7": "Cisco",
    "00:15:FA": "Cisco",
    "00:15:FB": "Cisco",
    "00:16:46": "Cisco",
    "00:16:47": "Cisco",
    "00:16:9C": "Cisco",
    "00:16:9D": "Cisco",
    "00:16:B6": "Cisco",
    "00:16:C7": "Cisco",
    "00:16:C8": "Cisco",
    "00:17:0E": "Cisco",
    "00:17:0F": "Cisco",
    "00:17:3B": "Cisco",
    "00:17:59": "Cisco",
    "00:17:5A": "Cisco",
    "00:17:94": "Cisco",
    "00:17:95": "Cisco",
    "00:17:DF": "Cisco",
    "00:17:E0": "Cisco",
    "00:18:0A": "Cisco",
    "00:18:18": "Cisco",
    "00:18:19": "Cisco",
    "00:18:68": "Cisco",
    "00:18:73": "Cisco",
    "00:18:74": "Cisco",
    "00:18:B9": "Cisco",
    "00:18:BA": "Cisco",
    "00:18:F8": "Cisco",
    "00:19:06": "Cisco",
    "00:19:07": "Cisco",
    "00:19:2F": "Cisco",
    "00:19:30": "Cisco",
    "00:19:47": "Cisco",
    "00:19:55": "Cisco",
    "00:19:56": "Cisco",
    "00:19:A9": "Cisco",
    "00:19:AA": "Cisco",
    "00:19:E7": "Cisco",
    "00:19:E8": "Cisco",
    "00:1A:2F": "Cisco",
    "00:1A:30": "Cisco",
    "00:1A:6C": "Cisco",
    "00:1A:6D": "Cisco",
    "00:1A:A1": "Cisco",
    "00:1A:E2": "Cisco",
    "00:1A:E3": "Cisco",
    "00:1B:0C": "Cisco",
    "00:1B:0D": "Cisco",
    "00:1B:2A": "Cisco",
    "00:1B:2B": "Cisco",
    "00:1B:53": "Cisco",
    "00:1B:54": "Cisco",
    "00:1B:67": "Cisco",
    "00:1B:8F": "Cisco",
    "00:1B:90": "Cisco",
    "00:1B:D4": "Cisco",
    "00:1B:D5": "Cisco",
    "00:1B:D7": "Cisco",
    "00:1C:0E": "Cisco",
    "00:1C:0F": "Cisco",
    "00:1C:57": "Cisco",
    "00:1C:58": "Cisco",
    "00:1C:B0": "Cisco",
    "00:1C:B1": "Cisco",
    "00:1C:F6": "Cisco",
    "00:1C:F9": "Cisco",
    "00:1D:45": "Cisco",
    "00:1D:46": "Cisco",
    "00:1D:70": "Cisco",
    "00:1D:71": "Cisco",
    "00:1D:A1": "Cisco",
    "00:1D:A2": "Cisco",
    "00:1D:E5": "Cisco",
    "00:1D:E6": "Cisco",
    "00:1E:13": "Cisco",
    "00:1E:14": "Cisco",
    "00:1E:49": "Cisco",
    "00:1E:4A": "Cisco",
    "00:1E:79": "Cisco",
    "00:1E:7A": "Cisco",
    "00:1E:BD": "Cisco",
    "00:1E:BE": "Cisco",
    "00:1E:F6": "Cisco",
    "00:1E:F7": "Cisco",
    "00:1F:26": "Cisco",
    "00:1F:27": "Cisco",
    "00:1F:6C": "Cisco",
    "00:1F:6D": "Cisco",
    "00:1F:9D": "Cisco",
    "00:1F:9E": "Cisco",
    "00:1F:C9": "Cisco",
    "00:1F:CA": "Cisco",
    "00:21:1B": "Cisco",
    "00:21:1C": "Cisco",
    "00:21:55": "Cisco",
    "00:21:56": "Cisco",
    "00:21:A0": "Cisco",
    "00:21:A1": "Cisco",
    "00:21:BE": "Cisco",
    "00:21:D7": "Cisco",
    "00:21:D8": "Cisco",
    "00:22:0C": "Cisco",
    "00:22:0D": "Cisco",
    "00:22:3A": "Cisco",
    "00:22:55": "Cisco",
    "00:22:56": "Cisco",
    "00:22:90": "Cisco",
    "00:22:91": "Cisco",
    "00:22:BD": "Cisco",
    "00:22:BE": "Cisco",
    "00:22:CE": "Cisco",
    "00:23:04": "Cisco",
    "00:23:05": "Cisco",
    "00:23:33": "Cisco",
    "00:23:34": "Cisco",
    "00:23:5D": "Cisco",
    "00:23:5E": "Cisco",
    "00:23:AB": "Cisco",
    "00:23:AC": "Cisco",
    "00:23:BE": "Cisco",
    "00:23:EA": "Cisco",
    "00:23:EB": "Cisco",
    "00:24:13": "Cisco",
    "00:24:14": "Cisco",
    "00:24:50": "Cisco",
    "00:24:51": "Cisco",
    "00:24:97": "Cisco",
    "00:24:98": "Cisco",
    "00:24:C3": "Cisco",
    "00:24:C4": "Cisco",
    "00:24:F7": "Cisco",
    "00:24:F9": "Cisco",
    "00:25:2E": "Cisco",
    "00:25:45": "Cisco",
    "00:25:46": "Cisco",
    "00:25:83": "Cisco",
    "00:25:84": "Cisco",
    "00:25:B4": "Cisco",
    "00:25:B5": "Cisco",
    "00:26:0A": "Cisco",
    "00:26:0B": "Cisco",
    "00:26:51": "Cisco",
    "00:26:52": "Cisco",
    "00:26:98": "Cisco",
    "00:26:99": "Cisco",
    "00:26:CB": "Cisco",
    "00:26:CC": "Cisco",
    "00:27:0C": "Cisco",
    "00:27:0D": "Cisco",
    "00:30:19": "Cisco",
    "00:30:24": "Cisco",
    "00:30:40": "Cisco",
    "00:30:71": "Cisco",
    "00:30:78": "Cisco",
    "00:30:7B": "Cisco",
    "00:30:80": "Cisco",
    "00:30:94": "Cisco",
    "00:30:96": "Cisco",
    "00:30:A3": "Cisco",
    "00:30:B6": "Cisco",
    "00:30:F2": "Cisco",
    "00:30:FA": "Cisco",
    "00:40:96": "Cisco",
    "00:50:0B": "Cisco",
    "00:50:0F": "Cisco",
    "00:50:14": "Cisco",
    "00:50:2A": "Cisco",
    "00:50:3E": "Cisco",
    "00:50:50": "Cisco",
    "00:50:53": "Cisco",
    "00:50:54": "Cisco",
    "00:50:73": "Cisco",
    "00:50:80": "Cisco",
    "00:50:A2": "Cisco",
    "00:50:A7": "Cisco",
    "00:50:BD": "Cisco",
    "00:50:D1": "Cisco",
    "00:50:E2": "Cisco",
    "00:50:F0": "Cisco",
    "00:60:09": "Cisco",
    "00:60:2F": "Cisco",
    "00:60:3E": "Cisco",
    "00:60:47": "Cisco",
    "00:60:5C": "Cisco",
    "00:60:70": "Cisco",
    "00:60:83": "Cisco",
    "00:90:0C": "Cisco",
    "00:90:21": "Cisco",
    "00:90:2B": "Cisco",
    "00:90:6D": "Cisco",
    "00:90:6F": "Cisco",
    "00:90:86": "Cisco",
    "00:90:92": "Cisco",
    "00:90:A6": "Cisco",
    "00:90:AB": "Cisco",
    "00:90:B1": "Cisco",
    "00:90:BF": "Cisco",
    "00:90:D9": "Cisco",
    "00:90:F2": "Cisco",
    "00:A0:C5": "Cisco",
    "00:A0:C9": "Cisco",
    "00:A0:CC": "Cisco",
    "00:A2:89": "Cisco",
    "00:A2:EE": "Cisco",
    "00:A7:42": "Cisco",
    "00:AF:1F": "Cisco",
    "00:B0:4A": "Cisco",
    "00:B0:64": "Cisco",
    "00:B0:8E": "Cisco",
    "00:B0:C2": "Cisco",
    "00:B0:E1": "Cisco",
    "00:C0:1D": "Cisco",
    "00:CB:00": "Cisco",
    "00:CC:FC": "Cisco",
    "00:D0:06": "Cisco",
    "00:D0:58": "Cisco",
    "00:D0:63": "Cisco",
    "00:D0:79": "Cisco",
    "00:D0:97": "Cisco",
    "00:D0:BA": "Cisco",
    "00:D0:BB": "Cisco",
    "00:D0:BC": "Cisco",
    "00:D0:C0": "Cisco",
    "00:D0:D3": "Cisco",
    "00:D0:E4": "Cisco",
    "00:D0:FF": "Cisco",
    "00:E0:14": "Cisco",
    "00:E0:1E": "Cisco",
    "00:E0:34": "Cisco",
    "00:E0:4F": "Cisco",
    "00:E0:8F": "Cisco",
    "00:E0:A3": "Cisco",
    "00:E0:B0": "Cisco",
    "00:E0:F7": "Cisco",
    "00:E0:F9": "Cisco",
    "00:E0:FE": "Cisco",
    "00:E1:6D": "Cisco",
    "00:EB:D5": "Cisco",
    "00:F2:8B": "Cisco",
    "00:F6:63": "Cisco",
    "00:FE:C8": "Cisco",
    "04:2A:E2": "Cisco",
    "04:62:73": "Cisco",
    "04:C5:A4": "Cisco",
    "04:DA:D2": "Cisco",
    "04:FE:7F": "Cisco",
    "08:17:35": "Cisco",
    "08:1F:F3": "Cisco",
    "08:80:39": "Cisco",
    "08:CC:68": "Cisco",
    "08:CC:A7": "Cisco",
    "0C:11:67": "Cisco",
    "0C:27:24": "Cisco",
    "0C:68:03": "Cisco",
    "0C:75:BD": "Cisco",
    "0C:85:25": "Cisco",
    "0C:8D:DB": "Cisco",
    "0C:D9:96": "Cisco",
    "0C:F5:A4": "Cisco",
    "10:05:CA": "Cisco",
    "10:5F:49": "Cisco",
    "10:8C:CF": "Cisco",
    "10:BD:18": "Cisco",
    "10:EA:59": "Cisco",
    "14:1F:BA": "Cisco",
    "14:A2:A0": "Cisco",
    "18:33:9D": "Cisco",
    "18:55:0F": "Cisco",
    "18:59:33": "Cisco",
    "18:8B:45": "Cisco",
    "18:8B:9D": "Cisco",
    "18:9C:5D": "Cisco",
    "18:E7:28": "Cisco",
    "18:EF:63": "Cisco",
    "1C:17:D3": "Cisco",
    "1C:1D:86": "Cisco",
    "1C:6A:7A": "Cisco",
    "1C:AA:07": "Cisco",
    "1C:DE:A7": "Cisco",
    "1C:E6:C7": "Cisco",
    "1C:E8:5D": "Cisco",
    "20:37:06": "Cisco",
    "20:3A:07": "Cisco",
    "20:4C:9E": "Cisco",
    "20:BB:C0": "Cisco",
    "24:01:C7": "Cisco",
    "24:37:4C": "Cisco",
    "24:76:7D": "Cisco",
    "24:B6:57": "Cisco",
    "24:E9:B3": "Cisco",
    "28:34:A2": "Cisco",
    "28:52:61": "Cisco",
    "28:6F:7F": "Cisco",
    "28:93:FE": "Cisco",
    "28:94:0F": "Cisco",
    "2C:31:24": "Cisco",
    "2C:33:11": "Cisco",
    "2C:36:F8": "Cisco",
    "2C:3E:CF": "Cisco",
    "2C:3F:38": "Cisco",
    "2C:54:2D": "Cisco",
    "2C:5A:0F": "Cisco",
    "2C:AB:A4": "Cisco",
    "2C:B0:5D": "Cisco",
    "2C:D0:2D": "Cisco",
    "30:37:A6": "Cisco",
    "30:E4:DB": "Cisco",
    "30:F7:0D": "Cisco",
    "34:62:88": "Cisco",
    "34:6F:90": "Cisco",
    "34:A8:4E": "Cisco",
    "34:BD:C8": "Cisco",
    "34:DB:FD": "Cisco",
    "38:1C:1A": "Cisco",
    "38:20:56": "Cisco",
    "38:C8:5C": "Cisco",
    "38:ED:18": "Cisco",
    "3C:08:F6": "Cisco",
    "3C:0E:23": "Cisco",
    "3C:5E:C3": "Cisco",
    "3C:CE:73": "Cisco",
    "3C:DF:1E": "Cisco",
    "40:55:39": "Cisco",
    "40:A6:E8": "Cisco",
    "40:F4:EC": "Cisco",
    "44:03:A7": "Cisco",
    "44:2B:03": "Cisco",
    "44:58:29": "Cisco",
    "44:AD:D9": "Cisco",
    "44:D3:CA": "Cisco",
    "48:1D:70": "Cisco",
    "48:44:87": "Cisco",
    "00:E0:4C": "Realtek",
    "00:40:F4": "Cameo (TP-Link/D-Link ODM)",
    "7C:8B:CA": "TP-Link",
    "00:1E:58": "D-Link",
    "00:50:56": "VMware",
    "FC:FB:FB": "Cisco",
    "00:23:AB": "Cisco",
    "00:1F:9E": "Cisco",
    "00:50:56": "VMware",
    "30:B4:9E": "TP-Link",
    "14:EB:B6": "TP-Link",
    "EC:41:18": "Samsung",
    "00:07:AB": "Samsung",
    "00:12:47": "Samsung",
    "00:12:FB": "Samsung",
    "00:13:77": "Samsung",
    "00:15:99": "Samsung",
    "00:16:32": "Samsung",
    "00:16:6B": "Samsung",
    "00:16:6C": "Samsung",
    "00:16:DB": "Samsung",
    "00:17:C9": "Samsung",
    "00:17:D5": "Samsung",
    "00:18:AF": "Samsung",
    "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung",
    "00:1C:43": "Samsung",
    "00:1D:25": "Samsung",
    "00:1D:F6": "Samsung",
    "00:1E:E1": "Samsung",
    "00:1E:E2": "Samsung",
    "00:1F:CC": "Samsung",
    "00:1F:CD": "Samsung",
    "00:21:19": "Samsung",
    "00:21:D1": "Samsung",
    "00:21:D2": "Samsung",
    "00:23:39": "Samsung",
    "00:23:3A": "Samsung",
    "00:23:99": "Samsung",
    "00:23:D6": "Samsung",
    "00:23:D7": "Samsung",
    "00:24:54": "Samsung",
    "00:24:90": "Samsung",
    "00:24:91": "Samsung",
    "00:24:E9": "Samsung",
    "00:25:66": "Samsung",
    "00:25:67": "Samsung",
    "00:26:37": "Samsung",
    "00:26:5D": "Samsung",
    "00:26:5F": "Samsung",
    "08:08:C2": "Samsung",
    "08:D4:2B": "Samsung",
    "08:EC:A9": "Samsung",
    "08:FC:88": "Samsung",
    "0C:14:20": "Samsung",
    "0C:71:5D": "Samsung",
    "0C:89:10": "Samsung",
    "10:1D:C0": "Samsung",
    "10:30:47": "Samsung",
    "14:32:D1": "Samsung",
    "14:49:E0": "Samsung",
    "14:89:FD": "Samsung",
    "14:A3:64": "Samsung",
    "14:B4:84": "Samsung",
    "18:22:7E": "Samsung",
    "18:3A:2D": "Samsung",
    "18:67:B0": "Samsung",
    "1C:62:B8": "Samsung",
    "1C:66:AA": "Samsung",
    "1C:AF:05": "Samsung",
    "20:13:E0": "Samsung",
    "20:55:31": "Samsung",
    "20:6E:9C": "Samsung",
    "24:4B:03": "Samsung",
    "24:C6:96": "Samsung",
    "24:DB:ED": "Samsung",
    "28:27:BF": "Samsung",
    "28:98:7B": "Samsung",
    "28:BA:B5": "Samsung",
    "28:CC:01": "Samsung",
    "2C:44:01": "Samsung",
    "2C:AE:2B": "Samsung",
    "30:19:66": "Samsung",
    "30:96:FB": "Samsung",
    "30:C7:AE": "Samsung",
    "30:CD:A7": "Samsung",
    "30:D6:C9": "Samsung",
    "34:14:5F": "Samsung",
    "34:23:BA": "Samsung",
    "34:C3:AC": "Samsung",
    "38:01:97": "Samsung",
    "38:0A:94": "Samsung",
    "38:16:D1": "Samsung",
    "38:AA:3C": "Samsung",
    "38:EC:E4": "Samsung",
    "3C:5A:37": "Samsung",
    "3C:62:00": "Samsung",
    "3C:8B:FE": "Samsung",
    "40:0E:85": "Samsung",
    "44:4E:1A": "Samsung",
    "44:6D:6C": "Samsung",
    "44:78:3E": "Samsung",
    "44:F4:59": "Samsung",
    "48:44:F7": "Samsung",
    "48:5A:3F": "Samsung",
    "4C:3C:16": "Samsung",
    "4C:BC:A5": "Samsung",
    "50:01:BB": "Samsung",
    "50:32:75": "Samsung",
    "50:85:69": "Samsung",
    "50:A4:C8": "Samsung",
    "50:CC:F8": "Samsung",
    "50:F0:D3": "Samsung",
    "50:F5:20": "Samsung",
    "54:40:AD": "Samsung",
    "54:92:BE": "Samsung",
    "54:9B:12": "Samsung",
    "58:C3:8B": "Samsung",
    "5C:0A:5B": "Samsung",
    "5C:2E:59": "Samsung",
    "5C:3C:27": "Samsung",
    "5C:A3:9D": "Samsung",
    "60:1E:02": "Samsung",
    "60:6B:BD": "Samsung",
    "60:8F:5C": "Samsung",
    "60:A1:0A": "Samsung",
    "60:AF:6D": "Samsung",
    "60:D0:A9": "Samsung",
    "64:77:91": "Samsung",
    "64:B3:10": "Samsung",
    "68:48:98": "Samsung",
    "68:EB:AE": "Samsung",
    "6C:2F:2C": "Samsung",
    "6C:F3:73": "Samsung",
    "70:F9:27": "Samsung",
    "74:45:CE": "Samsung",
    "74:A5:28": "Samsung",
    "78:1F:DB": "Samsung",
    "78:25:AD": "Samsung",
    "78:40:E4": "Samsung",
    "78:47:1D": "Samsung",
    "78:52:1A": "Samsung",
    "78:59:5E": "Samsung",
    "78:A8:73": "Samsung",
    "78:AB:BB": "Samsung",
    "78:BD:BC": "Samsung",
    "78:D6:F0": "Samsung",
    "7C:0B:C6": "Samsung",
    "7C:11:CB": "Samsung",
    "7C:F8:54": "Samsung",
    "80:18:A7": "Samsung",
    "80:65:6D": "Samsung",
    "84:11:9E": "Samsung",
    "84:25:DB": "Samsung",
    "84:2E:27": "Samsung",
    "84:38:38": "Samsung",
    "84:55:A5": "Samsung",
    "84:A4:66": "Samsung",
    "84:B5:41": "Samsung",
    "84:DB:AC": "Samsung",
    "88:32:9B": "Samsung",
    "88:9B:39": "Samsung",
    "88:AD:D2": "Samsung",
    "8C:77:12": "Samsung",
    "8C:F5:A3": "Samsung",
    "90:00:4E": "Samsung",
    "90:18:7C": "Samsung",
    "94:01:C2": "Samsung",
    "94:35:0A": "Samsung",
    "94:51:03": "Samsung",
    "94:63:D1": "Samsung",
    "94:76:B7": "Samsung",
    "94:B8:6D": "Samsung",
    "94:D7:71": "Samsung",
    "98:0C:82": "Samsung",
    "98:39:8E": "Samsung",
    "98:52:B1": "Samsung",
    "98:83:89": "Samsung",
    "9C:02:98": "Samsung",
    "9C:3A:AF": "Samsung",
    "9C:65:B0": "Samsung",
    "A0:07:98": "Samsung",
    "A0:0B:BA": "Samsung",
    "A0:21:95": "Samsung",
    "A0:82:1F": "Samsung",
    "A0:B4:A5": "Samsung",
    "A0:CB:FD": "Samsung",
    "A4:07:B6": "Samsung",
    "A4:5E:60": "Samsung",
    "A8:06:00": "Samsung",
    "A8:16:B2": "Samsung",
    "A8:7C:01": "Samsung",
    "AC:36:13": "Samsung",
    "AC:5F:3E": "Samsung",
    "AC:EE:9E": "Samsung",
    "B0:47:BF": "Samsung",
    "B0:C4:E7": "Samsung",
    "B0:D0:9C": "Samsung",
    "B0:DF:3A": "Samsung",
    "B0:EC:71": "Samsung",
    "B4:07:F9": "Samsung",
    "B4:3A:28": "Samsung",
    "B4:79:A7": "Samsung",
    "B4:EF:39": "Samsung",
    "B8:5A:73": "Samsung",
    "B8:D9:CE": "Samsung",
    "BC:14:01": "Samsung",
    "BC:20:A4": "Samsung",
    "BC:44:86": "Samsung",
    "BC:72:B1": "Samsung",
    "BC:76:70": "Samsung",
    "BC:85:1F": "Samsung",
    "BC:B1:F3": "Samsung",
    "BC:D1:1F": "Samsung",
    "C0:19:7C": "Samsung",
    "C0:8C:71": "Samsung",
    "C0:97:27": "Samsung",
    "C0:BD:D1": "Samsung",
    "C4:42:02": "Samsung",
    "C4:57:6E": "Samsung",
    "C4:73:1E": "Samsung",
    "C8:14:79": "Samsung",
    "C8:19:F7": "Samsung",
    "C8:38:70": "Samsung",
    "C8:BA:94": "Samsung",
    "CC:07:AB": "Samsung",
    "CC:3A:61": "Samsung",
    "D0:17:C2": "Samsung",
    "D0:22:BE": "Samsung",
    "D0:25:98": "Samsung",
    "D0:59:E4": "Samsung",
    "D0:66:7B": "Samsung",
    "D0:87:E2": "Samsung",
    "D0:C1:B1": "Samsung",
    "D0:DF:9A": "Samsung",
    "D4:87:D8": "Samsung",
    "D4:88:90": "Samsung",
    "D4:E8:B2": "Samsung",
    "D8:57:EF": "Samsung",
    "D8:90:E8": "Samsung",
    "D8:C4:E9": "Samsung",
    "DC:71:44": "Samsung",
    "E0:99:71": "Samsung",
    "E0:CB:1D": "Samsung",
    "E0:DB:10": "Samsung",
    "E4:12:1D": "Samsung",
    "E4:40:E2": "Samsung",
    "E4:58:B8": "Samsung",
    "E4:7C:F9": "Samsung",
    "E4:92:FB": "Samsung",
    "E4:E0:C5": "Samsung",
    "E8:03:9A": "Samsung",
    "E8:50:8B": "Samsung",
    "EC:1F:72": "Samsung",
    "EC:E0:9B": "Samsung",
    "F0:08:F1": "Samsung",
    "F0:25:B7": "Samsung",
    "F0:5A:09": "Samsung",
    "F0:6B:CA": "Samsung",
    "F0:72:8C": "Samsung",
    "F4:09:D8": "Samsung",
    "F4:0E:22": "Samsung",
    "F4:42:8F": "Samsung",
    "F4:7B:5E": "Samsung",
    "F4:7D:EF": "Samsung",
    "F4:9F:54": "Samsung",
    "F8:04:2E": "Samsung",
    "F8:D0:BD": "Samsung",
    "F8:E6:1A": "Samsung",
    "FC:A1:3E": "Samsung",
    "FC:DB:B3": "Samsung",
    "FC:F1:36": "Samsung",
    "18:3D:A2": "Huawei",
    "00:18:82": "Huawei",
    "00:1E:10": "Huawei",
    "00:22:A1": "Huawei",
    "00:25:9E": "Huawei",
    "00:25:68": "Huawei",
    "00:46:4B": "Huawei",
    "00:66:4B": "Huawei",
    "00:E0:FC": "Huawei",
    "04:02:1F": "Huawei",
    "04:25:C5": "Huawei",
    "04:27:58": "Huawei",
    "04:33:89": "Huawei",
    "04:4F:4C": "Huawei",
    "04:B0:E7": "Huawei",
    "04:BD:70": "Huawei",
    "04:C0:6F": "Huawei",
    "04:F9:38": "Huawei",
    "04:FE:8D": "Huawei",
    "08:19:A6": "Huawei",
    "08:34:DC": "Huawei",
    "08:4F:0A": "Huawei",
    "08:63:61": "Huawei",
    "08:7A:4C": "Huawei",
    "08:E8:4F": "Huawei",
    "0C:37:DC": "Huawei",
    "0C:45:BA": "Huawei",
    "0C:96:BF": "Huawei",
    "0C:D6:BD": "Huawei",
    "10:1B:54": "Huawei",
    "10:44:00": "Huawei",
    "10:47:80": "Huawei",
    "10:51:72": "Huawei",
    "10:C6:1F": "Huawei",
    "14:30:04": "Huawei",
    "14:57:9F": "Huawei",
    "14:5F:94": "Huawei",
    "14:B9:68": "Huawei",
    "18:C5:8A": "Huawei",
    "18:D2:76": "Huawei",
    "1C:15:1F": "Huawei",
    "1C:1D:67": "Huawei",
    "1C:8E:5C": "Huawei",
    "20:08:ED": "Huawei",
    "20:0B:C7": "Huawei",
    "20:2B:C1": "Huawei",
    "20:A6:80": "Huawei",
    "20:F3:A3": "Huawei",
    "24:09:95": "Huawei",
    "24:1F:A0": "Huawei",
    "24:44:27": "Huawei",
    "24:69:A5": "Huawei",
    "24:7F:3C": "Huawei",
    "24:DB:AC": "Huawei",
    "28:3C:E4": "Huawei",
    "28:5F:DB": "Huawei",
    "28:6E:D4": "Huawei",
    "28:A6:DB": "Huawei",
    "28:B4:48": "Huawei",
    "2C:AB:00": "Huawei",
    "2C:CF:58": "Huawei",
    "2C:F2:15": "Huawei",
    "30:D1:7E": "Huawei",
    "30:E9:8E": "Huawei",
    "30:F3:35": "Huawei",
    "34:00:A3": "Huawei",
    "34:12:98": "Huawei",
    "34:6A:C2": "Huawei",
    "34:CD:BE": "Huawei",
    "38:37:8B": "Huawei",
    "38:4C:4F": "Huawei",
    "38:BC:01": "Huawei",
    "3C:47:11": "Huawei",
    "3C:67:8C": "Huawei",
    "3C:7A:8A": "Huawei",
    "3C:F8:08": "Huawei",
    "40:4D:8E": "Huawei",
    "40:CB:A8": "Huawei",
    "44:55:B1": "Huawei",
    "44:6A:2E": "Huawei",
    "44:A1:91": "Huawei",
    "44:C3:46": "Huawei",
    "48:00:31": "Huawei",
    "48:46:FB": "Huawei",
    "48:62:76": "Huawei",
    "48:AD:08": "Huawei",
    "48:D5:39": "Huawei",
    "48:FD:8E": "Huawei",
    "4C:1F:CC": "Huawei",
    "4C:54:99": "Huawei",
    "4C:8B:EF": "Huawei",
    "4C:B1:6C": "Huawei",
    "50:01:6B": "Huawei",
    "50:1D:93": "Huawei",
    "50:A7:2B": "Huawei",
    "54:25:EA": "Huawei",
    "54:39:DF": "Huawei",
    "54:89:98": "Huawei",
    "54:A5:1B": "Huawei",
    "58:1F:28": "Huawei",
    "58:2A:F7": "Huawei",
    "58:60:5F": "Huawei",
    "58:7F:66": "Huawei",
    "5C:4C:A9": "Huawei",
    "5C:7D:5E": "Huawei",
    "5C:B3:95": "Huawei",
    "5C:B4:3E": "Huawei",
    "60:08:10": "Huawei",
    "60:DE:44": "Huawei",
    "60:E7:01": "Huawei",
    "64:16:F0": "Huawei",
    "64:3E:8C": "Huawei",
    "68:89:C1": "Huawei",
    "68:A0:F6": "Huawei",
    "6C:0E:0D": "Huawei",
    "70:19:2F": "Huawei",
    "70:54:F5": "Huawei",
    "70:72:3C": "Huawei",
    "70:7B:E8": "Huawei",
    "70:A8:E3": "Huawei",
    "74:88:2A": "Huawei",
    "74:A5:28": "Huawei",
    "78:1D:BA": "Huawei",
    "78:6A:89": "Huawei",
    "78:D7:52": "Huawei",
    "78:F5:57": "Huawei",
    "7C:60:97": "Huawei",
    "7C:A2:3E": "Huawei",
    "80:71:7A": "Huawei",
    "80:B6:86": "Huawei",
    "80:D0:9B": "Huawei",
    "80:FB:06": "Huawei",
    "84:A8:E4": "Huawei",
    "84:AD:58": "Huawei",
    "84:DB:AC": "Huawei",
    "84:EB:18": "Huawei",
    "88:28:B3": "Huawei",
    "88:3F:D3": "Huawei",
    "88:53:D4": "Huawei",
    "88:86:03": "Huawei",
    "88:A2:D7": "Huawei",
    "88:CE:FA": "Huawei",
    "88:CF:98": "Huawei",
    "88:E3:AB": "Huawei",
    "8C:34:FD": "Huawei",
    "8C:EB:C6": "Huawei",
    "90:17:AC": "Huawei",
    "90:4E:2B": "Huawei",
    "90:67:1C": "Huawei",
    "90:94:97": "Huawei",
    "90:E7:C4": "Huawei",
    "94:04:9C": "Huawei",
    "94:77:2B": "Huawei",
    "94:DB:C9": "Huawei",
    "94:FE:22": "Huawei",
    "98:E7:F5": "Huawei",
    "9C:28:EF": "Huawei",
    "9C:37:F4": "Huawei",
    "9C:74:1A": "Huawei",
    "9C:B2:B2": "Huawei",
    "9C:C1:72": "Huawei",
    "A0:08:6F": "Huawei",
    "A0:57:E3": "Huawei",
    "A0:6D:09": "Huawei",
    "A4:71:74": "Huawei",
    "A4:99:47": "Huawei",
    "A4:BA:76": "Huawei",
    "A4:BE:2B": "Huawei",
    "A4:DC:BE": "Huawei",
    "A8:C8:3A": "Huawei",
    "AC:4E:91": "Huawei",
    "AC:61:EA": "Huawei",
    "AC:CF:85": "Huawei",
    "AC:E2:15": "Huawei",
    "AC:E8:7B": "Huawei",
    "B0:5B:67": "Huawei",
    "B0:E5:ED": "Huawei",
    "B4:15:13": "Huawei",
    "B4:30:52": "Huawei",
    "B4:47:5E": "Huawei",
    "B4:CD:27": "Huawei",
    "B8:08:D7": "Huawei",
    "B8:BC:1B": "Huawei",
    "BC:25:E0": "Huawei",
    "BC:3F:8F": "Huawei",
    "BC:75:74": "Huawei",
    "BC:76:70": "Huawei",
    "BC:9C:31": "Huawei",
    "C0:70:09": "Huawei",
    "C4:05:28": "Huawei",
    "C4:07:2F": "Huawei",
    "C4:47:3F": "Huawei",
    "C4:75:AB": "Huawei",
    "C4:86:E9": "Huawei",
    "C8:51:95": "Huawei",
    "C8:D1:5E": "Huawei",
    "CC:53:B5": "Huawei",
    "CC:96:A0": "Huawei",
    "CC:A2:23": "Huawei",
    "CC:CC:81": "Huawei",
    "D0:3E:5C": "Huawei",
    "D0:7A:B5": "Huawei",
    "D0:D0:4B": "Huawei",
    "D0:FF:98": "Huawei",
    "D4:40:F0": "Huawei",
    "D4:61:2E": "Huawei",
    "D4:6A:A8": "Huawei",
    "D4:6E:5C": "Huawei",
    "D4:94:E8": "Huawei",
    "D4:B1:10": "Huawei",
    "D8:49:0B": "Huawei",
    "D8:C7:71": "Huawei",
    "DC:09:4C": "Huawei",
    "DC:D2:FC": "Huawei",
    "E0:19:1D": "Huawei",
    "E0:24:7F": "Huawei",
    "E0:97:96": "Huawei",
    "E4:35:C8": "Huawei",
    "E4:68:A3": "Huawei",
    "E4:C2:D1": "Huawei",
    "E8:08:8B": "Huawei",
    "E8:68:19": "Huawei",
    "E8:CD:2D": "Huawei",
    "EC:23:3D": "Huawei",
    "EC:38:8F": "Huawei",
    "EC:CB:30": "Huawei",
    "F0:2F:A7": "Huawei",
    "F0:43:47": "Huawei",
    "F0:C8:50": "Huawei",
    "F0:D4:F6": "Huawei",
    "F4:55:9C": "Huawei",
    "F4:63:49": "Huawei",
    "F4:C7:14": "Huawei",
    "F4:DC:F9": "Huawei",
    "F4:E3:FB": "Huawei",
    "F8:01:13": "Huawei",
    "F8:3D:FF": "Huawei",
    "F8:4A:BF": "Huawei",
    "F8:98:B9": "Huawei",
    "F8:E8:11": "Huawei",
    "FC:48:EF": "Huawei",
    "FC:E3:3C": "Huawei",
    "3C:CD:5D": "Xiaomi",
    "0C:1D:AF": "Xiaomi",
    "10:2A:B3": "Xiaomi",
    "14:F6:5A": "Xiaomi",
    "18:59:36": "Xiaomi",
    "1C:5A:3E": "Xiaomi",
    "20:82:C0": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "28:E3:1F": "Xiaomi",
    "34:80:B3": "Xiaomi",
    "34:CE:00": "Xiaomi",
    "38:A4:ED": "Xiaomi",
    "3C:BD:3E": "Xiaomi",
    "40:31:3C": "Xiaomi",
    "50:64:2B": "Xiaomi",
    "58:44:98": "Xiaomi",
    "64:09:80": "Xiaomi",
    "64:B4:73": "Xiaomi",
    "64:CC:2E": "Xiaomi",
    "68:DF:DD": "Xiaomi",
    "74:23:44": "Xiaomi",
    "74:51:BA": "Xiaomi",
    "7C:1D:D9": "Xiaomi",
    "84:F3:EB": "Xiaomi",
    "8C:BE:BE": "Xiaomi",
    "98:FA:E3": "Xiaomi",
    "9C:99:A0": "Xiaomi",
    "A0:86:C6": "Xiaomi",
    "AC:C1:EE": "Xiaomi",
    "B0:E2:35": "Xiaomi",
    "C4:6A:B7": "Xiaomi",
    "D4:97:0B": "Xiaomi",
    "F0:B4:29": "Xiaomi",
    "F4:8B:32": "Xiaomi",
    "F8:A4:5F": "Xiaomi",
    "FC:64:BA": "Xiaomi",
    "14:91:82": "Xiaomi",
    "00:1F:A7": "Sony",
    "00:13:A9": "Sony",
    "00:1A:80": "Sony",
    "00:1D:BA": "Sony",
    "00:1E:A4": "Sony",
    "00:24:BE": "Sony",
    "28:0D:FC": "Sony",
    "30:17:C8": "Sony",
    "40:B8:37": "Sony",
    "54:42:49": "Sony",
    "58:48:22": "Sony",
    "70:1A:04": "Sony",
    "78:84:3C": "Sony",
    "AC:9B:0A": "Sony",
    "B4:52:7E": "Sony",
    "BC:60:A7": "Sony",
    "FC:0F:E6": "Sony",
    "04:5D:4B": "Sony",
    "00:1B:FB": "Sony",
    "F8:D0:AC": "Sony",
    "FC:62:B9": "Sony",
    "40:B0:76": "ASUSTek/ASUS Router",
    "F4:6B:EF": "Netgear",
    "00:1B:2F": "Netgear",
    "00:1E:2A": "Netgear",
    "00:1F:33": "Netgear",
    "00:22:3F": "Netgear",
    "00:24:B2": "Netgear",
    "00:26:F2": "Netgear",
    "20:0C:C8": "Netgear",
    "20:4E:7F": "Netgear",
    "28:C6:8E": "Netgear",
    "2C:B0:5D": "Netgear",
    "30:46:9A": "Netgear",
    "44:94:FC": "Netgear",
    "4C:60:DE": "Netgear",
    "6C:B0:CE": "Netgear",
    "84:1B:5E": "Netgear",
    "8C:3B:AD": "Netgear",
    "A0:04:60": "Netgear",
    "A0:21:B7": "Netgear",
    "A0:40:A0": "Netgear",
    "A4:2B:8C": "Netgear",
    "B0:7F:B9": "Netgear",
    "B0:B9:8A": "Netgear",
    "C0:3F:0E": "Netgear",
    "C4:04:15": "Netgear",
    "CC:40:D0": "Netgear",
    "DC:EF:09": "Netgear",
    "E0:46:9A": "Netgear",
    "E0:91:F5": "Netgear",
    "E4:F4:C6": "Netgear",
    "E8:FC:AF": "Netgear",
    "F8:73:94": "Netgear",
    "00:09:5B": "Netgear",
    "00:0F:B5": "Netgear",
    "00:14:6C": "Netgear",
    "00:18:4D": "Netgear",
    "00:1A:2F": "Netgear",
    "10:0D:7F": "Netgear",
    "10:0C:6B": "Netgear",
    "4C:ED:FB": "Netgear",
    "08:02:8E": "Netgear",
    "20:E5:2A": "Netgear",
    "38:94:96": "Netgear",
    "6C:B0:CE": "Netgear",
    "84:1B:5E": "Netgear",
    "9C:D3:6D": "Netgear",
    "A0:63:91": "Netgear",
    "C4:3D:C7": "Netgear",
    "CC:40:D0": "Netgear",
    "E0:91:F5": "Netgear",
    "E4:F4:C6": "Netgear",
    "E8:FC:AF": "Netgear",
    "00:1C:DF": "Belkin",
    "00:1E:E5": "Belkin",
    "00:22:75": "Belkin",
    "08:86:3B": "Belkin",
    "30:23:03": "Belkin",
    "94:10:3E": "Belkin",
    "B4:75:0E": "Belkin",
    "C0:56:27": "Belkin",
    "C4:41:1E": "Belkin",
    "E8:9F:80": "Belkin",
    "EC:1A:59": "Belkin",
    "08:00:20": "Sun Microsystems",
    "00:14:4F": "Oracle/Sun",
    "00:21:F6": "Oracle/Sun",
    "00:10:E0": "Oracle/Sun",
    "00:03:BA": "Oracle/Sun",
    "00:1B:24": "Quanta (ODM)",
    "00:0B:DB": "Dell",
    "00:06:5B": "Dell",
    "00:08:74": "Dell",
    "00:0B:DB": "Dell",
    "00:0D:56": "Dell",
    "00:0F:1F": "Dell",
    "00:11:43": "Dell",
    "00:12:3F": "Dell",
    "00:13:72": "Dell",
    "00:14:22": "Dell",
    "00:15:C5": "Dell",
    "00:16:F0": "Dell",
    "00:18:8B": "Dell",
    "00:19:B9": "Dell",
    "00:1A:A0": "Dell",
    "00:1C:23": "Dell",
    "00:1D:09": "Dell",
    "00:1E:4F": "Dell",
    "00:1E:C9": "Dell",
    "00:21:70": "Dell",
    "00:21:9B": "Dell",
    "00:22:19": "Dell",
    "00:23:AE": "Dell",
    "00:24:E8": "Dell",
    "00:25:64": "Dell",
    "00:26:B9": "Dell",
    "10:98:36": "Dell",
    "14:18:77": "Dell",
    "14:9E:CF": "Dell",
    "14:B3:1F": "Dell",
    "14:FE:B5": "Dell",
    "18:03:73": "Dell",
    "18:66:DA": "Dell",
    "18:A9:9B": "Dell",
    "18:DB:F2": "Dell",
    "18:FB:7B": "Dell",
    "1C:40:24": "Dell",
    "20:47:47": "Dell",
    "20:88:10": "Dell",
    "68:DA:73:AB": "Haiyingzhilian",
    "68:DA:73:A": "Haiyingzhilian",
    "68:DA:73": "Haiyingzhilian",
    "24:6E:96": "Dell",
    "24:B6:FD": "Dell",
    "28:C8:25": "Dell",
    "28:F1:0E": "Dell",
    "34:17:EB": "Dell",
    "34:E6:D7": "Dell",
    "3C:A8:2A": "Dell",
    "44:A8:42": "Dell",
    "48:4D:7E": "Dell",
    "4C:76:25": "Dell",
    "50:9A:4C": "Dell",
    "54:9F:35": "Dell",
    "5C:26:0A": "Dell",
    "5C:F9:DD": "Dell",
    "64:00:6A": "Dell",
    "70:B5:E8": "Dell",
    "74:86:7A": "Dell",
    "74:E6:E2": "Dell",
    "78:2B:CB": "Dell",
    "78:45:C4": "Dell",
    "7C:B2:7D": "Dell",
    "80:18:44": "Dell",
    "84:2B:2B": "Dell",
    "84:7B:EB": "Dell",
    "84:8F:69": "Dell",
    "88:AE:1D": "Dell",
    "90:B1:1C": "Dell",
    "98:90:96": "Dell",
    "98:E7:43": "Dell",
    "A4:1F:72": "Dell",
    "A4:BA:DB": "Dell",
    "B0:83:FE": "Dell",
    "B4:E1:0F": "Dell",
    "B8:2A:72": "Dell",
    "B8:AC:6F": "Dell",
    "B8:CA:3A": "Dell",
    "BC:30:5B": "Dell",
    "C8:1F:66": "Dell",
    "D0:43:1E": "Dell",
    "D0:67:E5": "Dell",
    "D4:81:D7": "Dell",
    "D4:AE:52": "Dell",
    "D4:BE:D9": "Dell",
    "D8:9E:F3": "Dell",
    "E4:43:4B": "Dell",
    "E8:CF:83": "Dell",
    "EC:F4:BB": "Dell",
    "F0:1F:AF": "Dell",
    "F4:8E:38": "Dell",
    "F8:B1:56": "Dell",
    "F8:BC:12": "Dell",
    "F8:CA:B8": "Dell",
    "F8:DB:88": "Dell",
    "00:0D:60": "IBM",
    "00:04:AC": "IBM",
    "00:05:5D": "IBM",
    "00:06:29": "IBM",
    "00:09:6B": "IBM",
    "00:0A:E4": "IBM",
    "00:0D:60": "IBM",
    "00:10:D9": "IBM",
    "00:11:25": "IBM",
    "00:14:5E": "IBM",
    "00:16:35": "IBM",
    "00:17:EF": "IBM",
    "00:18:B1": "IBM",
    "00:1A:64": "IBM",
    "00:1A:E0": "IBM",
    "00:20:35": "IBM",
    "00:20:99": "IBM",
    "00:23:7D": "IBM",
    "00:24:7F": "IBM",
    "08:17:F4": "IBM",
    "28:6E:D4": "IBM",
    "34:40:B5": "IBM",
    "40:F2:E9": "IBM",
    "50:68:0A": "IBM",
    "5C:F3:FC": "IBM",
    "6C:AE:8B": "IBM",
    "74:99:75": "IBM",
    "A4:25:71": "IBM",
    "B4:99:BA": "Hewlett-Packard",
    "00:01:E6": "Hewlett-Packard",
    "00:01:E7": "Hewlett-Packard",
    "00:02:A5": "Hewlett-Packard",
    "00:04:EA": "Hewlett-Packard",
    "00:08:02": "Hewlett-Packard",
    "00:08:83": "Hewlett-Packard",
    "00:0A:57": "Hewlett-Packard",
    "00:0B:CD": "Hewlett-Packard",
    "00:0D:9D": "Hewlett-Packard",
    "00:0E:7F": "Hewlett-Packard",
    "00:0F:20": "Hewlett-Packard",
    "00:0F:61": "Hewlett-Packard",
    "00:10:83": "Hewlett-Packard",
    "00:10:E3": "Hewlett-Packard",
    "00:11:0A": "Hewlett-Packard",
    "00:11:85": "Hewlett-Packard",
    "00:12:79": "Hewlett-Packard",
    "00:13:21": "Hewlett-Packard",
    "00:14:38": "Hewlett-Packard",
    "00:14:C2": "Hewlett-Packard",
    "00:15:60": "Hewlett-Packard",
    "00:16:35": "Hewlett-Packard",
    "00:17:08": "Hewlett-Packard",
    "00:17:A4": "Hewlett-Packard",
    "00:18:FE": "Hewlett-Packard",
    "00:19:BB": "Hewlett-Packard",
    "00:1A:4B": "Hewlett-Packard",
    "00:1B:78": "Hewlett-Packard",
    "00:1C:C4": "Hewlett-Packard",
    "00:1E:0B": "Hewlett-Packard",
    "00:1F:29": "Hewlett-Packard",
    "00:21:5A": "Hewlett-Packard",
    "00:22:64": "Hewlett-Packard",
    "00:23:7D": "Hewlett-Packard",
    "00:24:81": "Hewlett-Packard",
    "00:25:B3": "Hewlett-Packard",
    "00:26:55": "Hewlett-Packard",
    "00:27:1A": "Hewlett-Packard",
    "00:30:6E": "Hewlett-Packard",
    "00:30:C1": "Hewlett-Packard",
    "00:50:8B": "Hewlett-Packard",
    "00:60:B0": "Hewlett-Packard",
    "00:80:A0": "Hewlett-Packard",
    "08:00:09": "Hewlett-Packard",
    "10:1F:74": "Hewlett-Packard",
    "10:60:4B": "Hewlett-Packard",
    "14:02:EC": "Hewlett-Packard",
    "14:58:D0": "Hewlett-Packard",
    "18:A9:05": "Hewlett-Packard",
    "1C:C1:DE": "Hewlett-Packard",
    "24:BE:05": "Hewlett-Packard",
    "28:80:23": "Hewlett-Packard",
    "28:92:4A": "Hewlett-Packard",
    "2C:27:D7": "Hewlett-Packard",
    "2C:41:38": "Hewlett-Packard",
    "2C:44:FD": "Hewlett-Packard",
    "2C:59:E5": "Hewlett-Packard",
    "2C:76:8A": "Hewlett-Packard",
    "30:8D:99": "Hewlett-Packard",
    "30:E1:71": "Hewlett-Packard",
    "34:64:A9": "Hewlett-Packard",
    "34:FC:B9": "Hewlett-Packard",
    "38:63:BB": "Hewlett-Packard",
    "38:EA:A7": "Hewlett-Packard",
    "3C:4A:92": "Hewlett-Packard",
    "3C:52:82": "Hewlett-Packard",
    "3C:D9:2B": "Hewlett-Packard",
    "40:A8:F0": "Hewlett-Packard",
    "40:B0:34": "Hewlett-Packard",
    "40:B9:3C": "Hewlett-Packard",
    "44:1E:A1": "Hewlett-Packard",
    "44:31:92": "Hewlett-Packard",
    "44:48:C1": "Hewlett-Packard",
    "48:0F:CF": "Hewlett-Packard",
    "48:DF:37": "Hewlett-Packard",
    "4C:39:09": "Hewlett-Packard",
    "50:65:F3": "Hewlett-Packard",
    "58:20:B1": "Hewlett-Packard",
    "5C:B9:01": "Hewlett-Packard",
    "5C:B9:02": "Hewlett-Packard",
    "60:45:BD": "Hewlett-Packard",
    "64:31:50": "Hewlett-Packard",
    "64:51:06": "Hewlett-Packard",
    "68:B5:99": "Hewlett-Packard",
    "6C:3B:E5": "Hewlett-Packard",
    "6C:C2:17": "Hewlett-Packard",
    "70:10:6F": "Hewlett-Packard",
    "70:5A:0F": "Hewlett-Packard",
    "74:46:A0": "Hewlett-Packard",
    "78:48:59": "Hewlett-Packard",
    "78:AC:C0": "Hewlett-Packard",
    "78:E3:B5": "Hewlett-Packard",
    "78:E7:D1": "Hewlett-Packard",
    "80:C1:6E": "Hewlett-Packard",
    "84:34:97": "Hewlett-Packard",
    "88:51:FB": "Hewlett-Packard",
    "8C:DC:D4": "Hewlett-Packard",
    "90:1B:0E": "Hewlett-Packard",
    "94:57:A5": "Hewlett-Packard",
    "98:4B:E1": "Hewlett-Packard",
    "98:E7:F4": "Hewlett-Packard",
    "9C:8E:99": "Hewlett-Packard",
    "9C:B6:54": "Hewlett-Packard",
    "A0:1D:48": "Hewlett-Packard",
    "A0:2B:B8": "Hewlett-Packard",
    "A0:48:1C": "Hewlett-Packard",
    "A0:D3:C1": "Hewlett-Packard",
    "A4:5D:36": "Hewlett-Packard",
    "A8:B1:D4": "Hewlett-Packard",
    "AC:16:2D": "Hewlett-Packard",
    "B0:5A:DA": "Hewlett-Packard",
    "B4:39:D6": "Hewlett-Packard",
    "B4:B5:2F": "Hewlett-Packard",
    "B8:AF:67": "Hewlett-Packard",
    "C0:91:34": "Hewlett-Packard",
    "C4:34:6B": "Hewlett-Packard",
    "C8:B5:AD": "Hewlett-Packard",
    "C8:CB:B8": "Hewlett-Packard",
    "CC:3E:5F": "Hewlett-Packard",
    "D0:7E:28": "Hewlett-Packard",
    "D4:85:64": "Hewlett-Packard",
    "D4:C9:EF": "Hewlett-Packard",
    "D8:9D:67": "Hewlett-Packard",
    "D8:D3:85": "Hewlett-Packard",
    "DC:4A:3E": "Hewlett-Packard",
    "E0:07:1B": "Hewlett-Packard",
    "E4:11:5B": "Hewlett-Packard",
    "E8:39:35": "Hewlett-Packard",
    "EC:8E:B5": "Hewlett-Packard",
    "EC:B1:D7": "Hewlett-Packard",
    "F0:62:81": "Hewlett-Packard",
    "F0:92:1C": "Hewlett-Packard",
    "F4:03:43": "Hewlett-Packard",
    "F4:CE:46": "Hewlett-Packard",
    "FC:15:B4": "Hewlett-Packard",
    "FC:3F:DB": "Hewlett-Packard",
    "FC:A8:41": "Hewlett-Packard",
    # ─── Hikvision / EZVIZ / HiLook (133 OUI blocks) ───────────────
    "00:0C:E5": "Hikvision",
    "00:BC:99": "Hikvision",
    "04:03:12": "Hikvision",
    "04:EE:CD": "Hikvision",
    "08:3B:C1": "Hikvision",
    "08:54:11": "Hikvision",
    "08:A1:89": "Hikvision",
    "08:CC:81": "Hikvision",
    "0C:75:D2": "Hikvision",
    "0C:A6:4C": "Hikvision",
    "10:12:FB": "Hikvision",
    "18:68:CB": "Hikvision",
    "18:80:25": "Hikvision",
    "20:BB:BC": "Hikvision",
    "24:0F:9B": "Hikvision",
    "24:28:FD": "Hikvision",
    "24:32:AE": "Hikvision",
    "24:48:45": "Hikvision",
    "24:B1:05": "Hikvision",
    "28:57:BE": "Hikvision",
    "2C:A5:9C": "Hikvision",
    "34:09:62": "Hikvision",
    "34:C6:DD": "Hikvision",
    "3C:1B:F8": "Hikvision",
    "40:AC:BF": "Hikvision",
    "40:B5:70": "Hikvision",
    "44:19:B6": "Hikvision",
    "44:47:CC": "Hikvision",
    "44:A6:42": "Hikvision",
    "48:78:5B": "Hikvision",
    "4C:1F:86": "Hikvision",
    "4C:62:DF": "Hikvision",
    "4C:BD:8F": "Hikvision",
    "4C:F5:DC": "Hikvision",
    "50:E5:38": "Hikvision",
    "54:8C:81": "Hikvision",
    "54:C4:15": "Hikvision",
    "54:D6:0D": "Hikvision",
    "58:03:FB": "Hikvision",
    "58:50:ED": "Hikvision",
    "58:8F:CF": "Hikvision",
    "5C:34:5B": "Hikvision",
    "5C:DD:70": "Hikvision",
    "60:08:91": "Hikvision",
    "64:24:4D": "Hikvision",
    "64:7E:B0": "Hikvision",
    "64:DB:8B": "Hikvision",
    "64:F2:FB": "Hikvision",
    "68:6D:BC": "Hikvision",
    "6C:EF:C6": "Hikvision",
    "70:2E:80": "Hikvision",
    "74:3F:C2": "Hikvision",
    "74:DA:88": "Hikvision",
    "78:07:54": "Hikvision",
    "78:A6:A0": "Hikvision",
    "78:C1:AE": "Hikvision",
    "7C:09:12": "Hikvision",
    "7C:F3:4A": "Hikvision",
    "80:48:9F": "Hikvision",
    "80:7C:62": "Hikvision",
    "80:A2:35": "Hikvision",
    "80:BE:AF": "Hikvision",
    "80:F5:AE": "Hikvision",
    "84:94:59": "Hikvision",
    "84:9A:40": "Hikvision",
    "84:E0:F4": "Hikvision",
    "88:40:33": "Hikvision",
    "88:DE:39": "Hikvision",
    "8C:22:D2": "Hikvision",
    "8C:E7:48": "Hikvision",
    "90:02:A9": "Hikvision",
    "94:E1:AC": "Hikvision",
    "94:EC:13": "Hikvision",
    "98:0D:67": "Hikvision",
    "98:8B:0A": "Hikvision",
    "98:9D:E5": "Hikvision",
    "98:DF:82": "Hikvision",
    "98:F1:12": "Hikvision",
    "98:F6:21": "Hikvision",
    "A0:CC:2B": "Hikvision",
    "A0:FF:0C": "Hikvision",
    "A4:14:37": "Hikvision",
    "A4:29:02": "Hikvision",
    "A4:4B:D9": "Hikvision",
    "A4:A4:59": "Hikvision",
    "A4:D5:C2": "Hikvision",
    "AC:1C:26": "Hikvision",
    "AC:1D:DF": "Hikvision",
    "AC:B9:2F": "Hikvision",
    "AC:CB:51": "Hikvision",
    "B0:3A:F2": "Hikvision",
    "B4:A3:82": "Hikvision",
    "BC:29:78": "Hikvision",
    "BC:5E:33": "Hikvision",
    "BC:9B:5E": "Hikvision",
    "BC:AD:28": "Hikvision",
    "BC:BA:C2": "Hikvision",
    "C0:2C:5C": "Hikvision",
    "C0:51:7E": "Hikvision",
    "C0:56:E3": "Hikvision",
    "C0:6D:ED": "Hikvision",
    "C4:2F:90": "Hikvision",
    "C4:A3:6E": "Hikvision",
    "C8:A7:02": "Hikvision",
    "CC:13:F3": "Hikvision",
    "CC:D3:9D": "Hikvision",
    "D0:67:26": "Hikvision",
    "D4:6D:6D": "Hikvision",
    "D4:E8:53": "Hikvision",
    "D8:E0:E1": "Hikvision",
    "DC:07:F8": "Hikvision",
    "DC:D2:6A": "Hikvision",
    "DC:E5:33": "Hikvision",
    "E0:2B:96": "Hikvision",
    "E0:50:8B": "Hikvision",
    "E0:BA:AD": "Hikvision",
    "E0:CA:3C": "Hikvision",
    "E0:DF:13": "Hikvision",
    "E4:3E:D7": "Hikvision",
    "E4:D5:8B": "Hikvision",
    "E8:A0:ED": "Hikvision",
    "EC:3E:F7": "Hikvision",
    "EC:72:40": "Hikvision",
    "EC:97:E0": "Hikvision",
    "EC:A9:71": "Hikvision",
    "EC:C8:9C": "Hikvision",
    "F4:66:0E": "Hikvision",
    "F4:70:18": "Hikvision",
    "F8:36:9B": "Hikvision",
    "F8:4D:FC": "Hikvision",
    "FC:24:22": "Hikvision",
    "FC:8B:97": "Hikvision",
    "FC:9F:FD": "Hikvision",
    # ─── Fortinet ───────────────────────────────────────────────────
    "04:01:A1": "Fortinet",
    "70:4C:A5": "Fortinet",
    "00:09:0F": "Fortinet",
    # ─── Dahua Technology ───────────────────────────────────────────
    "3C:EF:8C": "Dahua",
    "40:34:8E": "Dahua",
    "4C:11:BF": "Dahua",
    "80:00:0B": "Dahua",
    "90:02:A9": "Dahua",
    "9C:14:63": "Dahua",
    "A0:BD:1D": "Dahua",
    "B0:A7:B9": "Dahua",
    "BC:32:5F": "Dahua",
    "C8:B6:D3": "Dahua",
    "D4:43:A8": "Dahua",
    "E0:50:8B": "Dahua",
    "E4:24:6C": "Dahua",
    "E4:4E:2D": "Dahua",
    "F8:4D:FC": "Dahua",
    "FC:5A:1D": "Dahua",
    "14:A7:8B": "Dahua",
    "20:17:11": "Dahua",
    "24:2C:E4": "Dahua",
    "3C:DA:2A": "Dahua",
    "48:E8:DB": "Dahua",
    "54:83:3A": "Dahua",
    "58:10:8C": "Dahua",
    "A0:39:EE": "Dahua",
    # ─── Axis Communications (IP Camera) ───────────────────────────
    "00:40:8C": "Axis Communications",
    "AC:CC:8E": "Axis Communications",
    "B8:A4:4F": "Axis Communications",
    "D4:81:D7": "Axis Communications",
    "00:1A:07": "Axis Communications",
    # ─── Uniview ───────────────────────────────────────────────────
    "54:F0:06": "Uniview",
    "24:24:05": "Uniview",
    "44:15:2B": "Uniview",
    "70:2D:84": "Uniview",
    "74:0A:E1": "Uniview",
    # ─── HiLook (Hikvision sub-brand) ─────────────────────────────
    "BC:AD:28": "HiLook/Hikvision",
}


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
║     ███╗   ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗    ║
║     ████╗  ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║    ║
║     ██╔██╗ ██║█████╗      ███████╗██║     ███████║██╔██╗ ██║    ║
║     ██║╚██╗██║██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║    ║
║     ██║ ╚████║███████╗    ███████║╚██████╗██║  ██║██║ ╚████║    ║
║     ╚═╝  ╚═══╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ║
║                                                                  ║
║           {Colors.YELLOW}Network Equipment Scanner v2.0{Colors.CYAN}                        ║
║           {Colors.DIM}Scan · Discover · Identify{Colors.RESET}{Colors.CYAN}{Colors.BOLD}                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)


def get_local_ip():
    """ดึง IP ของเครื่องปัจจุบัน"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ping_host(ip_str, timeout=1):
    """Ping ไปยัง host เพื่อเช็คว่าออนไลน์หรือไม่"""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip_str]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout * 1000), ip_str]
    else:  # Linux
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip_str]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 2
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False


def get_mac_address(ip_str):
    """ดึง MAC Address จาก ARP table"""
    system = platform.system().lower()
    try:
        if system == "windows":
            result = subprocess.run(
                ["arp", "-a", ip_str],
                capture_output=True, text=True, timeout=5
            )
            # Windows ARP format: 192.168.1.1   00-aa-bb-cc-dd-ee   dynamic
            match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", result.stdout)
        else:
            result = subprocess.run(
                ["arp", "-n", ip_str],
                capture_output=True, text=True, timeout=5
            )
            # macOS/Linux ARP format
            match = re.search(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}", result.stdout)

        if match:
            mac = match.group(0).upper()
            # Normalize: ensure each octet is 2 digits, use colon
            parts = re.split(r'[:-]', mac)
            mac = ":".join(p.zfill(2) for p in parts)
            return mac
    except Exception:
        pass
    return "N/A"


def get_hostname(ip_str):
    """แปลง IP เป็น Hostname (Reverse DNS)"""
    try:
        hostname = socket.gethostbyaddr(ip_str)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return "N/A"


def lookup_vendor(mac_address):
    """หา Vendor จาก OUI (รองรับ 4 octets, 3.5 octets, 3 octets และ 2 octets)"""
    if mac_address == "N/A":
        return "Unknown"

    mac_upper = mac_address.upper()

    # ลอง match 4 octets (11 ตัวอักษร e.g. "68:DA:73:AB")
    prefix_4 = mac_upper[:11]
    if prefix_4 in OUI_DATABASE:
        return OUI_DATABASE[prefix_4]

    # ลอง match 3.5 octets (10 ตัวอักษร e.g. "68:DA:73:A")
    prefix_3_5 = mac_upper[:10]
    if prefix_3_5 in OUI_DATABASE:
        return OUI_DATABASE[prefix_3_5]

    # ลอง match 3 octets (8 ตัวอักษร e.g. "00:50:56")
    prefix_3 = mac_upper[:8]
    if prefix_3 in OUI_DATABASE:
        return OUI_DATABASE[prefix_3]

    # ลอง match 2 octets (5 ตัวอักษร e.g. "02:42")
    prefix_2 = mac_upper[:5]
    if prefix_2 in OUI_DATABASE:
        return OUI_DATABASE[prefix_2]

    return "Unknown"


def detect_device_type(hostname, vendor, open_ports=None):
    """คาดเดาประเภทอุปกรณ์จากข้อมูลที่มี"""
    hostname_lower = hostname.lower() if hostname != "N/A" else ""
    vendor_lower = vendor.lower()

    # ─── IP Camera / CCTV (ตรวจจับก่อน เพราะเป็นงานหลัก) ─────────
    camera_vendors = ["hikvision", "hilook", "dahua", "axis communications", "uniview"]
    camera_hostnames = ["ipcam", "camera", "nvr", "dvr", "hik", "dahua", "cam-", "cam.", "hikvision", "hikv"]
    if any(kw in vendor_lower for kw in camera_vendors):
        brand = vendor.split('/')[0] if '/' in vendor else vendor
        return f"📹 IP Camera ({brand})"
    if any(kw in hostname_lower for kw in camera_hostnames):
        return "📹 IP Camera/NVR"

    # Router/Gateway
    router_keywords = ["gateway", "router", "gw", "mikrotik", "ubiquiti", "openwrt"]
    if any(kw in hostname_lower for kw in router_keywords):
        return "🌐 Router/Gateway"
    if any(kw in vendor_lower for kw in ["cisco", "mikrotik", "juniper",
           "ubiquiti", "linksys", "netgear", "tp-link", "d-link", "asus router"]):
        return "🌐 Router/Switch"

    # Access Point
    ap_keywords = ["ap", "access", "wifi", "wireless"]
    if any(kw in hostname_lower for kw in ap_keywords):
        return "📡 Access Point"

    # Printer
    printer_keywords = ["printer", "print", "prn", "hp-", "epson", "canon", "brother"]
    if any(kw in hostname_lower for kw in printer_keywords):
        return "🖨️  Printer"

    # Server
    server_keywords = ["server", "srv", "nas", "storage", "esxi", "vcenter", "dc-", "ad-"]
    if any(kw in hostname_lower for kw in server_keywords):
        return "🖥️  Server"
    if any(kw in vendor_lower for kw in ["dell", "ibm", "hewlett", "supermicro"]):
        return "🖥️  Server/Workstation"

    # Virtual Machine
    vm_keywords = ["vm", "virtual"]
    if any(kw in hostname_lower for kw in vm_keywords) or any(
            kw in vendor_lower for kw in ["vmware", "virtualbox", "qemu", "kvm", "xen", "hyper-v"]):
        return "☁️  Virtual Machine"

    # Docker
    if "docker" in vendor_lower:
        return "🐳 Docker Container"

    # Mobile
    mobile_keywords = ["iphone", "ipad", "android", "galaxy", "pixel", "oneplus"]
    if any(kw in hostname_lower for kw in mobile_keywords):
        return "📱 Mobile Device"
    if any(kw in vendor_lower for kw in ["samsung", "xiaomi", "huawei", "sony", "oneplus"]):
        return "📱 Mobile/IoT Device"

    # Apple Device
    if "apple" in vendor_lower:
        if any(kw in hostname_lower for kw in ["macbook", "imac", "mac-", "mac."]):
            return "💻 Mac Computer"
        return "🍎 Apple Device"

    # Raspberry Pi
    if "raspberry" in vendor_lower:
        return "🍓 Raspberry Pi"

    # Intel Desktop/Laptop
    if "intel" in vendor_lower:
        return "💻 PC/Laptop"

    # ASUSTek
    if "asustek" in vendor_lower:
        return "💻 PC/Router (ASUS)"

    # Realtek
    if "realtek" in vendor_lower:
        return "💻 PC/Embedded"

    # Sun/Oracle
    if "sun" in vendor_lower or "oracle" in vendor_lower:
        return "🖥️  Server (Oracle/Sun)"

    # Unknown
    if vendor != "Unknown":
        return f"📦 Device ({vendor})"

    return "❓ Unknown Device"


def detect_windows_version(ip_str):
    """ระบุ Windows Version รายละเอียดผ่าน HTTP IIS Header หรือ SMB/RPC Probe"""
    # 1. Probe HTTP Server Header (Microsoft-IIS)
    for port in (80, 443, 8080, 8000):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                s.connect((ip_str, port))
                s.sendall(f"HEAD / HTTP/1.1\r\nHost: {ip_str}\r\nConnection: close\r\n\r\n".encode())
                data = s.recv(1024).decode('utf-8', errors='ignore')
                iis_match = re.search(r'Server:\s*Microsoft-IIS/([\d\.]+)', data, re.IGNORECASE)
                if iis_match:
                    ver = iis_match.group(1)
                    if ver == "10.0":
                        return "Windows 10/11/Server 2016+"
                    elif ver == "8.5":
                        return "Windows 8.1 / Server 2012 R2"
                    elif ver == "8.0":
                        return "Windows 8 / Server 2012"
                    elif ver == "7.5":
                        return "Windows 7 / Server 2008 R2"
                    elif ver == "7.0":
                        return "Windows Vista / Server 2008"
                    elif ver == "6.0":
                        return "Windows Server 2003"
                    return f"Windows (IIS/{ver})"
        except Exception:
            pass

    # 2. Probe SMB / NetBIOS (Port 445 / 139)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex((ip_str, 445)) == 0:
                neg_req = b"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x0c\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
                s.sendall(neg_req)
                resp = s.recv(1024)
                resp_str = resp.decode('latin1', errors='ignore')
                if "Windows 10" in resp_str or "Windows 11" in resp_str:
                    return "Windows 10/11"
                elif "Windows Server 2022" in resp_str or "Windows Server 2019" in resp_str:
                    return "Windows Server 2019/2022"
                elif "Windows Server 2016" in resp_str:
                    return "Windows Server 2016"
                elif "Windows 7" in resp_str or "Server 2008 R2" in resp_str:
                    return "Windows 7 / Server 2008 R2"
                elif "Windows 8" in resp_str or "Server 2012" in resp_str:
                    return "Windows 8 / Server 2012"
                return "Windows (SMB)"
    except Exception:
        pass

    return "Windows"


def detect_os_ttl(ip_str, timeout=1):
    """ตรวจสอบ OS จาก TTL ของ ping response พร้อมระบุรายละเอียด Windows Version"""
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip_str]
        elif system == "darwin":
            cmd = ["ping", "-c", "1", "-W", str(timeout * 1000), ip_str]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), ip_str]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2)
        output = result.stdout.decode('utf-8', errors='ignore')

        ttl_match = re.search(r'ttl[=\s](\d+)', output, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return detect_windows_version(ip_str)
            elif ttl <= 255:
                return "Network Device"
    except Exception:
        pass
    return "Unknown"


def check_port_open(ip_str, ports=(80, 443, 554, 8000, 37777, 8080, 445, 22, 139), timeout=0.2):
    """เช็คว่าเปิดพอร์ตที่ใช้บ่อยหรือไม่ (สำหรับเครื่อง/กล้องที่บล็อก ICMP Ping)"""
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip_str, port)) == 0:
                    return True
        except Exception:
            pass
    return False


def scan_host(ip_str):
    """สแกน host เดียว - คืนค่าผลลัพธ์แบบ Multi-stage (Ping -> TCP Probe -> ARP Check)"""
    online = ping_host(ip_str)

    # หาก Ping ไม่ตอบสนอง ลองตรวจจับด้วย TCP Port Probe (สำหรับอุปกรณ์ที่ตั้ง Firewall บล็อก Ping)
    if not online:
        if check_port_open(ip_str):
            online = True

    # ดึง MAC Address จาก ARP Table
    mac = get_mac_address(ip_str)

    # หากมีข้อมูลใน ARP Table แปลว่าอุปกรณ์เชื่อมต่อบน LAN จริง
    if not online and mac != "N/A" and mac != "00:00:00:00:00:00":
        online = True

    if online:
        hostname = get_hostname(ip_str)
        vendor = lookup_vendor(mac)
        device_type = detect_device_type(hostname, vendor)
        os_guess = detect_os_ttl(ip_str)
        return {
            "ip": ip_str,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "device_type": device_type,
            "os": os_guess,
            "status": "Online"
        }
    return None


def get_subnet_class(ip_str):
    """คืนค่า class ของ IP"""
    first_octet = int(ip_str.split('.')[0])
    if first_octet < 128:
        return "A", "/8", 16777214
    elif first_octet < 192:
        return "B", "/16", 65534
    elif first_octet < 224:
        return "C", "/24", 254
    else:
        return "D/E", "N/A", 0


def parse_target(target_input):
    """แปลง input ของผู้ใช้เป็น list ของ IP addresses"""
    ips = []

    target_input = target_input.strip()

    # CIDR notation (e.g., 192.168.1.0/24)
    if '/' in target_input:
        try:
            network = ipaddress.ip_network(target_input, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        except ValueError as e:
            print(f"{Colors.RED}  ❌ Invalid CIDR: {e}{Colors.RESET}")
            return []

    # Range notation (e.g., 192.168.1.1-254)
    elif '-' in target_input:
        try:
            parts = target_input.split('-')
            base_ip_parts = parts[0].strip().split('.')
            end = int(parts[1].strip())

            if len(base_ip_parts) == 4:
                start = int(base_ip_parts[3])
                base = '.'.join(base_ip_parts[:3])
                for i in range(start, end + 1):
                    if 0 <= i <= 255:
                        ips.append(f"{base}.{i}")
            else:
                print(f"{Colors.RED}  ❌ Invalid range format{Colors.RESET}")
        except (ValueError, IndexError):
            print(f"{Colors.RED}  ❌ Invalid range format. Use: 192.168.1.1-254{Colors.RESET}")

    # Single IP
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target_input):
        ips = [target_input]

    # Partial IP with wildcard (e.g., 192.168.1.*)
    elif '*' in target_input:
        base = target_input.replace('*', '').rstrip('.')
        octets = base.split('.')
        if len(octets) == 3:
            for i in range(1, 255):
                ips.append(f"{base}.{i}")
        elif len(octets) == 2:
            for j in range(0, 256):
                for i in range(1, 255):
                    ips.append(f"{base}.{j}.{i}")
        else:
            print(f"{Colors.RED}  ❌ Invalid wildcard format{Colors.RESET}")

    else:
        print(f"{Colors.RED}  ❌ Cannot parse target: {target_input}{Colors.RESET}")

    return ips


def print_results_table(results):
    """แสดงผลลัพธ์เป็นตาราง"""
    if not results:
        print(f"\n{Colors.YELLOW}  ⚠️  ไม่พบอุปกรณ์ที่ออนไลน์ในช่วง IP ที่ระบุ{Colors.RESET}")
        return

    results.sort(key=lambda x: [int(p) for p in x['ip'].split('.')])

    ip_w = max(max(len(r['ip']) for r in results), 15)
    mac_w = 17
    host_w = min(max(max(len(r['hostname']) for r in results), 10), 30)
    vendor_w = min(max(max(len(r['vendor']) for r in results), 8), 18)
    os_w = min(max(max(len(r.get('os', '')) for r in results), 10), 14)
    type_w = min(max(max(len(r['device_type']) for r in results), 15), 28)

    total_w = ip_w + mac_w + host_w + vendor_w + os_w + type_w + 25

    print(f"\n{Colors.CYAN}{Colors.BOLD}  {'─' * total_w}{Colors.RESET}")
    print(f"  {Colors.BOLD}{Colors.CYAN}"
          f"{'IP Address':<{ip_w}}  {'MAC Address':<{mac_w}}  "
          f"{'Hostname':<{host_w}}  {'OS':<{os_w}}  "
          f"{'Vendor':<{vendor_w}}  {'Device Type':<{type_w}}"
          f"{Colors.RESET}")
    print(f"{Colors.CYAN}  {'─' * total_w}{Colors.RESET}")

    for r in results:
        hostname_d = r['hostname'][:host_w]
        vendor_d = r['vendor'][:vendor_w]
        type_d = r['device_type'][:type_w]
        os_d = r.get('os', 'Unknown')[:os_w]

        os_color = Colors.BLUE
        if 'Windows' in os_d:
            os_color = Colors.CYAN
        elif 'Linux' in os_d:
            os_color = Colors.GREEN
        elif 'Network' in os_d:
            os_color = Colors.YELLOW

        print(f"  {Colors.GREEN}{r['ip']:<{ip_w}}{Colors.RESET}  "
              f"{Colors.YELLOW}{r['mac']:<{mac_w}}{Colors.RESET}  "
              f"{Colors.BLUE}{hostname_d:<{host_w}}{Colors.RESET}  "
              f"{os_color}{os_d:<{os_w}}{Colors.RESET}  "
              f"{Colors.DIM}{vendor_d:<{vendor_w}}{Colors.RESET}  "
              f"{type_d}")

    print(f"{Colors.CYAN}  {'─' * total_w}{Colors.RESET}")

    # ─── OS Summary ─────────────────────────────────────────────
    os_count = {}
    for r in results:
        os_n = r.get('os', 'Unknown')
        os_count[os_n] = os_count.get(os_n, 0) + 1

    print(f"\n  {Colors.BOLD}OS Summary:{Colors.RESET} ", end="")
    for os_name, count in sorted(os_count.items(), key=lambda x: -x[1]):
        print(f"{Colors.CYAN}{os_name}{Colors.RESET}: {Colors.BOLD}{count}{Colors.RESET}  ", end="")
    print()


def export_results(results, filename):
    """บันทึกผลลัพธ์เป็นไฟล์ CSV หรือ JSON"""
    if filename.endswith('.json'):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    else:
        if not filename.endswith('.csv'):
            filename += '.csv'
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("IP Address,MAC Address,Hostname,Vendor,Device Type,Status\n")
            for r in results:
                # ลบ emoji ออกจาก device_type สำหรับ CSV
                device = re.sub(r'[^\x00-\x7F]+', '', r['device_type']).strip()
                f.write(f"{r['ip']},{r['mac']},{r['hostname']},{r['vendor']},{device},{r['status']}\n")

    print(f"\n{Colors.GREEN}  ✅ ผลลัพธ์ถูกบันทึกไปที่: {filename}{Colors.RESET}")


def run_scan(target_ips, max_threads=100):
    """สแกน IP ทั้งหมดแบบ multi-threaded"""
    total = len(target_ips)
    results = []
    scanned = 0

    print(f"\n{Colors.CYAN}  🔍 กำลังสแกน {total} hosts...{Colors.RESET}")
    print(f"{Colors.DIM}  ใช้ {min(max_threads, total)} threads{Colors.RESET}\n")

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_threads, total)) as executor:
        future_to_ip = {executor.submit(scan_host, ip): ip for ip in target_ips}

        for future in concurrent.futures.as_completed(future_to_ip):
            scanned += 1
            result = future.result()
            if result:
                results.append(result)
                # แสดงผลแบบ real-time
                print(f"  {Colors.GREEN}✓{Colors.RESET} [{scanned}/{total}] "
                      f"{Colors.GREEN}{result['ip']:<15}{Colors.RESET} "
                      f"{Colors.YELLOW}{result['mac']:<17}{Colors.RESET} "
                      f"{result['device_type']}")
            else:
                # Progress indicator ทุก ๆ 10%
                if scanned % max(1, total // 10) == 0:
                    pct = (scanned / total) * 100
                    print(f"  {Colors.DIM}  [{scanned}/{total}] ({pct:.0f}%) scanning...{Colors.RESET}")

    elapsed = time.time() - start_time
    print(f"\n{Colors.CYAN}  ⏱️  สแกนเสร็จใน {elapsed:.1f} วินาที{Colors.RESET}")
    print(f"{Colors.GREEN}  📊 พบอุปกรณ์ออนไลน์: {len(results)}/{total} hosts{Colors.RESET}")

    return results


def show_menu():
    """แสดงเมนูหลัก"""
    local_ip = get_local_ip()
    ip_class, cidr, host_count = get_subnet_class(local_ip)
    subnet_base = '.'.join(local_ip.split('.')[:3])

    print(f"""
{Colors.BOLD}  📡 ข้อมูลเครื่องปัจจุบัน:{Colors.RESET}
  {Colors.DIM}├─{Colors.RESET} IP Address : {Colors.GREEN}{local_ip}{Colors.RESET}
  {Colors.DIM}├─{Colors.RESET} Class      : {Colors.YELLOW}{ip_class}{Colors.RESET} ({cidr})
  {Colors.DIM}└─{Colors.RESET} Subnet     : {Colors.CYAN}{subnet_base}.0/24{Colors.RESET}

{Colors.BOLD}  🎯 เลือกโหมดการสแกน:{Colors.RESET}
  {Colors.CYAN}┌─────────────────────────────────────────────────────────┐{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[1]{Colors.RESET} สแกนทั้ง Subnet (/24) ── {subnet_base}.1-254         {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[2]{Colors.RESET} สแกนทั้ง Class B (/16) ── {'.'.join(local_ip.split('.')[:2])}.0.0/16      {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[3]{Colors.RESET} ระบุ IP/Range/CIDR เอง                           {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[4]{Colors.RESET} สแกน IP เดียว                                    {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[5]{Colors.RESET} แสดงวิธีใช้งาน                                   {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}[0]{Colors.RESET} ออกจากโปรแกรม                                    {Colors.CYAN}│{Colors.RESET}
  {Colors.CYAN}└─────────────────────────────────────────────────────────┘{Colors.RESET}
""")


def show_help():
    """แสดงวิธีใช้งาน"""
    print(f"""
{Colors.BOLD}{Colors.CYAN}  ═══════════════════ วิธีใช้งาน ═══════════════════{Colors.RESET}

  {Colors.BOLD}รูปแบบการระบุเป้าหมาย:{Colors.RESET}

  {Colors.GREEN}CIDR Notation:{Colors.RESET}
    192.168.1.0/24     → สแกน 192.168.1.1 - 192.168.1.254
    10.0.0.0/16        → สแกน 10.0.0.1 - 10.0.255.254
    172.16.0.0/12      → สแกน 172.16.0.1 - 172.31.255.254

  {Colors.GREEN}Range Notation:{Colors.RESET}
    192.168.1.1-254    → สแกน 192.168.1.1 ถึง 192.168.1.254
    10.0.0.100-200     → สแกน 10.0.0.100 ถึง 10.0.0.200

  {Colors.GREEN}Wildcard:{Colors.RESET}
    192.168.1.*        → สแกนทั้ง subnet (1-254)
    192.168.*.*        → สแกนทั้ง Class B

  {Colors.GREEN}Single IP:{Colors.RESET}
    192.168.1.1        → สแกน IP เดียว

  {Colors.BOLD}หมายเหตุ:{Colors.RESET}
  {Colors.YELLOW}• ต้องรันด้วยสิทธิ์ root/sudo เพื่อดึง MAC Address ได้ถูกต้อง{Colors.RESET}
  {Colors.YELLOW}• การสแกน Class B (/16) อาจใช้เวลานาน (65,534 hosts){Colors.RESET}
  {Colors.YELLOW}• Vendor ระบุจาก OUI Database ในตัว (อาจไม่ครอบคลุมทั้งหมด){Colors.RESET}

{Colors.CYAN}  ═══════════════════════════════════════════════════{Colors.RESET}
""")


def main():
    """ฟังก์ชันหลัก"""
    if platform.system().lower() == "windows":
        os.system("")  # Enable ANSI escape sequences in Windows CMD/PowerShell

    clear_screen()
    print_banner()

    # ตรวจสอบ root
    if platform.system().lower() != "windows" and hasattr(os, 'geteuid') and os.geteuid() != 0:
        print(f"{Colors.YELLOW}  ⚠️  แนะนำให้รันด้วย sudo เพื่อดึง MAC Address ได้ถูกต้อง{Colors.RESET}")
        print(f"{Colors.DIM}     $ sudo python3 {sys.argv[0]}{Colors.RESET}\n")

    while True:
        show_menu()
        choice = input(f"  {Colors.BOLD}เลือก [{Colors.CYAN}0-5{Colors.RESET}{Colors.BOLD}]: {Colors.RESET}").strip()

        if choice == '0':
            print(f"\n{Colors.CYAN}  👋 ขอบคุณที่ใช้งาน NE Scan!{Colors.RESET}\n")
            sys.exit(0)

        elif choice == '1':
            # Scan /24 subnet
            local_ip = get_local_ip()
            subnet = '.'.join(local_ip.split('.')[:3]) + '.0/24'
            target_ips = parse_target(subnet)

        elif choice == '2':
            # Scan /16 subnet
            local_ip = get_local_ip()
            subnet = '.'.join(local_ip.split('.')[:2]) + '.0.0/16'
            print(f"\n{Colors.YELLOW}  ⚠️  การสแกน /16 จะสแกน 65,534 hosts และใช้เวลานาน{Colors.RESET}")
            confirm = input(f"  {Colors.BOLD}ยืนยันหรือไม่? [y/N]: {Colors.RESET}").strip().lower()
            if confirm != 'y':
                continue
            target_ips = parse_target(subnet)

        elif choice == '3':
            # Custom target
            print(f"\n{Colors.BOLD}  ใส่เป้าหมาย:{Colors.RESET}")
            print(f"{Colors.DIM}  รูปแบบ: CIDR (10.0.0.0/24) | Range (10.0.0.1-100) | Wildcard (10.0.0.*){Colors.RESET}")
            target = input(f"  {Colors.BOLD}Target: {Colors.RESET}").strip()
            if not target:
                continue
            target_ips = parse_target(target)

        elif choice == '4':
            # Single IP
            ip = input(f"\n  {Colors.BOLD}ใส่ IP Address: {Colors.RESET}").strip()
            if not ip:
                continue
            target_ips = parse_target(ip)

        elif choice == '5':
            show_help()
            continue

        else:
            print(f"{Colors.RED}  ❌ ตัวเลือกไม่ถูกต้อง{Colors.RESET}")
            continue

        if not target_ips:
            continue

        # เลือกจำนวน threads
        thread_count = 100
        if len(target_ips) > 1000:
            thread_input = input(f"\n  {Colors.BOLD}จำนวน threads (default=200, max=500): {Colors.RESET}").strip()
            if thread_input.isdigit():
                thread_count = min(int(thread_input), 500)
            else:
                thread_count = 200

        # เริ่มสแกน
        results = run_scan(target_ips, max_threads=thread_count)

        # แสดงตาราง
        print_results_table(results)

        # ถามว่าต้องการ export หรือไม่
        if results:
            export_choice = input(f"\n  {Colors.BOLD}ต้องการบันทึกผลลัพธ์? [y/N]: {Colors.RESET}").strip().lower()
            if export_choice == 'y':
                filename = input(f"  {Colors.BOLD}ชื่อไฟล์ (default: scan_result.csv): {Colors.RESET}").strip()
                if not filename:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"scan_result_{timestamp}.csv"
                export_results(results, filename)

        print()  # เว้นบรรทัดก่อนกลับเมนู


if __name__ == "__main__":
    main()
