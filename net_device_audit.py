#!/usr/bin/env python3
"""
Network Device Security Audit Tool
================══════════════════
สคริปต์ตรวจสอบความปลอดภัยและการตั้งค่าอุปกรณ์ Network (Router/Switch/Firewall)
เน้นตรวจสอบการตั้งค่า Management Service, SNMP, และ Protocol ความเสี่ยงสูง

Usage:
    python3 net_device_audit.py -t 192.168.1.1
"""

import socket
import ssl
import sys
import time
import os
import argparse
import concurrent.futures
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


def is_port_open(ip, port, timeout=2):
    """เช็คสถานะการเปิดของ Port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        res = sock.connect_ex((ip, port))
        sock.close()
        return res == 0
    except Exception:
        return False


def check_snmp_community(ip, community="public", timeout=2):
    """ทดสอบส่ง SNMP v1/v2c GetRequest แพ็กเกจพื้นฐานเพื่อเช็ค Default Community String"""
    # SNMP v1/v2c GetRequest packet for OID 1.3.6.1.2.1.1.1.0 (sysDescr)
    # Hex representation for UDP packet with community string
    comm_bytes = community.encode()
    comm_len = len(comm_bytes)

    # Simple SNMP v2c GetRequest UDP Payload Template
    packet = bytearray([
        0x30, 0x00,  # Sequence header (length will be set)
        0x02, 0x01, 0x01,  # Version: v2c (1)
        0x04, comm_len  # Community string header
    ]) + comm_bytes + bytearray([
        0xa0, 0x1b,  # PDU Type: GetRequest
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # Request ID
        0x02, 0x01, 0x00,  # Error Status: 0
        0x02, 0x01, 0x00,  # Error Index: 0
        0x30, 0x0e,  # Varbind List
        0x30, 0x0c,  # Varbind
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # OID 1.3.6.1.2.1.1.1.0
        0x05, 0x00  # Value: Null
    ])

    # Fix packet length
    packet[1] = len(packet) - 2

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 161))
        data, addr = sock.recvfrom(1024)
        sock.close()
        return True if data else False
    except Exception:
        return False


def audit_network_device(ip):
    print(f"\n{Colors.CYAN}{Colors.BOLD}🔍 เริ่มตรวจสอบอุปกรณ์ Network เป้าหมาย: {Colors.GREEN}{ip}{Colors.RESET}")
    print("=" * 65)

    results = []

    # 1. Management Ports Audit
    mgmt_ports = {
        23: ("Telnet", "CRITICAL", "พบการเปิดโปรโตคอล Telnet ข้อมูลส่งเป็น Plaintext เสี่ยงถูกดักจับรหัสผ่าน", "ปิด Telnet และเปลี่ยนไปใช้ SSHv2 เท่านั้น"),
        80: ("HTTP Web Admin", "HIGH", "พบ Web Management ผ่าน HTTP ( unencrypted )", "เปิดใช้ HTTPS (443) และปิด HTTP หรือตั้ง Redirect ไปยัง HTTPS"),
        21: ("FTP", "HIGH", "พบบริการ FTP เปิดใช้งานสำหรับโอนย้ายไฟล์/Config", "เปลี่ยนไปใช้ SFTP หรือ SCP ที่มีความปลอดภัยสูงกว่า"),
        22: ("SSH", "INFO", "บริการ SSH เปิดใช้งานอยู่", "ตรวจสอบว่าใช้ SSHv2 และปิดอัลกอริทึมเข้ารหัสเก่า (Weak Ciphers)"),
        443: ("HTTPS Web Admin", "INFO", "บริการ Web Admin ผ่าน HTTPS เปิดใช้งานอยู่", "ตรวจสอบความถูกต้องของ SSL/TLS Certificate และปิด TLS 1.0/1.1"),
        8291: ("MikroTik Winbox", "MEDIUM", "พบพอร์ต Winbox เปิดอยู่", "จำกัด IP ที่อนุญาตให้เข้าถึง Winbox ผ่าน Firewall/IP Service List"),
    }

    print(f"  {Colors.BOLD}[1] ตรวจสอบบริการการบริหารจัดการ (Management Services){Colors.RESET}")
    for port, (name, sev, desc, rec) in mgmt_ports.items():
        if is_port_open(ip, port):
            color = Colors.RED if sev in ["CRITICAL", "HIGH"] else (Colors.YELLOW if sev == "MEDIUM" else Colors.GREEN)
            print(f"   {color}• [{sev}] Port {port} ({name}) เปิดใช้งานอยู่{Colors.RESET}")
            print(f"     รายละเอียด: {desc}")
            print(f"     คำแนะนำ   : {rec}\n")
            results.append({"type": "Management Port", "port": port, "service": name,
                           "severity": sev, "issue": desc, "recommendation": rec})

    # 2. SNMP Security Audit
    print(f"  {Colors.BOLD}[2] ตรวจสอบความปลอดภัยบริการ SNMP (Port 161 UDP){Colors.RESET}")
    common_communities = ["public", "private", "community", "cisco", "read", "write", "admin"]
    snmp_found = False

    for comm in common_communities:
        if check_snmp_community(ip, comm):
            snmp_found = True
            print(f"   {Colors.RED}• [CRITICAL] พบ Default SNMP Community String: '{comm}'{Colors.RESET}")
            print(f"     รายละเอียด: ผู้โจมตีสามารถอ่านข้อมูลโครงสร้างเครือข่ายและระบบจาก SNMP ได้")
            print(f"     คำแนะนำ   : เปลี่ยน Community String เป็นคำที่ซับซ้อน หรืออัปเกรดไปใช้ SNMPv3 (มี Encryption + Auth)\n")
            results.append({"type": "SNMP",
                            "severity": "CRITICAL",
                            "issue": f"Default Community String '{comm}' ใช้งานได้",
                            "recommendation": "อัปเกรดเป็น SNMPv3 หรือเปลี่ยนชื่อ String"})

    if not snmp_found:
        print(f"   {Colors.GREEN}✓ ไม่พบ Default SNMP Community String ทั่วไป (หรือบริการถูกปิดอยู่){Colors.RESET}\n")

    # Summary
    print("=" * 65)
    print(f"{Colors.BOLD}📊 สรุปผลการตรวจสอบอุปกรณ์ Network ({ip}){Colors.RESET}")
    print(f"   พบประเด็นความเสี่ยงทั้งหมด: {len(results)} รายการ")

    return results


def main():
    parser = argparse.ArgumentParser(description="Network Device Security Audit Tool")
    parser.add_argument("-t", "--target", required=True, help="IP ของอุปกรณ์ Network เป้าหมาย")
    args = parser.parse_args()

    audit_network_device(args.target)


if __name__ == "__main__":
    main()
