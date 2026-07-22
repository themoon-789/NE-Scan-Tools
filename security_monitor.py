#!/usr/bin/env python3
"""
Security & Privacy Monitoring Tool (Defensive Security Project)
==============================================================
เครื่องมือเฝ้าระวังและทดสอบความปลอดภัยสำหรับระบบ Windows:
1. Webcam & Microphone Access Monitor (ตรวจจับการเข้าถึงกล้อง/ไมค์)
2. Brute Force Log Detector (ตรวจจับการสุ่มรหัสผ่านจาก Event Log)

Usage:
    python security_monitor.py
"""

import os
import sys
import time
import json
import subprocess
import platform
from datetime import datetime

class Colors:
    HEADER    = '\033[95m'
    BLUE      = '\033[94m'
    CYAN      = '\033[96m'
    GREEN     = '\033[92m'
    YELLOW    = '\033[93m'
    RED       = '\033[91m'
    BOLD      = '\033[1m'
    DIM       = '\033[2m'
    RESET     = '\033[0m'

def run_powershell(command):
    """รันคำสั่ง PowerShell และคืนค่าผลลัพธ์"""
    try:
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception as e:
        return ""

def monitor_camera_mic_access():
    """ตรวจสอบว่ามีแอปพลิเคชันกำลังใช้งาน Camera หรือ Microphone อยู่หรือไม่ผ่าน Registry"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}📷 [Privacy Monitor] ตรวจสอบการใช้งาน Webcam & Microphone...{Colors.RESET}")
    
    ps_cmd_cam = """
    Get-ChildItem -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam' -ErrorAction SilentlyContinue | 
    ForEach-Object {
        $name = $_.PSChildName
        $prop = Get-ItemProperty -Path $_.PSPath
        if ($prop.LastUsedTimeStop -eq 0 -and $prop.LastUsedTimeStart -gt 0) {
            [PSCustomObject]@{ Device = 'Webcam'; App = $name; Status = 'ACTIVE' }
        }
    } | ConvertTo-Json
    """
    
    ps_cmd_mic = """
    Get-ChildItem -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone' -ErrorAction SilentlyContinue | 
    ForEach-Object {
        $name = $_.PSChildName
        $prop = Get-ItemProperty -Path $_.PSPath
        if ($prop.LastUsedTimeStop -eq 0 -and $prop.LastUsedTimeStart -gt 0) {
            [PSCustomObject]@{ Device = 'Microphone'; App = $name; Status = 'ACTIVE' }
        }
    } | ConvertTo-Json
    """

    cam_output = run_powershell(ps_cmd_cam)
    mic_output = run_powershell(ps_cmd_mic)

    active_found = False

    for device_name, output in [("Webcam", cam_output), ("Microphone", mic_output)]:
        if output and output != "[]":
            try:
                data = json.loads(output)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    active_found = True
                    print(f"  {Colors.RED}{Colors.BOLD}🚨 [ALERT] พบอุปกรณ์ {device_name} กำลังถูกใช้งาน!{Colors.RESET}")
                    print(f"     Application: {Colors.YELLOW}{item.get('App')}{Colors.RESET}")
            except Exception:
                pass

    if not active_found:
        print(f"  {Colors.GREEN}✓ ไม่พบแอปพลิเคชันที่กำลังเปิดใช้งานกล้องหรือไมโครโฟนในขณะนี้{Colors.RESET}")

def detect_brute_force_events(threshold=5):
    """ตรวจสอบ Event ID 4625 (Failed Logon) ใน Windows Security Event Log"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}🔐 [Brute Force Detector] ตรวจสอบ Failed Login Events (Event ID 4625)...{Colors.RESET}")
    
    ps_cmd = f"""
    Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625}} -MaxEvents 50 -ErrorAction SilentlyContinue | 
    Group-Object -Property @{{$_.Properties[19].Value}} | 
    Select-Object Name, Count | ConvertTo-Json
    """
    
    output = run_powershell(ps_cmd)
    
    if not output or output == "[]":
        print(f"  {Colors.GREEN}✓ ไม่ประวัติพบการสุ่มรหัสผ่านล้มเหลวที่ผิดปกติใน Security Log{Colors.RESET}")
        return

    try:
        data = json.loads(output)
        items = data if isinstance(data, list) else [data]
        suspicious = False
        
        for item in items:
            ip = item.get("Name") or "Local/Unknown"
            count = item.get("Count", 0)
            if count >= threshold:
                suspicious = True
                print(f"  {Colors.RED}{Colors.BOLD}🚨 [WARNING] ตรวจพบแนวโน้มการ Brute Force / Login Failed สูงผิดปกติ!{Colors.RESET}")
                print(f"     Source IP / Account: {Colors.YELLOW}{ip}{Colors.RESET}")
                print(f"     Failed Attempts    : {Colors.RED}{count} ครั้ง{Colors.RESET}")
                print(f"     คำแนะนำ           : บล็อก IP ดังกล่าวบน Firewall หรือตรวจสอบนโยบาย Account Lockout\n")
        
        if not suspicious:
            print(f"  {Colors.GREEN}✓ จำนวนครั้งการใส่รหัสผิดอยู่ในเกณฑ์ปกติ (ต่ำกว่า Threshold {threshold} ครั้ง){Colors.RESET}")
    except Exception:
        print(f"  {Colors.DIM}  (ต้องรันด้วยสิทธิ์ Administrator เพื่ออ่าน Windows Security Log){Colors.RESET}")

def main():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     Security Monitoring & Privacy Audit Toolkit v1.0             ║
║     (Defensive Project Tool for Privacy & Audit)                 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}""")

    if platform.system().lower() != "windows":
        print(f"{Colors.YELLOW}  ⚠️  เครื่องมือนี้ออกแบบมาสำหรับรันบน Windows OS{Colors.RESET}\n")

    monitor_camera_mic_access()
    detect_brute_force_events()

if __name__ == "__main__":
    main()
