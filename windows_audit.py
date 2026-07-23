#!/usr/bin/env python3
"""
Windows Security Hardening & Audit Tool
=======================================
โปรแกรมตรวจสอบการตั้งค่าความปลอดภัยบนระบบปฏิบัติการ Windows (Defensive Audit)
ช่วยประเมินความเสี่ยงและตรวจสอบจุดตั้งค่าที่ผิดพลาด (Misconfiguration)

ข้อแนะนำ: ควร รันบน Windows ด้วยสิทธิ์ Administrator
Usage:
    python windows_audit.py
"""

import os
import sys
import json
import subprocess
import platform
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


def run_powershell(command):
    """รันคำสั่ง PowerShell และคืนค่าผลลัพธ์แบบ string"""
    try:
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return result.stdout.strip()
    except Exception as e:
        return f"Error: {str(e)}"


def check_windows_version():
    """ตรวจสอบ Windows Version และ Build Number"""
    if platform.system().lower() != "windows":
        os_info = f"{platform.system()} {platform.release()} (Architecture: {platform.machine()})"
        return {
            "status": "PASS",
            "severity": "INFO",
            "detail": f"ระบบปฏิบัติการปัจจุบัน: {os_info}",
            "recommendation": "ไม่ต้องดำเนินการใดๆ"
        }

    ps_cmd = "(Get-CimInstance Win32_OperatingSystem) | Select-Object Caption, Version, BuildNumber, OSArchitecture | ConvertTo-Json"
    output = run_powershell(ps_cmd)

    if output and "Error" not in output:
        try:
            data = json.loads(output)
            caption = data.get("Caption", "Windows").strip()
            version = data.get("Version", "").strip()
            build = data.get("BuildNumber", "").strip()
            arch = data.get("OSArchitecture", "").strip()

            disp_ver_cmd = "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').DisplayVersion"
            disp_ver = run_powershell(disp_ver_cmd)
            disp_str = f" {disp_ver}" if disp_ver and "Error" not in disp_ver else ""

            details = f"{caption}{disp_str} (Version: {version}, Build: {build}, Arch: {arch})"

            is_end_of_life = any(legacy in caption for legacy in ["Windows 7", "Windows 8", "Windows XP", "Server 2008", "Server 2003"])
            if is_end_of_life:
                return {
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "detail": f"{details} — Windows รุ่นนี้หมดการซัพพอร์ต (End of Life)",
                    "recommendation": "อัพเกรดเป็น Windows 10/11 หรือ Windows Server 2019/2022 เพื่อรับ Security Patch"
                }

            return {
                "status": "PASS",
                "severity": "INFO",
                "detail": details,
                "recommendation": "ตรวจสอบและอัพเดท Windows Update เป็นประจำ"
            }
        except Exception:
            pass

    win_ver = platform.win32_ver()
    return {
        "status": "PASS",
        "severity": "INFO",
        "detail": f"Windows Version: {win_ver[0]} {win_ver[1]} ({win_ver[2]})",
        "recommendation": "หมั่นอัพเดท Security Patches ให้เป็นปัจจุบัน"
    }


def check_smbv1():
    """ตรวจสอบการเปิดใช้งาน SMBv1 (โปรโตคอลเก่าที่มีช่องโหว่ร้ายแรง)"""
    ps_cmd = "(Get-SmbServerConfiguration).EnableSMB1Protocol"
    output = run_powershell(ps_cmd)
    if "True" in output:
        return {
            "status": "FAIL",
            "severity": "CRITICAL",
            "detail": "SMBv1 เปิดใช้งานอยู่ (เสี่ยงต่อ Ransomware และ EternalBlue)",
            "recommendation": "ปิด SMBv1 โดยใช้คำสั่ง: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
        }
    return {
        "status": "PASS",
        "severity": "INFO",
        "detail": "SMBv1 ถูกปิดใช้งานแล้ว (ปลอดภัย)",
        "recommendation": "ไม่ต้องดำเนินการใดๆ"
    }


def check_firewall():
    """ตรวจสอบสถานะ Windows Firewall ทุก Profile"""
    ps_cmd = "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
    output = run_powershell(ps_cmd)

    if "Error" in output or not output:
        return {"status": "UNKNOWN", "severity": "MEDIUM", "detail": "ไม่สามารถตรวจสอบ Firewall ได้",
                "recommendation": "ตรวจสอบสิทธิ์ Administrator"}

    try:
        profiles = json.loads(output)
        disabled_profiles = []
        if isinstance(profiles, list):
            for p in profiles:
                if not p.get("Enabled"):
                    disabled_profiles.append(p.get("Name"))
        elif isinstance(profiles, dict):
            if not profiles.get("Enabled"):
                disabled_profiles.append(profiles.get("Name"))

        if disabled_profiles:
            return {
                "status": "FAIL",
                "severity": "HIGH",
                "detail": f"Firewall ถูกปิดใช้งานใน Profile: {', '.join(disabled_profiles)}",
                "recommendation": "เปิดใช้งาน Firewall ทุก Profile (Domain, Private, Public)"
            }
        return {
            "status": "PASS",
            "severity": "INFO",
            "detail": "Windows Firewall เปิดใช้งานครบทุก Profile",
            "recommendation": "ไม่ต้องดำเนินการใดๆ"
        }
    except Exception:
        return {"status": "UNKNOWN", "severity": "MEDIUM",
                "detail": "รูปแบบข้อมูล Firewall ไม่ถูกต้อง", "recommendation": "ตรวจสอบด้วยตนเอง"}


def check_uac():
    """ตรวจสอบการตั้งค่า User Account Control (UAC)"""
    ps_cmd = "(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA"
    output = run_powershell(ps_cmd)
    if "0" in output:
        return {
            "status": "FAIL",
            "severity": "HIGH",
            "detail": "UAC (User Account Control) ถูกปิดใช้งาน",
            "recommendation": "เปิดใช้งาน UAC เพื่อป้องกันโปรแกรมแปลกปลอมรันด้วยสิทธิ์ Admin"
        }
    return {
        "status": "PASS",
        "severity": "INFO",
        "detail": "UAC เปิดใช้งานอยู่",
        "recommendation": "ไม่ต้องดำเนินการใดๆ"
    }


def check_rdp_nla():
    """ตรวจสอบการตั้งค่า Remote Desktop Network Level Authentication (NLA)"""
    ps_cmd_rdp = "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections"
    output_rdp = run_powershell(ps_cmd_rdp)

    if "0" in output_rdp:  # RDP เปิดอยู่
        ps_cmd_nla = "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication"
        output_nla = run_powershell(ps_cmd_nla)
        if "1" not in output_nla:
            return {
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "RDP เปิดอยู่แต่ไม่ได้เปิดใช้ NLA (Network Level Authentication)",
                "recommendation": "เปิดใช้งาน NLA สำหรับ RDP เพื่อบังคับยืนยันตัวตนก่อนเชื่อมต่อ"
            }
        return {
            "status": "PASS",
            "severity": "INFO",
            "detail": "RDP เปิดใช้งานพร้อม NLA อย่างปลอดภัย",
            "recommendation": "ไม่ต้องดำเนินการใดๆ"
        }
    return {
        "status": "PASS",
        "severity": "INFO",
        "detail": "RDP (Remote Desktop) ถูกปิดใช้งานอยู่",
        "recommendation": "ไม่ต้องดำเนินการใดๆ"
    }


def check_defender():
    """ตรวจสอบสถานะ Windows Defender Real-time Protection"""
    ps_cmd = "(Get-MpComputerStatus).RealTimeProtectionEnabled"
    output = run_powershell(ps_cmd)
    if "False" in output:
        return {
            "status": "FAIL",
            "severity": "HIGH",
            "detail": "Windows Defender Real-time Protection ถูกปิดอยู่",
            "recommendation": "เปิดใช้งาน Real-time Protection ใน Windows Security"
        }
    elif "True" in output:
        return {
            "status": "PASS",
            "severity": "INFO",
            "detail": "Windows Defender Real-time Protection เปิดทำงานอยู่ปกติ",
            "recommendation": "ไม่ต้องดำเนินการใดๆ"
        }
    return {
        "status": "UNKNOWN",
        "severity": "MEDIUM",
        "detail": "ใช้อิสระกับ Third-party Antivirus หรือไม่สามารถดึงข้อมูลได้",
        "recommendation": "ตรวจสอบโปรแกรม Antivirus หลักในเครื่อง"
    }


def main():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║        Windows Security Hardening & Audit Tool v1.0              ║
║        โปรแกรมตรวจสอบการตั้งค่าความปลอดภัยของ Windows            ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}""")

    if platform.system().lower() != "windows":
        print(f"{Colors.YELLOW}  ⚠️  สคริปต์นี้ออกแบบสำหรับรันบนระบบปฏิบัติการ Windows เท่านั้น{Colors.RESET}\n")

    print(f"  🔍 กำลังเริ่มการตรวจสอบความปลอดภัยของระบบ...\n")

    checks = [
        ("1. การตรวจสอบ Windows OS Version & Build", check_windows_version),
        ("2. การตรวจสอบ SMBv1 Protocol", check_smbv1),
        ("3. การตรวจสอบ Windows Firewall", check_firewall),
        ("4. การตรวจสอบ UAC (User Account Control)", check_uac),
        ("5. การตรวจสอบ RDP NLA Authentication", check_rdp_nla),
        ("6. การตรวจสอบ Windows Defender Status", check_defender),
    ]

    results = []

    for name, func in checks:
        res = func()
        results.append({"check": name, "result": res})

        status_color = Colors.GREEN if res["status"] == "PASS" else Colors.RED
        print(f"  {Colors.BOLD}{name}{Colors.RESET}")
        print(f"  Result : {status_color}[{res['status']}]{Colors.RESET} ({res['severity']})")
        print(f"  Detail : {res['detail']}")
        if res["status"] == "FAIL":
            print(f"  {Colors.YELLOW}Fix    : {res['recommendation']}{Colors.RESET}")
        print("-" * 65)

    # Export report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"windows_security_audit_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n{Colors.GREEN}  ✅ การตรวจสอบเสร็จสิ้น รายงานถูกบันทึกที่: {filename}{Colors.RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n  {Colors.CYAN}👋 ออกจาก Windows Audit เรียบร้อย{Colors.RESET}\n")
        sys.exit(0)
