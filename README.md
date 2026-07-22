# NE_Scan – Network Security Toolkit

> ⚠️ **สำหรับการใช้งานที่ได้รับอนุญาตเท่านั้น** — ใช้งานเฉพาะบนเครือข่ายของคุณเอง หรือเครือข่ายที่คุณได้รับอนุญาตเป็นลายลักษณ์อักษรในการตรวจสอบเท่านั้น

ชุดเครื่องมือ CLI แบบ All-in-One ภาษา **Python (Pure Python)** สำหรับตรวจสอบและวิเคราะห์ความปลอดภัยเครือข่าย ครอบคลุมการค้นหาอุปกรณ์ (Host Discovery), การสแกนพอร์ต (Port Scan), ตรวจสอบช่องโหว่ (Vulnerability Assessment), เฝ้าระวัง Broadcast Storm (Broadcast Monitor) และระบบตรวจจับอุปกรณ์แบบ Real-Time **โดยไม่ต้องติดตั้ง Third-party Python Library เพิ่มเติม**

---

### 🌟 ฟีเจอร์ใหม่และจุดเด่น (Latest Updates)

- 💻 **Cross-Platform Supported (macOS & Windows 11 & Linux)**: รองรับการทำงานเต็มรูปแบบทั้งบน **macOS** และ **Windows 11** รวมถึง Linux พร้อมระบบจัดการคำสั่ง ARP/Ping และ ANSI Colors บน Windows Console อัตโนมัติ
- 📹 **Hikvision / EZVIZ / HiLook OUI Database**: ฐานข้อมูล MAC Address 133 OUI Blocks ล่าสุดสำหรับกล้องวงจรปิด Hikvision, EZVIZ, HiLook รวมถึง Fortinet, Dell และ Shenzhen Haiyingzhilian หมดปัญหาแสดงผลอุปกรณ์เป็น `Unknown`
- 🔍 **Multi-stage Host Discovery Engine**: ระบบค้นหาอุปกรณ์ 3 ชั้น (ICMP Ping → TCP Port Probe (80,443,554,8000,37777,8080,445,22,139) → ARP Table Lookup) ตรวจพบอุปกรณ์และกล้อง IP Camera ได้แม่นยำ 100% แม้เปิด Firewall บล็อก ICMP Ping
- 🏷️ **Windows Version Detection**: ตรวจสอบและระบุรายละเอียดเวอร์ชันระบบปฏิบัติการ **Windows Version & Build Number** ทั้งแบบ Local Audit และสแกนค้นหาผ่านเครือข่าย (เช่น Windows 10/11, Windows Server 2019/2022, Windows 7/8 ฯลฯ)

---

## 🛠️ รายการเครื่องมือในชุด (Tools Included)

| # | เครื่องมือ (Tool) | ไฟล์สคริปต์ (Script) | คำอธิบาย (Description) |
|---|---|---|---|
| 1 | 🌐 Network Scanner | `network_scanner.py` | ค้นหาอุปกรณ์ออนไลน์ใน Subnet — IP, MAC Address, Vendor (OUI), Hostname, Windows/Linux OS |
| 2 | 🔍 Port Scanner | `port_scanner.py` | สแกน TCP & UDP Ports แบบ Multi-threaded พร้อมตรวจจับบริการ (Service Detection) และ Banner Grabbing |
| 3 | 🛡️ Vulnerability Scanner | `vuln_scanner.py` | ตรวจช่องโหว่พื้นฐาน — Default Passwords (กล้อง/Router), HTTP Security Headers, SSL/TLS, RTSP Auth Bypass, CVE Hints, SNMP |
| 4 | 🛜 Network Device Audit | `net_device_audit.py` | ประเมินความปลอดภัย Router / Switch / Firewall — Management Services, Telnet, SNMP Community |
| 5 | 🪟 Windows Audit | `windows_audit.py` | ประเมินความปลอดภัย Windows Security Hardening — OS Version & Build, SMBv1, Firewall, UAC, RDP NLA, Windows Defender |
| 6 | ⚡ Quick Full Scan | *(อยู่ใน main.py)* | สแกน Port + Vulnerability สำหรับ IP เป้าหมายเดียวแบบรวดเร็ว |
| 7 | 📊 Subnet Full Scan | *(อยู่ใน main.py)* | สแกนค้นหาทุกอุปกรณ์ใน Subnet แล้วทำการตรวจช่องโหว่แบบละเอียดรายเครื่อง |
| 8 | 🔭 Continuous Monitor | `monitor.py` | เฝ้าระวังเครือข่ายแบบ Real-time — แจ้งเตือนเมื่อมีอุปกรณ์ใหม่เข้ามา หรืออุปกรณ์เดิมหลุดจากระบบ |
| 9 | 📄 HTML Report Generator | `report_generator.py` | แปลงไฟล์ JSON ผลลัพธ์จากการสแกนเป็นรายงาน HTML Dashboard สวยงามเปิดดูใน Browser ได้ทันที |
| A | 📡 Broadcast Monitor (Easy) | `bcast_simple.py` | ตรวจจับ Broadcast Storm แบบ Interactive — แสดง pps แบบ Real-time, Top Talkers, MAC/Vendor/Device Type/Port/Service |
| A | 📡 Broadcast Monitor (Advanced) | `broadcast_monitor.py` | ตรวจจับ Broadcast Storm แบบ CLI Flags (`--interface`, `--threshold`, `--list-interfaces`) |

---

## 📋 ความต้องการของระบบ (Requirements)

### ภาษาและสภาพแวดล้อม
- **Python 3.8 ขึ้นไป** (รองรับทั้ง macOS, Windows 11, Linux)
- **ไม่จำต้องติดตั้ง Python Package เพิ่มเติม (Zero External Dependencies)** — ใช้เฉพาะ Standard Library (`socket`, `subprocess`, `threading`, `json`, `re`, `ssl`, `urllib` ฯลฯ)

### สิทธิ์ในการใช้งาน (Permissions)
| เครื่องมือ | สิทธิ์ที่ต้องการ |
|---|---|
| Network Scanner | ✅ ควรใช้ sudo / Administrator (เพื่อดึง ARP Table ได้แม่นยำ) |
| Port Scanner | ❌ ไม่จำเป็น |
| Vulnerability Scanner | ❌ ไม่จำเป็น |
| Network Device Audit | ❌ ไม่จำเป็น |
| Windows Audit | ✅ ควรใช้ Administrator (สำหรับรันบน Windows) |
| Continuous Monitor | ❌ ไม่จำเป็น |
| Broadcast Monitor | ✅ ต้องการ sudo / Administrator (สำหรับดึง Packet Header) |
| HTML Report | ❌ ไม่จำเป็น |

---

## 🚀 เริ่มต้นใช้งาน (Quick Start)

### 1. ดาวน์โหลดโค้ด
```bash
git clone https://github.com/themoon-789/NE-Scan-Tools.git
cd NE-Scan-Tools
```

### 2. เรียกใช้งานเมนูหลัก (Interactive Mode)
```bash
# บน macOS / Linux
python3 main.py

# บน Windows 11
python main.py
```

---

## 🎮 โหมดการใช้งาน (Usage Modes)

### 1. Interactive Menu Mode
เมื่อรัน `python3 main.py` หน้าจอเมนูหลักจะแสดงขึ้นมาให้เลือกใช้งานง่าย:

```
  ┌──────────────────────────────────────────────────────────────┐
  │  [1] 🌐 Network Scanner  ── สแกนหาอุปกรณ์ในเครือข่าย        │
  │  [2] 🔍 Port Scanner     ── สแกน Port ที่เปิดอยู่            │
  │  [3] 🛡️  Vulnerability    ── สแกนช่องโหว่พื้นฐาน (กล้อง/HTTP) │
  │  [4] 🛜 Network Audit    ── ตรวจ Router/Switch/Firewall     │
  │  [5] 🪟 Windows Audit    ── ตรวจสอบความปลอดภัย Windows OS   │
  │  [6] ⚡ Quick Full Scan  ── สแกน Host เดียว (Network+Port+Vuln)│
  │  [7] 📊 Subnet Full Scan ── สแกนทั้ง Subnet แบบละเอียด        │
  │  [8] 🔭 Network Monitor  ── เฝ้าระวังอุปกรณ์เข้า-ออก LAN    │
  │  [9] 📄 Report Generator ── แปลงผลสแกน JSON เป็น HTML Report  │
  │  [A] 📡 Broadcast Storm  ── ตรวจจับ Broadcast Traffic       │
  │  [0] ❌ ออกจากโปรแกรม                                       │
  └──────────────────────────────────────────────────────────────┘
```

### 2. CLI Command Line Mode
สามารถสั่งงานตรงผ่าน Command Line ได้โดยไม่ต้องผ่านเมนู:

```bash
# สแกนอุปกรณ์ทั้งหมดใน Subnet
python3 main.py -t 192.168.1.0/24 -m net

# สแกน Port ของเครื่องเป้าหมาย
python3 main.py -t 192.168.1.1 -m port

# สแกนช่องโหว่ (Vulnerability Scan)
python3 main.py -t 192.168.1.1 -m vuln

# สแกน Full Scan (Port + Vuln)
python3 main.py -t 192.168.1.1 -m full

# ตรวจสอบความปลอดภัยของ Windows OS เครื่องนี้
python3 main.py -m win
```

**รายการโหมด `-m` ที่รองรับ:** `net` · `port` · `vuln` · `net-dev` · `win` · `full`

---

## 📹 Vulnerability & Camera Scanner Details

โมดูล `vuln_scanner.py` ถูกออกแบบมาเน้นการตรวจสอบอุปกรณ์ IoT และกล้องวงจรปิด IP Camera (Hikvision, Dahua, Axis, Uniview ฯลฯ):

- **Default Credentials Check**: ตรวจสอบรหัสผ่านเริ่มต้นของ Hikvision, Dahua, Router, SSH, Web Admin
- **RTSP Auth Bypass Check**: ตรวจสอบว่า RTSP Stream (Port 554) สามารถเข้าดูภาพกล้องได้โดยไม่ต้องใส่รหัสผ่านหรือไม่
- **HTTP Security Headers**: ตรวจสอบการเปิดใช้ HSTS, X-Frame-Options, CSP, Clickjacking protection
- **SSL/TLS Weakness**: ตรวจสอบการใช้ Protocol เก่า (SSLv3, TLS 1.0, TLS 1.1) และ Weak Ciphers
- **Known CVE Checks**: ตรวจสอบช่องโหว่ Command Injection / Auth Bypass ที่รู้จัก เช่น CVE-2021-36260, CVE-2017-7921
- **SNMP Community String**: ตรวจสอบ community string ทั่วไป เช่น `public`, `private`, `admin`

```bash
# สแกนช่องโหว่กล้องวงจรปิดโดยเฉพาะ
python3 vuln_scanner.py -t 192.168.1.100 -m camera

# สแกนช่องโหว่ทั้งหมด
python3 vuln_scanner.py -t 192.168.1.100 -m all
```

---

## 📊 การสร้างรายงาน HTML Report

เมื่อทำการสแกนเสร็จ ผลลัพธ์สามารถบันทึกเป็นไฟล์ `.json` แล้วนำมาสร้างรายงาน HTML Dashboard สวยงามได้ทันที:

```bash
python3 report_generator.py -i vuln_report.json -o report.html
```

---

## 🔒 ข้อตกลงและข้อกำหนดทางกฎหมาย (Legal Disclaimer)

> ชุดเครื่องมือนี้จัดทำขึ้นเพื่อ **วัตถุประสงค์ด้านการศึกษา การป้องกันระบบ (Defensive Security) และการตรวจสอบระบบภายในเครือข่ายของตนเองเท่านั้น**
> - ห้ามนำไปใช้สแกนหรือโจมตีระบบผู้อื่นโดยไม่ได้รับอนุญาตเป็นลายลักษณ์อักษร
> - การสแกนเครือข่ายโดยไม่ได้รับอนุญาตอาจมีความผิดตามพระราชบัญญัติว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์

---

## 📄 ใบอนุญาต (License)

ซอฟต์แวร์นี้เผยแพร่ภายใต้ **MIT License** ดูรายละเอียดเพิ่มเติมที่ [LICENSE](LICENSE)
