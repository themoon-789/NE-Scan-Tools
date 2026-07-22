# NE_Scan – Network Security Toolkit

> ⚠️ **For authorized use only** — Use only on networks you own or have explicit written permission to test.

A modular, all-in-one **CLI toolkit** for network discovery, port scanning, vulnerability assessment, broadcast traffic analysis, and continuous monitoring — built with **pure Python** and no external Python packages required.

---

## 🛠️ Tools Included

| # | Tool | Script | Description |
|---|------|--------|-------------|
| 1 | 🌐 Network Scanner | `network_scanner.py` | Discover live hosts — IP, MAC Address, Vendor (OUI), Hostname, OS hint |
| 2 | 🔍 Port Scanner | `port_scanner.py` | TCP + UDP port scanning with service detection and banner grabbing |
| 3 | 🛡️ Vulnerability Scanner | `vuln_scanner.py` | Default credential checks (cameras, routers), HTTP security headers, SSL/TLS weakness, RTSP auth bypass, common CVE hints, SNMP enumeration |
| 4 | 🌐 Network Device Audit | `net_device_audit.py` | Router / Switch / Firewall hardening check — management services, SNMP, risky protocols |
| 5 | 🪟 Windows Audit | `windows_audit.py` | Windows security hardening assessment (run as Administrator on Windows) |
| 6 | ⚡ Quick Full Scan | *(built into main.py)* | Port scan + Vulnerability scan on a single IP in one shot |
| 7 | 📊 Subnet Full Scan | *(built into main.py)* | Discover all live hosts in a subnet, then run vulnerability scan on each |
| 8 | 🔭 Continuous Monitor | `monitor.py` | Real-time new-device detection — alerts when a new device joins or a known device disappears |
| 9 | 📊 HTML Report | `report_generator.py` | Generate a formatted HTML report from JSON scan output files |
| A | 📡 Broadcast Monitor (Easy) | `bcast_simple.py` | Interactive broadcast storm detector — shows real-time pps, top sources with MAC/Vendor/Device Type/Port/Service |
| A | 📡 Broadcast Monitor (Advanced) | `broadcast_monitor.py` | CLI-flag version with `--interface`, `--threshold`, `--list-interfaces` options |

---

## 📋 Requirements

### System Dependencies
- **Python 3.8+**
- **Nmap** — for OS detection and service fingerprinting  
  `brew install nmap` / `sudo apt install nmap`
- **tcpdump** — required for Broadcast Monitor  
  `brew install tcpdump` / `sudo apt install tcpdump`

### Python Dependencies
**None** — uses only Python standard library modules:
`socket`, `subprocess`, `threading`, `collections`, `argparse`, `json`, `re`, `ssl`, `urllib`, etc.

### Permissions
| Tool | Requires sudo/root? |
|------|---------------------|
| Network Scanner | ✅ Yes (ARP requires root) |
| Port Scanner | ❌ No |
| Vulnerability Scanner | ❌ No |
| Network Device Audit | ❌ No |
| Windows Audit | ✅ Yes (run as Administrator on Windows) |
| Continuous Monitor | ✅ Yes (ping via ICMP) |
| Broadcast Monitor | ✅ Yes (tcpdump requires root) |
| HTML Report | ❌ No |

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/themoon-789/NE-Scan-Tools.git
cd NE-Scan-Tools

# Launch interactive menu
python3 main.py

# Broadcast Monitor (requires sudo)
sudo python3 bcast_simple.py
```

---

## 📂 Project Structure

```
NE-Scan-Tools/
├── main.py                 ← Interactive launcher / CLI entry point
│
├── network_scanner.py      ← [1] Host discovery (IP, MAC, Vendor, Hostname)
├── port_scanner.py         ← [2] Port scanner (TCP + UDP + Banner)
├── vuln_scanner.py         ← [3] Vulnerability scanner
├── net_device_audit.py     ← [4] Network device hardening audit
├── windows_audit.py        ← [5] Windows security hardening audit
│
├── monitor.py              ← [8] Continuous network monitor (baseline aware)
├── report_generator.py     ← [9] HTML report generator from JSON output
│
├── bcast_simple.py         ← [A] Broadcast storm detector — Easy interactive mode
└── broadcast_monitor.py    ← [A] Broadcast storm detector — Advanced CLI mode
```

---

## 🎮 Interactive Mode

```bash
python3 main.py
```

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  [1] 🌐 Network Scanner         ค้นหา IP/MAC/Vendor/OS           │
  │  [2] 🔍 Port Scanner            สแกน Port + UDP + Service        │
  │  [3] 🛡️  Vulnerability Scan    ตรวจช่องโหว่ CVE/SNMP/Creds      │
  │  [4] 🌐 Network Device Audit    ตรวจ Router/Switch/Firewall      │
  │  [5] 🪟 Windows Audit           ตรวจ Windows Security            │
  │  [6] ⚡ Quick Full Scan         Port + Vuln อัตโนมัติ            │
  │  [7] 📊 Subnet Full Scan        สแกนทุก IP ใน Subnet             │
  │  [8] 🔭 Continuous Monitor      เฝ้าระวัง Real-time              │
  │  [9] 📊 HTML Report             สร้าง HTML Report                │
  │  [A] 📡 Broadcast Monitor       ตรวจ Broadcast Storm / ARP Flood │
  │  [0] ❌ Exit                                                      │
  └──────────────────────────────────────────────────────────────────┘
```

---

## ⌨️ CLI Mode (Non-interactive)

```bash
# Network device discovery
python3 main.py -t 192.168.1.0/24 -m net

# Port scan a single target
python3 main.py -t 192.168.1.1 -m port

# Vulnerability scan
python3 main.py -t 192.168.1.1 -m vuln

# Full scan (Port + Vuln) — default mode
python3 main.py -t 192.168.1.1 -m full

# Subnet full scan (discover all hosts, then scan each)
python3 main.py -t 192.168.1.0/24 -m full

# Network device audit
python3 main.py -t 192.168.1.1 -m net-dev

# Windows audit (run on the Windows machine itself)
python3 main.py -m win
```

**Available `-m` modes:** `net` · `port` · `vuln` · `net-dev` · `win` · `full`

---

## 📡 Broadcast Monitor

Captures live traffic using `tcpdump` and displays a real-time dashboard:

- **Packet rate (pps)** with Storm (`≥200 pps`) and Alert (`≥50 pps`) thresholds
- **Top broadcast sources** — IP, MAC Address (from Ethernet header), Vendor (OUI lookup), Device Type, dominant Port/Service
- **Protocol & Port breakdown** — ARP, DHCP, Syslog (514), mDNS (5353), SSDP/UPnP (1900), NetBIOS (137/138), IGMP, Video Stream (5557), NTP, Dahua Discovery (37777), Hikvision SADP (40000) and more
- **Auto-detects default interface** with an interactive list showing IP and MAC per interface
- **Storm alerts** for abnormal sources
- **Summary report** with up to 30 top devices when stopped with `Ctrl+C`

```bash
# Easy interactive mode
sudo python3 bcast_simple.py

# Advanced: list interfaces with IP/MAC
sudo python3 broadcast_monitor.py --list-interfaces

# Advanced: specify interface and custom threshold
sudo python3 broadcast_monitor.py -i en0 --threshold 50
```

Supported platforms: **macOS** and **Linux**

---

## 📊 Vulnerability Scanner Details

The vulnerability scanner (`vuln_scanner.py`) checks for:

- **Default Credentials** — Hikvision, Dahua, MikroTik, TP-Link, Netgear, generic HTTP Basic Auth
- **HTTP Security Headers** — Missing HSTS, X-Frame-Options, CSP, etc.
- **SSL/TLS Weaknesses** — Expired certs, weak cipher hints
- **RTSP Authentication Bypass** — Common IP camera RTSP endpoints
- **SNMP Community Strings** — `public`, `private`, `admin`
- **Service Version CVE hints** — Based on banner grabbing
- **Open Management Interfaces** — Telnet, unencrypted HTTP admin panels

```bash
python3 vuln_scanner.py -t 192.168.1.100
python3 vuln_scanner.py -t 192.168.1.100 -m camera   # Camera-focused mode
python3 vuln_scanner.py -t 192.168.1.100 -m all       # All checks
```

---

## 🔒 Legal Notice

> This toolkit is intended **only** for:
> - Networks you own or are authorized to administer
> - Authorized penetration testing with **written permission**
> - Academic lab and CTF environments

Unauthorized network scanning may be **illegal** under computer crime laws in your jurisdiction.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
