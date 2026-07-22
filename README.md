# NE_Scan – Network Security Toolkit

> **Authorized Use Only** — For use on networks you own or have written permission to test.

A modular, all-in-one CLI toolkit for **Network Discovery, Port Scanning, Vulnerability Assessment, Broadcast Analysis and Continuous Monitoring** — built with pure Python and zero external dependencies.

---

## ✨ Features

| Tool | Description |
|------|-------------|
| 🌐 **Network Scanner** | Discover live hosts, MAC, Vendor, OS fingerprint |
| 🔍 **Port Scanner** | TCP + UDP + Service/Banner detection |
| 🛡️ **Vulnerability Scan** | CVE hints, SNMP enumeration, default credential checks |
| 🌐 **Network Device Audit** | Router / Switch / Firewall hardening check |
| 🪟 **Windows Audit** | Windows security hardening assessment |
| ⚡ **Quick Full Scan** | Port + Vulnerability in one shot |
| 📊 **Subnet Full Scan** | Scan every host in a subnet automatically |
| 🔭 **Continuous Monitor** | Real-time new-device alert with baseline |
| 📊 **HTML Report** | Generate a beautiful HTML report from JSON results |
| 📡 **Broadcast Monitor** | Detect Broadcast Storm / ARP Flood / Syslog / mDNS live |

---

## 📋 Requirements

- **Python 3.8+** (tested on macOS 13+ and Ubuntu 22.04+)
- **Nmap** — `brew install nmap` / `apt install nmap`
- **tcpdump** — `brew install tcpdump` / `apt install tcpdump`
- No third-party Python packages required

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/<your-username>/NE_Scan.git
cd NE_Scan

# Run the interactive launcher (no sudo needed for most tools)
python3 main.py

# Broadcast Monitor requires sudo (uses tcpdump)
sudo python3 bcast_simple.py
```

---

## 📂 Project Structure

```
NE_Scan/
├── main.py                 # Interactive launcher — entry point
│
├── network_scanner.py      # [1] Network / Host Discovery
├── port_scanner.py         # [2] Port Scanner (TCP + UDP)
├── vuln_scanner.py         # [3] Vulnerability Scanner
├── net_device_audit.py     # [4] Network Device Audit
├── windows_audit.py        # [5] Windows Security Audit
│
├── monitor.py              # [8] Continuous Monitor (baseline aware)
├── report_generator.py     # [9] HTML Report Generator
│
├── bcast_simple.py         # [A] Broadcast Storm Detector — Easy Mode
├── broadcast_monitor.py    # [A] Broadcast Monitor — Advanced (CLI flags)
│
└── security_monitor.py     # Background security event monitor
```

---

## 🎮 Usage — Interactive Mode

```
python3 main.py
```

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  [1] 🌐 Network Scanner         ค้นหา IP/MAC/Vendor/OS           │
  │  [2] 🔍 Port Scanner            สแกน Port + UDP + Service        │
  │  [3] 🛡️  Vulnerability Scan    ตรวจช่องโหว่ CVE/SNMP             │
  │  [4] 🌐 Network Device Audit    ตรวจ Router/Switch/Firewall      │
  │  [5] 🪟 Windows Audit           ตรวจ Windows Security            │
  │  [6] ⚡ Quick Full Scan         Port + Vuln อัตโนมัติ            │
  │  [7] 📊 Subnet Full Scan        สแกนทุก IP ใน Subnet             │
  │  [8] 🔭 Continuous Monitor      เฝ้าระวัง Real-time              │
  │  [9] 📊 HTML Report             สร้าง HTML Report                │
  │  [A] 📡 Broadcast Monitor       ตรวจ Broadcast Storm / ARP Flood │
  │  [0] ❌ ออกจากโปรแกรม                                             │
  └──────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Usage — CLI Mode (Non-interactive)

```bash
# Network scan a single target
python3 main.py -t 192.168.1.1 -m scan

# Port scan
python3 main.py -t 192.168.1.1 -m port

# Vulnerability scan
python3 main.py -t 192.168.1.1 -m vuln

# Full scan (Port + Vuln)
python3 main.py -t 192.168.1.1 -m full

# Subnet scan
python3 main.py -t 192.168.1.0/24 -m full

# Network Device Audit (Router/Switch)
python3 main.py -t 192.168.1.1 -m net

# Windows Audit
python3 main.py -t 192.168.1.100 -m win

# Broadcast Monitor (with sudo)
sudo python3 bcast_simple.py

# Broadcast Monitor advanced (list interfaces)
sudo python3 broadcast_monitor.py --list-interfaces
sudo python3 broadcast_monitor.py -i en0 --threshold 50
```

---

## 📡 Broadcast Monitor

The Broadcast Storm Detector (`bcast_simple.py`) captures live traffic via `tcpdump` and shows:

- **Real-time pps (packets per second)** with Storm / Alert thresholds
- **Top broadcast sources** with MAC Address, Vendor (OUI lookup), Device Type, and Main Service/Port
- **Protocol & Port breakdown** — ARP, DHCP, mDNS, SSDP, NetBIOS, IGMP, Syslog, Video Stream …
- **Auto-detect interface** with interactive selection showing IP and MAC per interface
- **Alerts** for abnormal sources and storm events
- **Summary report** (all devices, up to 30) on `Ctrl+C`

```bash
sudo python3 bcast_simple.py
```

Supports: **macOS** and **Linux**

---

## 🔒 Legal & Ethical Use

> ⚠️ This toolkit is intended **only** for:
> - Networks you own or administer
> - Authorized penetration testing engagements (with written permission)
> - Academic / lab environments

Unauthorized scanning of networks is **illegal** in most jurisdictions.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
