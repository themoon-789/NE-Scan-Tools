#!/usr/bin/env python3
"""
HTML Report Generator
======================
สร้างรายงาน HTML สวยงามจากไฟล์ JSON ที่ได้จาก tools ทั้งหมด
รองรับ: network_scanner, port_scanner, vuln_scanner output

Usage:
    python3 report_generator.py
    python3 report_generator.py -i scan_result.json -o report.html
    python3 report_generator.py -i vuln_report.json -o vuln_report.html
"""

import json
import os
import sys
import argparse
import glob
from datetime import datetime

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NE Scan — Security Report</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0d1117; --bg2: #161b22; --bg3: #1c2128;
    --border: #30363d; --text: #e6edf3; --muted: #7d8590;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
    --blue: #58a6ff; --cyan: #79c0ff; --purple: #bc8cff;
    --orange: #ffa657; --critical: #ff4444; --high: #ff6b35;
    --medium: #ffd166; --low: #06d6a0; --info: #58a6ff;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; font-size: 14px; }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px; }

  /* Header */
  .header { background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%);
            border: 1px solid var(--border); border-radius: 12px; padding: 32px;
            margin-bottom: 24px; position: relative; overflow: hidden; }
  .header::before { content: ''; position: absolute; top: -50%; right: -10%;
                    width: 400px; height: 400px;
                    background: radial-gradient(circle, rgba(88,166,255,0.08) 0%, transparent 70%);
                    pointer-events: none; }
  .header h1 { font-size: 28px; font-weight: 700; color: var(--cyan);
               display: flex; align-items: center; gap: 12px; }
  .header .subtitle { color: var(--muted); margin-top: 6px; font-size: 13px; }
  .header .meta { display: flex; gap: 24px; margin-top: 16px; flex-wrap: wrap; }
  .header .meta-item { display: flex; align-items: center; gap: 6px; color: var(--muted); font-size: 12px; }
  .header .meta-item strong { color: var(--text); }

  /* Summary Cards */
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                  gap: 16px; margin-bottom: 24px; }
  .card { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
          padding: 20px; text-align: center; transition: transform 0.2s, border-color 0.2s; }
  .card:hover { transform: translateY(-2px); border-color: var(--blue); }
  .card .num { font-size: 36px; font-weight: 700; }
  .card .label { color: var(--muted); font-size: 12px; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
  .card.critical { border-color: var(--critical); }
  .card.critical .num { color: var(--critical); }
  .card.high { border-color: var(--high); }
  .card.high .num { color: var(--high); }
  .card.medium { border-color: var(--medium); }
  .card.medium .num { color: var(--medium); }
  .card.low { border-color: var(--low); }
  .card.low .num { color: var(--low); }
  .card.info { border-color: var(--info); }
  .card.info .num { color: var(--info); }
  .card.online { border-color: var(--green); }
  .card.online .num { color: var(--green); }

  /* Risk Badge */
  .risk-badge { display: inline-flex; align-items: center; gap: 6px;
                padding: 6px 16px; border-radius: 20px; font-weight: 600; font-size: 13px; }
  .risk-critical { background: rgba(255,68,68,0.15); color: var(--critical); border: 1px solid var(--critical); }
  .risk-high { background: rgba(255,107,53,0.15); color: var(--high); border: 1px solid var(--high); }
  .risk-medium { background: rgba(255,209,102,0.15); color: var(--medium); border: 1px solid var(--medium); }
  .risk-low { background: rgba(6,214,160,0.15); color: var(--low); border: 1px solid var(--low); }

  /* Section */
  .section { background: var(--bg2); border: 1px solid var(--border);
             border-radius: 10px; margin-bottom: 20px; overflow: hidden; }
  .section-header { padding: 16px 20px; border-bottom: 1px solid var(--border);
                    display: flex; align-items: center; justify-content: space-between; }
  .section-title { font-size: 15px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
  .badge { background: var(--bg3); color: var(--muted); padding: 2px 8px;
           border-radius: 12px; font-size: 11px; border: 1px solid var(--border); }

  /* Table */
  table { width: 100%; border-collapse: collapse; }
  th { background: var(--bg3); color: var(--muted); font-size: 11px; text-transform: uppercase;
       letter-spacing: 0.5px; padding: 10px 16px; text-align: left; font-weight: 500; }
  td { padding: 10px 16px; border-top: 1px solid var(--border); font-family: 'JetBrains Mono', monospace; font-size: 12px; }
  tr:hover td { background: var(--bg3); }
  .ip { color: var(--green); }
  .mac { color: var(--yellow); }
  .port { color: var(--orange); }
  .service { color: var(--cyan); }
  .vendor { color: var(--muted); }

  /* Device Type badges */
  .device-badge { display: inline-flex; align-items: center; gap: 4px;
                  padding: 2px 8px; border-radius: 4px; font-size: 11px;
                  font-family: 'Inter', sans-serif; }
  .device-camera { background: rgba(188,140,255,0.15); color: var(--purple); }
  .device-router { background: rgba(88,166,255,0.15); color: var(--blue); }
  .device-server { background: rgba(63,185,80,0.15); color: var(--green); }
  .device-windows { background: rgba(121,192,255,0.15); color: var(--cyan); }
  .device-linux { background: rgba(63,185,80,0.15); color: var(--green); }
  .device-network { background: rgba(255,166,87,0.15); color: var(--orange); }
  .device-unknown { background: rgba(125,133,144,0.15); color: var(--muted); }

  /* OS badges */
  .os-windows { color: var(--cyan); }
  .os-linux { color: var(--green); }
  .os-network { color: var(--orange); }

  /* Open port pill */
  .port-open { background: rgba(63,185,80,0.15); color: var(--green);
               padding: 1px 6px; border-radius: 4px; border: 1px solid rgba(63,185,80,0.3); }
  .port-filtered { background: rgba(210,153,34,0.15); color: var(--yellow);
                   padding: 1px 6px; border-radius: 4px; border: 1px solid rgba(210,153,34,0.3); }

  /* Severity */
  .sev { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;
         font-family: 'Inter', sans-serif; }
  .sev-CRITICAL { background: rgba(255,68,68,0.15); color: var(--critical); border: 1px solid rgba(255,68,68,0.3); }
  .sev-HIGH     { background: rgba(255,107,53,0.15); color: var(--high);     border: 1px solid rgba(255,107,53,0.3); }
  .sev-MEDIUM   { background: rgba(255,209,102,0.15); color: var(--medium); border: 1px solid rgba(255,209,102,0.3); }
  .sev-LOW      { background: rgba(6,214,160,0.15); color: var(--low);       border: 1px solid rgba(6,214,160,0.3); }
  .sev-INFO     { background: rgba(88,166,255,0.15); color: var(--info);     border: 1px solid rgba(88,166,255,0.3); }

  /* Finding Card */
  .finding { background: var(--bg3); border: 1px solid var(--border);
             border-radius: 8px; padding: 16px; margin: 12px 20px; }
  .finding-title { font-weight: 600; margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
  .finding-row { display: flex; gap: 8px; margin-top: 6px; font-size: 12px; }
  .finding-label { color: var(--muted); min-width: 70px; }
  .finding-value { color: var(--text); flex: 1; }
  .finding-fix { color: var(--green); }

  /* Footer */
  .footer { text-align: center; color: var(--muted); font-size: 11px; padding: 24px 0; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ NE Scan — Security Report</h1>
    <div class="subtitle">Network Security Assessment Results</div>
    <div class="meta">
      <div class="meta-item">📅 <strong>__SCAN_TIME__</strong></div>
      <div class="meta-item">🎯 <strong>__TARGET__</strong></div>
      <div class="meta-item">📂 <strong>__SOURCE__</strong></div>
    </div>
  </div>

  __SUMMARY_SECTION__
  __CONTENT_SECTION__

  <div class="footer">NE Scan Security Toolkit — Generated __GEN_TIME__</div>
</div>
</body>
</html>"""


def get_device_class(device_type):
    dt = device_type.lower()
    if 'camera' in dt or 'hikvision' in dt or 'dahua' in dt:
        return 'device-camera'
    if 'router' in dt or 'switch' in dt or 'gateway' in dt:
        return 'device-router'
    if 'server' in dt or 'workstation' in dt:
        return 'device-server'
    return 'device-unknown'


def get_os_class(os_str):
    os_lower = os_str.lower()
    if 'windows' in os_lower:
        return 'os-windows'
    if 'linux' in os_lower:
        return 'os-linux'
    if 'network' in os_lower:
        return 'os-network'
    return ''


def build_network_section(data):
    """สร้าง HTML สำหรับข้อมูล Network Scan"""
    if not isinstance(data, list):
        return ""

    rows = ""
    for r in data:
        ip = r.get('ip', '-')
        mac = r.get('mac', '-')
        hostname = r.get('hostname', 'N/A')
        vendor = r.get('vendor', 'Unknown')
        device_type = r.get('device_type', '❓ Unknown')
        os_g = r.get('os', 'Unknown')
        os_cls = get_os_class(os_g)
        dev_cls = get_device_class(device_type)

        rows += f"""<tr>
          <td class="ip">{ip}</td>
          <td class="mac">{mac}</td>
          <td>{hostname}</td>
          <td class="{os_cls}">{os_g}</td>
          <td class="vendor">{vendor}</td>
          <td><span class="device-badge {dev_cls}">{device_type}</span></td>
        </tr>"""

    count = len(data)
    camera_count = sum(
        1 for r in data if 'Camera' in r.get(
            'device_type',
            '') or 'camera' in r.get(
            'device_type',
            '').lower())

    summary = f"""<div class="summary-grid">
      <div class="card online"><div class="num">{count}</div><div class="label">Online Hosts</div></div>
      <div class="card info"><div class="num">{camera_count}</div><div class="label">IP Cameras</div></div>
    </div>"""

    section = f"""<div class="section">
      <div class="section-header">
        <div class="section-title">🌐 Network Scan Results <span class="badge">{count} hosts</span></div>
      </div>
      <table>
        <tr><th>IP Address</th><th>MAC Address</th><th>Hostname</th><th>OS (TTL)</th><th>Vendor</th><th>Device Type</th></tr>
        {rows}
      </table>
    </div>"""

    return summary, section


def build_port_section(data):
    """สร้าง HTML สำหรับ Port Scan"""
    if isinstance(data, dict) and 'targets' in data:
        # Multi-target
        all_ports = []
        for ip, ports in data['targets'].items():
            for p in ports:
                p['target_ip'] = ip
                all_ports.append(p)
        data = all_ports
    elif not isinstance(data, list):
        return "", ""

    rows = ""
    open_count = sum(1 for p in data if p.get('state') == 'OPEN')
    for p in data:
        state = p.get('state', '-')
        state_cls = 'port-open' if state == 'OPEN' else 'port-filtered'
        banner = p.get('banner', '') or '-'
        rows += f"""<tr>
          <td class="ip">{p.get('target_ip', p.get('port',''))}</td>
          <td class="port">{p.get('port', '-')}</td>
          <td>{p.get('proto', 'TCP')}</td>
          <td><span class="{state_cls}">{state}</span></td>
          <td class="service">{p.get('service', '-')}</td>
          <td style="color:var(--muted);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{banner[:80]}</td>
        </tr>"""

    summary = f"""<div class="summary-grid">
      <div class="card online"><div class="num">{open_count}</div><div class="label">Open Ports</div></div>
    </div>"""

    section = f"""<div class="section">
      <div class="section-header">
        <div class="section-title">🔍 Port Scan Results <span class="badge">{len(data)} ports found</span></div>
      </div>
      <table>
        <tr><th>Target</th><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Banner / Version</th></tr>
        {rows}
      </table>
    </div>"""

    return summary, section


def build_vuln_section(data):
    """สร้าง HTML สำหรับ Vulnerability Report"""
    # Support both list of findings and {target, findings} format
    findings = []
    target = "-"

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and 'result' in item:
                r = item['result']
                findings.append({
                    'severity': r.get('severity', 'INFO'),
                    'module': item.get('check', '-'),
                    'title': r.get('detail', '-'),
                    'description': r.get('detail', '-'),
                    'recommendation': r.get('recommendation', '-'),
                })
            elif isinstance(item, dict) and 'severity' in item:
                findings.append(item)
    elif isinstance(data, dict):
        target = data.get('target', '-')
        findings = data.get('findings', [])

    counts = {}
    for f in findings:
        sev = f.get('severity', 'INFO')
        counts[sev] = counts.get(sev, 0) + 1

    sev_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    findings_html = ""
    for sev in sev_order:
        sev_findings = [f for f in findings if f.get('severity') == sev]
        if not sev_findings:
            continue
        findings_html += f"""<div style="padding:8px 20px 0">
          <div style="font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">{sev} ({len(sev_findings)})</div>
        </div>"""
        for f in sev_findings:
            fix_class = "finding-fix" if f.get('recommendation') else ""
            findings_html += f"""<div class="finding">
              <div class="finding-title">
                <span class="sev sev-{sev}">{sev}</span>
                {f.get('title', f.get('detail', '-'))}
              </div>
              <div class="finding-row">
                <span class="finding-label">Module</span>
                <span class="finding-value">{f.get('module', '-')}</span>
              </div>
              <div class="finding-row">
                <span class="finding-label">Detail</span>
                <span class="finding-value">{f.get('description', f.get('detail', '-'))}</span>
              </div>
              <div class="finding-row">
                <span class="finding-label">Fix</span>
                <span class="finding-value {fix_class}">{f.get('recommendation', '-')}</span>
              </div>
            </div>"""

    total = len(findings)
    crit = counts.get('CRITICAL', 0)
    high = counts.get('HIGH', 0)
    med = counts.get('MEDIUM', 0)
    low = counts.get('LOW', 0)
    info = counts.get('INFO', 0)

    risk_score = crit * 40 + high * 20 + med * 10 + low * 5
    if risk_score == 0:
        risk_cls, risk_label = "risk-low", "LOW RISK"
    elif risk_score < 50:
        risk_cls, risk_label = "risk-medium", "MEDIUM RISK"
    elif risk_score < 100:
        risk_cls, risk_label = "risk-high", "HIGH RISK"
    else:
        risk_cls, risk_label = "risk-critical", "CRITICAL RISK"

    summary = f"""<div class="summary-grid">
      <div class="card critical"><div class="num">{crit}</div><div class="label">Critical</div></div>
      <div class="card high"><div class="num">{high}</div><div class="label">High</div></div>
      <div class="card medium"><div class="num">{med}</div><div class="label">Medium</div></div>
      <div class="card low"><div class="num">{low}</div><div class="label">Low</div></div>
      <div class="card info"><div class="num">{info}</div><div class="label">Info</div></div>
    </div>
    <div style="margin-bottom:20px">
      <span class="risk-badge {risk_cls}">⚠️ {risk_label}</span>
      <span style="color:var(--muted);font-size:12px;margin-left:12px">Risk Score: {risk_score} | Total: {total} findings</span>
    </div>"""

    section = f"""<div class="section">
      <div class="section-header">
        <div class="section-title">🛡️ Vulnerability Findings
          <span class="badge">{total} findings</span>
        </div>
        <span style="color:var(--muted);font-size:12px">Target: {target}</span>
      </div>
      {findings_html if findings_html else '<div style="padding:20px;color:var(--muted);text-align:center">ไม่พบช่องโหว่</div>'}
    </div>"""

    return summary, section


def detect_report_type(data):
    """ระบุประเภทของ JSON report"""
    if isinstance(data, list) and len(data) > 0:
        first = data[0]
        if isinstance(first, dict):
            if 'ip' in first and 'mac' in first:
                return 'network'
            if 'port' in first and 'state' in first:
                return 'port'
            if 'check' in first and 'result' in first:
                return 'vuln'
            if 'severity' in first and 'title' in first:
                return 'vuln'
    if isinstance(data, dict):
        if 'findings' in data:
            return 'vuln'
        if 'targets' in data and isinstance(data['targets'], dict):
            return 'port'
        if 'results' in data:
            return 'network'
    return 'unknown'


def generate_html_report(json_file, output_file=None):
    """โหลด JSON และสร้าง HTML Report"""
    if not os.path.exists(json_file):
        print(f"  ❌ ไม่พบไฟล์: {json_file}")
        return None

    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    report_type = detect_report_type(data)

    # ดึงข้อมูล meta
    if isinstance(data, dict):
        target = data.get('target', data.get('subnet', '-'))
        scan_time = data.get('scan_time', '-')
        inner = data.get('results', data.get('findings', data))
    else:
        target = 'Multiple'
        scan_time = datetime.now().isoformat()
        inner = data

    # สร้าง section ตามประเภท
    summary_html = ""
    content_html = ""

    if report_type == 'network':
        result = build_network_section(inner if isinstance(inner, list) else data)
        if result and len(result) == 2:
            summary_html, content_html = result
    elif report_type == 'port':
        result = build_port_section(data)
        if result and len(result) == 2:
            summary_html, content_html = result
    elif report_type == 'vuln':
        result = build_vuln_section(data)
        if result and len(result) == 2:
            summary_html, content_html = result
    else:
        # Generic JSON display
        content_html = f"""<div class="section">
          <div class="section-header"><div class="section-title">📄 Raw Data</div></div>
          <pre style="padding:20px;color:var(--muted);overflow-x:auto;font-size:12px">{json.dumps(data, indent=2, ensure_ascii=False)[:5000]}</pre>
        </div>"""

    # Render template
    html = HTML_TEMPLATE
    html = html.replace('__TARGET__', str(target))
    html = html.replace('__SCAN_TIME__', str(scan_time))
    html = html.replace('__SOURCE__', os.path.basename(json_file))
    html = html.replace('__GEN_TIME__', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    html = html.replace('__SUMMARY_SECTION__', summary_html)
    html = html.replace('__CONTENT_SECTION__', content_html)

    if not output_file:
        base = os.path.splitext(json_file)[0]
        output_file = f"{base}_report.html"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    return output_file


def main():
    print("""
\033[96m\033[1m
╔══════════════════════════════════════════════════════════╗
║   📊 NE Scan — HTML Report Generator                     ║
║   แปลงไฟล์ JSON ผลสแกนเป็น HTML Report สวยงาม           ║
╚══════════════════════════════════════════════════════════╝
\033[0m""")

    parser = argparse.ArgumentParser(description="HTML Report Generator สำหรับ NE Scan")
    parser.add_argument('-i', '--input', help='Input JSON file')
    parser.add_argument('-o', '--output', help='Output HTML file')
    args = parser.parse_args()

    if args.input:
        output = generate_html_report(args.input, args.output)
        if output:
            print(f"\n  \033[92m✅ HTML Report สร้างสำเร็จ: {output}\033[0m")
            print(f"  \033[2m  เปิดไฟล์ใน Browser เพื่อดูผลลัพธ์\033[0m\n")
    else:
        # Interactive mode - ค้นหา JSON files ที่มีอยู่
        json_files = glob.glob('*.json')
        if not json_files:
            print("  \033[33m⚠️  ไม่พบไฟล์ JSON ในโฟลเดอร์ปัจจุบัน\033[0m")
            print("  รันสแกนก่อนแล้วค่อยสร้าง Report ครับ\n")
            return

        print("  \033[1mพบไฟล์ JSON ดังนี้:\033[0m")
        for i, f in enumerate(json_files, 1):
            size = os.path.getsize(f)
            print(f"  [{i}] {f} ({size:,} bytes)")

        print("  [0] ออก\n")

        choice = input("  เลือกไฟล์ [1-{}]: ".format(len(json_files))).strip()
        if choice == '0' or not choice.isdigit():
            return

        idx = int(choice) - 1
        if 0 <= idx < len(json_files):
            json_file = json_files[idx]
            output = generate_html_report(json_file)
            if output:
                print(f"\n  \033[92m✅ HTML Report สร้างสำเร็จ: {output}\033[0m")
                print(f"  \033[2m  เปิดไฟล์ใน Browser เพื่อดูผลลัพธ์\033[0m\n")
                # เปิด browser อัตโนมัติ
                import webbrowser
                webbrowser.open(f'file://{os.path.abspath(output)}')


if __name__ == "__main__":
    main()
