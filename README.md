# 🛡️ Action Against Cyber Attack

A real-time network and system security monitoring tool with automated threat detection and response. Built with Python and Flask, it captures live network traffic, monitors system behavior, detects attacks, and fires automated defenses — all viewable through a live web dashboard.

---

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Detection Capabilities](#detection-capabilities)
- [Automated Response](#automated-response)
- [Dashboard](#dashboard)
- [Logs](#logs)
- [Project Structure](#project-structure)

---

## ✨ Features

- **Live packet capture** using Scapy across Wi-Fi and VirtualBox interfaces
- **System monitoring** — CPU, memory, disk, running processes, file changes, and user sessions
- **12 threat detection algorithms** covering the most common attack vectors
- **Automated defense** — blocks malicious IPs via Windows Firewall, kills suspicious processes
- **Web dashboard** accessible at `http://localhost:5000` with real-time stats and alerts
- **Demo mode** — works without Scapy/Watchdog for testing and preview
- **CSV/TXT log export** for all network connections, system resources, processes, and sessions

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│                  app.py (Flask)             │
│          Web Dashboard & REST API           │
└──────────┬──────────────────────────────────┘
           │
    ┌──────▼──────┐
    │ IntegratedMonitor (main_monitor.py)     │
    │  orchestrates all components            │
    └──┬───────┬──────────┬───────────────────┘
       │       │          │
┌──────▼──┐ ┌──▼──────┐ ┌─▼──────────────┐ ┌──────────────────┐
│ Network │ │ System  │ │ Detection      │ │ Response         │
│ Monitor │ │ Monitor │ │ Engine         │ │ Engine           │
│         │ │         │ │                │ │                  │
│ Scapy   │ │ psutil  │ │ 12 detectors   │ │ IP blocking      │
│ packets │ │ watchdog│ │ dedup + sort   │ │ process killing  │
└─────────┘ └─────────┘ └────────────────┘ └──────────────────┘
```

---

## 🔧 Requirements

- Python 3.8+
- Windows OS (firewall commands use `netsh`)
- Administrator / root privileges (required for packet capture and firewall rules)

**Python dependencies:**

```
flask
psutil
scapy
watchdog
```

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Soumyadip-UEM/action-against-cyber-attack.git
cd action-against-cyber-attack

# Install dependencies
pip install flask psutil scapy watchdog
```

> **Note:** On Windows, run your terminal as Administrator to allow Scapy packet capture and firewall rule management.

---

## 🚀 Usage

### Run the web dashboard

```bash
python app.py
```

Then open your browser at **http://localhost:5000**.

### Run the terminal-only monitor (no web UI)

```bash
python main_monitor.py
```

Press `Ctrl+C` to stop monitoring. All logs will be automatically saved to the `logs/` directory.

### Demo mode

If Scapy or Watchdog is not available, the dashboard launches automatically in **demo mode** with simulated data so you can explore the UI without elevated privileges.

---

## 🔍 Detection Capabilities

The `DetectionEngine` runs 12 independent checks every 5 seconds:

| Detection Type | Trigger Condition | Severity |
|---|---|---|
| **Port Scan** | Single IP contacts >15 unique ports | HIGH |
| **Brute Force** | >10 login attempts on ports 21/22/3389 | HIGH |
| **DDoS** | Packet rate exceeds 200 packets/sec | CRITICAL |
| **Sensitive Port Access** | Connections to ports 21, 22, 445, 3389 | HIGH |
| **Suspicious Process** | Any process using >50% CPU | HIGH |
| **Data Exfiltration** | Single IP transfers >5 MB | CRITICAL |
| **ARP Spoofing** | IP with >50 packets with no destination port | CRITICAL |
| **DNS Tunneling** | Single IP sends >20 UDP packets to port 53 | HIGH |
| **C2 Beaconing** | Single IP appears ≥6 times in connection log | CRITICAL |
| **Lateral Movement** | Internal IP connects to ≥4 other internal hosts | HIGH |
| **Ransomware** | >20 file changes within a 10-second window | CRITICAL |
| **Reverse Shell** | Shell process (bash/cmd/nc/etc.) + incoming high port connection | CRITICAL |

Alerts are **deduplicated** (same type + IP suppressed for 60 seconds) and **sorted by severity** before being returned.

---

## 🛡️ Automated Response

When `auto_defense=True` (default), the `ResponseEngine` takes the following actions automatically:

| Alert Type | Action |
|---|---|
| PORT_SCAN, BRUTE_FORCE, DDOS, ARP_SPOOFING, C2_BEACONING, DNS_TUNNELING, SENSITIVE_ACCESS | Block attacker IP via Windows Firewall |
| DATA_EXFILTRATION | Block IP + log exfiltration event |
| LATERAL_MOVEMENT | Block IP + containment message |
| REVERSE_SHELL | Block IP + containment alert |
| SUSPICIOUS_PROCESS | Kill the offending process via psutil |
| RANSOMWARE | Block IP + system isolation alert |

Blocked IPs are **automatically unblocked after 5 minutes** (300 seconds) by a background watcher thread.

---

## 🖥️ Dashboard

The web dashboard (served at `http://localhost:5000`) provides:

- **Live / Demo mode toggle** — start and stop real monitoring
- **Network stats** — packet count, total data transferred, protocol distribution (TCP/UDP/Other)
- **Top IPs by bandwidth** and recent connections
- **System metrics** — CPU, memory, disk usage gauges
- **Top processes** by CPU usage
- **File system changes** — real-time listing of created/modified/deleted files
- **Security alerts panel** — live feed of detected threats with type, severity, attacker IP, and details
- **Blocked IPs list** and defense action log
- **Clear history** button to reset dashboard state without stopping the monitor

---

## 📁 Logs

All session logs are saved to the `logs/` directory on shutdown (terminal mode) or can be reviewed directly. Each session produces:

| File | Contents |
|---|---|
| `network_connections_<timestamp>.csv` | Full packet-level connection log |
| `system_resources_<timestamp>.csv` | CPU / memory / disk snapshots every 5s |
| `system_processes_<timestamp>.csv` | Top-5 processes by CPU every 10s |
| `file_changes_<timestamp>.csv` | File system events (create/modify/delete) |
| `user_sessions_<timestamp>.csv` | Login and logout events |
| `monitoring_summary_<timestamp>.txt` | Human-readable session summary |

---

## 📂 Project Structure

```
action-against-cyber-attack/
├── app.py                  # Flask web server and REST API
├── main_monitor.py         # IntegratedMonitor — orchestrates all components
├── network_monitor.py      # Packet capture and network statistics
├── system_monitor.py       # CPU/memory/process/file/session monitoring
├── detection_engine.py     # 12 threat detection algorithms
├── response_engine.py      # Automated defense — IP blocking, process killing
├── shared_utils.py         # Logging helpers and display utilities
├── templates/
│   └── index.html          # Dashboard HTML template
├── static/
│   ├── script.js           # Dashboard frontend logic
│   └── style.css           # Dashboard styles
└── logs/                   # Auto-generated session logs (CSV + TXT)
```

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security research purposes only**. The automated firewall rules require Administrator privileges and will modify your local Windows Firewall configuration. Always obtain proper authorization before running network monitoring tools on any network.

---

## 👤 Author

**Soumyadip** — [GitHub](https://github.com/timeless-debugger)
