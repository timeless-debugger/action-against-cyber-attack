#!/usr/bin/env python
# pip install flask psutil scapy watchdog
# Run: python app.py
# Open: http://localhost:5000

import random
import time
from collections import deque
from datetime import datetime

from flask import Flask, jsonify, render_template

try:
    from main_monitor import IntegratedMonitor
    SCAPY_AVAILABLE = True
except Exception as e:
    # If imports that rely on scapy/watchdog fail, fall back to demo-only mode
    IntegratedMonitor = None  # type: ignore
    SCAPY_AVAILABLE = False
    IMPORT_ERROR = str(e)
else:
    IMPORT_ERROR = ""


app = Flask(__name__)

# Global monitoring objects
monitor = IntegratedMonitor() if IntegratedMonitor is not None else None
is_live = False

# Alerts history (max 50)
alerts_history = deque(maxlen=50)

# Mock state values to keep them smooth between calls
mock_state = {
    "packet_count": 0,
    "total_bytes_mb": 0.0,
    "file_changes_count": 0,
    "alert_index": 0,
}

MOCK_ALERTS_CYCLE = [
    {
        "type": "PORT_SCAN",
        "severity": "HIGH",
        "attacker_ip": "192.168.1.105",
        "details": "23 ports scanned",
    },
    {
        "type": "BRUTE_FORCE",
        "severity": "HIGH",
        "attacker_ip": "10.0.0.44",
        "details": "15 login attempts",
    },
    {
        "type": "C2_BEACONING",
        "severity": "CRITICAL",
        "attacker_ip": "172.16.0.8",
        "details": "C2 beaconing detected",
    },
    {
        "type": "DDOS",
        "severity": "CRITICAL",
        "attacker_ip": "N/A",
        "details": "High traffic rate: 312 packets/sec",
    },
    {
        "type": "DATA_EXFILTRATION",
        "severity": "CRITICAL",
        "attacker_ip": "10.0.0.77",
        "details": "Large data sent to external IP",
    },
]


def _now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@app.route("/")
def index():
    return render_template("index.html", import_error=IMPORT_ERROR, scapy_available=SCAPY_AVAILABLE)


@app.post("/start")
def start_monitor():
    global is_live
    if not SCAPY_AVAILABLE or monitor is None:
        # Cannot truly start, stay in demo mode
        is_live = False
        return jsonify({"status": "demo_only", "message": IMPORT_ERROR}), 200

    if not is_live:
        try:
            monitor.start()
            is_live = True
        except Exception as e:
            is_live = False
            return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "started"}), 200


@app.post("/stop")
def stop_monitor():
    global is_live
    if monitor is not None and is_live:
        try:
            monitor.stop()
        except Exception:
            # Even if stop fails, fall back to not live
            pass
    is_live = False
    return jsonify({"status": "stopped"}), 200


def _build_live_stats():
    """Build stats payload from real monitor objects."""
    net_stats = monitor.network_monitor.get_stats()
    sys_stats = monitor.system_monitor.get_stats()

    # Run detection engine from live monitor data to keep web dashboard in sync.
    alerts = monitor.detector.analyze(monitor.system_monitor, monitor.network_monitor)

    # Push alerts into history with timestamp
    for a in alerts:
        enriched = {
            "timestamp": _now_ts(),
            "type": a.get("type", "UNKNOWN"),
            "severity": a.get("severity", "LOW"),
            "attacker_ip": a.get("attacker_ip", "N/A"),
            "details": a.get("details", ""),
        }
        alerts_history.append(enriched)

    # Response/defense state from ResponseEngine
    blocked_ips = []
    defense_actions = []
    if hasattr(monitor, "responder") and monitor.responder is not None:
        try:
            blocked_ips = list(getattr(monitor.responder, "blocked_ips", {}).keys())
        except Exception:
            blocked_ips = []
        try:
            defense_actions = list(getattr(monitor.responder, "actions_log", []))[-10:]
        except Exception:
            defense_actions = []

    latest_res = sys_stats.get("latest_resource") or {
        "cpu_percent": 0,
        "memory_percent": 0,
        "disk_percent": 0,
    }

    payload = {
        "live": True,
        "packet_count": net_stats.get("packet_count", 0),
        "total_bytes_mb": round(net_stats.get("total_bytes", 0) / (1024 * 1024), 2),
        "protocol_stats": net_stats.get("protocol_stats", {"TCP": 0, "UDP": 0, "OTHER": 0}),
        "top_ips": net_stats.get("top_ips", []),
        "recent_connections": net_stats.get("recent_connections", []),
        "cpu_percent": latest_res.get("cpu_percent", 0),
        "memory_percent": latest_res.get("memory_percent", 0),
        "disk_percent": latest_res.get("disk_percent", 0),
        "recent_processes": [
            {
                "name": p.get("name", "unknown"),
                "cpu_percent": p.get("cpu_percent", 0),
                "memory_percent": p.get("memory_percent", 0),
            }
            for p in sys_stats.get("recent_processes", [])
        ],
        "file_changes_count": sys_stats.get("file_changes_count", 0),
        "recent_file_changes": sys_stats.get("recent_file_changes", []),
        "alerts": list(alerts_history)[-20:],
        "blocked_ips": blocked_ips,
        "defense_actions": defense_actions,
    }
    return payload


def _build_mock_stats():
    """Return realistic fake/demo data when not live."""
    # Increment packets and bytes
    mock_state["packet_count"] += random.randint(10, 50)
    mock_state["total_bytes_mb"] += random.uniform(0.5, 2.0)
    mock_state["file_changes_count"] += random.randint(0, 3)

    # Protocol distribution ~60/30/10
    total_proto = 1000
    tcp = int(total_proto * random.uniform(0.55, 0.65))
    udp = int(total_proto * random.uniform(0.25, 0.35))
    other = max(total_proto - tcp - udp, 0)

    # Top IPs
    base_ips = [f"192.168.1.{i}" for i in range(100, 105)]
    top_ips = []
    for ip in base_ips:
        top_ips.append((ip, random.randint(5_000_000, 50_000_000)))

    # Recent connections
    recent_connections = []
    for _ in range(5):
        direction = random.choice(["INCOMING", "OUTGOING"])
        src_ip = random.choice(base_ips)
        dst_ip = random.choice(
            ["10.0.0.5", "8.8.8.8", "1.1.1.1", "172.16.0.10", "93.184.216.34"]
        )
        recent_connections.append(
            {
                "timestamp": _now_ts(),
                "direction": direction,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": random.choice([22, 80, 443, 3389, 8080, 54545]),
                "protocol": random.choice(["TCP", "UDP"]),
            }
        )

    # System metrics
    cpu_percent = random.uniform(20, 60)
    memory_percent = random.uniform(40, 70)
    disk_percent = 55.0 + random.uniform(-2, 2)

    # Recent processes
    processes = [
        "chrome.exe",
        "python.exe",
        "svchost.exe",
        "explorer.exe",
        "firefox.exe",
    ]
    recent_processes = []
    for name in processes:
        recent_processes.append(
            {
                "name": name,
                "cpu_percent": round(random.uniform(0, 35), 1),
                "memory_percent": round(random.uniform(0.5, 8.0), 1),
            }
        )

    # File changes
    actions = ["CREATED", "MODIFIED", "DELETED"]
    recent_file_changes = []
    for i in range(5):
        recent_file_changes.append(
            {
                "timestamp": _now_ts(),
                "action": random.choice(actions),
                "path": f"C:/Projects/IntegratedSecurity/logs/log_{i}.txt",
            }
        )

    # Cycle alerts
    if random.random() < 0.7:
        idx = mock_state["alert_index"] % len(MOCK_ALERTS_CYCLE)
        base = MOCK_ALERTS_CYCLE[idx]
        mock_state["alert_index"] += 1
        alerts_history.append(
            {
                "timestamp": _now_ts(),
                **base,
            }
        )

    payload = {
        "live": False,
        "packet_count": mock_state["packet_count"],
        "total_bytes_mb": round(mock_state["total_bytes_mb"], 2),
        "protocol_stats": {"TCP": tcp, "UDP": udp, "OTHER": other},
        "top_ips": top_ips,
        "recent_connections": recent_connections,
        "cpu_percent": round(cpu_percent, 1),
        "memory_percent": round(memory_percent, 1),
        "disk_percent": round(disk_percent, 1),
        "recent_processes": recent_processes,
        "file_changes_count": mock_state["file_changes_count"],
        "recent_file_changes": recent_file_changes,
        "alerts": list(alerts_history)[-20:],
        "blocked_ips": [],
        "defense_actions": [],
    }
    return payload


@app.get("/stats")
def get_stats():
    if is_live and monitor is not None:
        data = _build_live_stats()
    else:
        data = _build_mock_stats()
    return jsonify(data)


@app.get("/alerts")
def get_alerts():
    # Always return last 20 alerts
    return jsonify(list(alerts_history)[-20:])


@app.post("/clear_history")
def clear_history():
    """Clear dashboard-visible historical state without stopping monitoring."""
    alerts_history.clear()

    # Reset demo counters/history
    mock_state["packet_count"] = 0
    mock_state["total_bytes_mb"] = 0.0
    mock_state["file_changes_count"] = 0
    mock_state["alert_index"] = 0

    # Best-effort clear of monitor runtime logs
    if monitor is not None:
        try:
            monitor.network_monitor.connection_log.clear()
            monitor.network_monitor.bandwidth_per_ip.clear()
            monitor.network_monitor.port_usage.clear()
            monitor.network_monitor.app_connections.clear()
            monitor.network_monitor.packet_count = 0
            monitor.network_monitor.total_bytes = 0
        except Exception:
            pass
        try:
            monitor.system_monitor.resource_log.clear()
            monitor.system_monitor.process_log.clear()
            monitor.system_monitor.file_changes.clear()
            monitor.system_monitor.session_log.clear()
        except Exception:
            pass
        try:
            monitor.responder.actions_log.clear()
            monitor.responder.blocked_ips.clear()
        except Exception:
            pass

    return jsonify({"status": "cleared"}), 200


if __name__ == "__main__":
    # Ensure consistent random behaviour across runs, but not fixed
    random.seed(time.time())
    app.run(host="0.0.0.0", port=5000, debug=False)

