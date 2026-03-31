// SecureWatch front-end logic

const POLL_INTERVAL_MS = 3000;
let isLive = (window.__SECUREWATCH_INITIAL__ && window.__SECUREWATCH_INITIAL__.isLive) || false;
let lastStats = null;
let lastAlertsTimestamps = new Set();
let terminalLines = [];
const TERMINAL_MAX_LINES = 100;

function $(id) {
    return document.getElementById(id);
}

function formatTime(ts) {
    if (!ts) return "";
    // Expect "YYYY-MM-DD HH:MM:SS"
    const parts = ts.split(" ");
    if (parts.length === 2) {
        return parts[1];
    }
    return ts;
}

function animateNumber(el, from, to, suffix = "") {
    if (!el) return;
    const duration = 400;
    const start = performance.now();
    const diff = to - from;
    function step(now) {
        const t = Math.min(1, (now - start) / duration);
        const value = from + diff * t;
        el.textContent = suffix ? `${value.toFixed(0)}${suffix}` : value.toFixed(0);
        if (t < 1) {
            requestAnimationFrame(step);
        }
    }
    requestAnimationFrame(step);
}

function animateNumberFloat(el, from, to, decimals = 2) {
    if (!el) return;
    const duration = 400;
    const start = performance.now();
    const diff = to - from;
    function step(now) {
        const t = Math.min(1, (now - start) / duration);
        const value = from + diff * t;
        el.textContent = value.toFixed(decimals);
        if (t < 1) {
            requestAnimationFrame(step);
        }
    }
    requestAnimationFrame(step);
}

function setRing(ringEl, labelEl, percent) {
    const clamped = Math.max(0, Math.min(100, percent || 0));
    const circumference = 2 * Math.PI * 50; // r=50
    const offset = circumference * (1 - clamped / 100);
    ringEl.style.strokeDashoffset = offset;
    labelEl.textContent = `${clamped.toFixed(0)}%`;

    let color = "#00ff88";
    if (clamped >= 80) {
        color = "#ff4444";
    } else if (clamped >= 60) {
        color = "#ff8800";
    }
    ringEl.style.stroke = color;
}

function updateStatusPill(live) {
    const pill = $("status-pill");
    const text = $("status-text");
    const demoBanner = $("demo-banner");
    if (!pill || !text) return;
    pill.classList.remove("demo", "live");
    if (live) {
        pill.classList.add("live");
        text.textContent = "LIVE MONITORING";
        if (demoBanner) demoBanner.classList.add("hidden");
    } else {
        pill.classList.add("demo");
        text.textContent = "DEMO MODE";
        if (demoBanner) demoBanner.classList.remove("hidden");
    }
}

function severityClass(sev) {
    switch (sev) {
        case "CRITICAL":
            return "severity-critical";
        case "HIGH":
            return "severity-high";
        case "MEDIUM":
            return "severity-medium";
        default:
            return "severity-low";
    }
}

function logToTerminal(level, message) {
    const body = $("terminal-body");
    if (!body) return;
    const now = new Date();
    const ts = now.toTimeString().split(" ")[0];
    const lineText = `[${ts}] ${level.toUpperCase()}: ${message}`;

    terminalLines.push({ level, text: lineText });
    if (terminalLines.length > TERMINAL_MAX_LINES) {
        terminalLines.shift();
    }

    body.innerHTML = "";
    for (const l of terminalLines) {
        const div = document.createElement("div");
        div.className = `terminal-line ${l.level.toLowerCase()}`;
        div.textContent = l.text;
        body.appendChild(div);
    }
    body.scrollTop = body.scrollHeight;
}

function showCriticalToast(alert) {
    const container = $("toast-container");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = "toast critical";

    const icon = document.createElement("div");
    icon.className = "toast-icon";
    icon.textContent = "⚠";

    const body = document.createElement("div");
    body.className = "toast-body";

    const title = document.createElement("div");
    title.className = "toast-title";
    title.textContent = `CRITICAL: ${alert.type}`;

    const subtitle = document.createElement("div");
    subtitle.className = "toast-subtitle";
    const ip = alert.attacker_ip || "N/A";
    subtitle.textContent = `Source: ${ip} — ${alert.details || ""}`;

    body.appendChild(title);
    body.appendChild(subtitle);
    toast.appendChild(icon);
    toast.appendChild(body);

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add("toast-out");
        setTimeout(() => {
            container.removeChild(toast);
        }, 280);
    }, 4000);
}

function updateThreatTable(alert) {
    const type = alert.type;
    const row = document.querySelector(`tr[data-threat="${type}"]`);
    if (!row) return;
    const statusPill = row.querySelector(".status-pill");
    if (statusPill) {
        statusPill.textContent = "DETECTED";
        statusPill.classList.remove("neutral");
        statusPill.classList.add("detected");
    }
    row.classList.remove("threat-row-flash");
    void row.offsetWidth; // force reflow
    row.classList.add("threat-row-flash");
}

function updateStatsCards(data) {
    const packetsEl = $("packet-count");
    const bytesEl = $("total-bytes");
    const threatsEl = $("active-threats");
    const cpuEl = $("cpu-usage");

    const prevPackets = lastStats ? lastStats.packet_count : 0;
    const prevBytes = lastStats ? lastStats.total_bytes_mb : 0;
    const activeThreats = Array.isArray(data.alerts) ? data.alerts.length : 0;

    animateNumber(packetsEl, prevPackets, data.packet_count || 0);
    animateNumberFloat(bytesEl, prevBytes, data.total_bytes_mb || 0, 2);

    if (threatsEl) {
        threatsEl.textContent = activeThreats.toString();
        threatsEl.style.color = activeThreats > 0 ? "#ff4444" : "#00ff88";
    }

    const prevCpu = lastStats ? lastStats.cpu_percent : 0;
    const newCpu = data.cpu_percent || 0;
    if (cpuEl) {
        animateNumber(cpuEl, prevCpu, newCpu, "%");
        if (newCpu >= 80) {
            cpuEl.style.color = "#ff4444";
        } else if (newCpu >= 50) {
            cpuEl.style.color = "#ff8800";
        } else {
            cpuEl.style.color = "#00ff88";
        }
    }
}

function updateProtocolBars(protocolStats) {
    const tcp = protocolStats.TCP || 0;
    const udp = protocolStats.UDP || 0;
    const other = protocolStats.OTHER || 0;
    const total = tcp + udp + other || 1;
    const tcpPct = (tcp / total) * 100;
    const udpPct = (udp / total) * 100;
    const otherPct = (other / total) * 100;

    const tcpBar = $("tcp-bar");
    const udpBar = $("udp-bar");
    const otherBar = $("other-bar");
    const tcpLabel = $("tcp-label");
    const udpLabel = $("udp-label");
    const otherLabel = $("other-label");

    if (tcpBar) tcpBar.style.width = `${tcpPct.toFixed(1)}%`;
    if (udpBar) udpBar.style.width = `${udpPct.toFixed(1)}%`;
    if (otherBar) otherBar.style.width = `${otherPct.toFixed(1)}%`;
    if (tcpLabel) tcpLabel.textContent = `${tcpPct.toFixed(1)}%`;
    if (udpLabel) udpLabel.textContent = `${udpPct.toFixed(1)}%`;
    if (otherLabel) otherLabel.textContent = `${otherPct.toFixed(1)}%`;
}

function updateTopIps(topIps) {
    const list = $("top-ips");
    if (!list) return;
    list.innerHTML = "";
    if (!topIps || !topIps.length) {
        const li = document.createElement("li");
        li.textContent = "No IP statistics yet.";
        li.style.fontSize = "0.78rem";
        li.style.color = "#9ca3af";
        list.appendChild(li);
        return;
    }

    const maxBytes = Math.max(...topIps.map((t) => t[1] || 0)) || 1;
    for (const [ip, bytes] of topIps) {
        const li = document.createElement("li");
        li.className = "top-ip-item";

        const name = document.createElement("span");
        name.className = "top-ip-name";
        name.textContent = ip;

        const barWrapper = document.createElement("div");
        barWrapper.className = "top-ip-bar-wrapper";

        const bar = document.createElement("div");
        bar.className = "top-ip-bar";
        const pct = (bytes / maxBytes) * 100;
        bar.style.width = `${pct.toFixed(0)}%`;

        barWrapper.appendChild(bar);

        const bytesSpan = document.createElement("span");
        bytesSpan.className = "top-ip-bytes";
        const mb = bytes / (1024 * 1024);
        bytesSpan.textContent = `${mb.toFixed(2)} MB`;

        li.appendChild(name);
        li.appendChild(barWrapper);
        li.appendChild(bytesSpan);
        list.appendChild(li);
    }
}

function updateRecentConnections(conns) {
    const tbody = $("recent-connections");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!conns || !conns.length) return;
    for (const c of conns) {
        const tr = document.createElement("tr");
        const timeTd = document.createElement("td");
        timeTd.textContent = formatTime(c.timestamp);
        const dirTd = document.createElement("td");
        const arrow = c.direction === "INCOMING" ? "←" : "→";
        dirTd.textContent = arrow;
        dirTd.className = "connection-dir " + (c.direction === "INCOMING" ? "in" : "out");
        const srcTd = document.createElement("td");
        srcTd.textContent = c.src_ip;
        const dstTd = document.createElement("td");
        dstTd.textContent = c.dst_ip;
        const portTd = document.createElement("td");
        portTd.textContent = c.dst_port;
        const protoTd = document.createElement("td");
        protoTd.textContent = c.protocol;
        tr.appendChild(timeTd);
        tr.appendChild(dirTd);
        tr.appendChild(srcTd);
        tr.appendChild(dstTd);
        tr.appendChild(portTd);
        tr.appendChild(protoTd);
        tbody.appendChild(tr);
    }
}

function updateProcesses(list) {
    const tbody = $("top-processes");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!list || !list.length) return;
    for (const p of list) {
        const tr = document.createElement("tr");
        if (p.cpu_percent > 50) {
            tr.classList.add("process-row-high");
        }
        const nameTd = document.createElement("td");
        nameTd.textContent = p.name;
        const cpuTd = document.createElement("td");
        cpuTd.textContent = (p.cpu_percent || 0).toFixed(1);
        const memTd = document.createElement("td");
        memTd.textContent = (p.memory_percent || 0).toFixed(1);
        tr.appendChild(nameTd);
        tr.appendChild(cpuTd);
        tr.appendChild(memTd);
        tbody.appendChild(tr);
    }
}

function updateFileChanges(changes) {
    const list = $("file-changes");
    if (!list) return;
    list.innerHTML = "";
    if (!changes || !changes.length) {
        const li = document.createElement("li");
        li.textContent = "No recent file activity.";
        li.style.fontSize = "0.78rem";
        li.style.color = "#9ca3af";
        list.appendChild(li);
        return;
    }
    for (const ch of changes) {
        const li = document.createElement("li");
        li.className = "file-change-item";
        const header = document.createElement("div");
        header.className = "file-change-header";

        const badge = document.createElement("span");
        badge.className = "badge-action";
        const action = (ch.action || "").toUpperCase();
        badge.textContent = action;
        if (action === "CREATED") badge.classList.add("badge-created");
        else if (action === "MODIFIED") badge.classList.add("badge-modified");
        else if (action === "DELETED") badge.classList.add("badge-deleted");

        const timeSpan = document.createElement("span");
        timeSpan.className = "file-change-time";
        timeSpan.textContent = formatTime(ch.timestamp);

        header.appendChild(badge);
        header.appendChild(timeSpan);

        const pathSpan = document.createElement("span");
        pathSpan.className = "file-change-path";
        pathSpan.textContent = ch.path || "";

        li.appendChild(header);
        li.appendChild(pathSpan);
        list.appendChild(li);
    }
}

function updateBlockedIps(blocked) {
    const list = $("blocked-ips");
    if (!list) return;
    list.innerHTML = "";
    if (!blocked || !blocked.length) {
        const li = document.createElement("li");
        li.textContent = "No IPs are currently blocked by auto-defense.";
        li.style.fontSize = "0.78rem";
        li.style.color = "#9ca3af";
        list.appendChild(li);
        return;
    }
    for (const ip of blocked) {
        const li = document.createElement("li");
        li.className = "blocked-ip-item";
        const addr = document.createElement("span");
        addr.className = "blocked-ip-address";
        addr.textContent = ip;
        const badge = document.createElement("span");
        badge.className = "blocked-ip-badge";
        badge.textContent = "BLOCKED";
        li.appendChild(addr);
        li.appendChild(badge);
        list.appendChild(li);
    }
}

function resetThreatTable() {
    const rows = document.querySelectorAll("#threat-table-body tr");
    for (const row of rows) {
        const statusPill = row.querySelector(".status-pill");
        if (!statusPill) continue;
        statusPill.textContent = "Watching";
        statusPill.classList.remove("detected");
        statusPill.classList.add("neutral");
    }
}

function clearUiHistory() {
    lastAlertsTimestamps = new Set();
    lastStats = null;
    terminalLines = [];

    const alertsFeed = $("alerts-feed");
    if (alertsFeed) {
        alertsFeed.innerHTML = `
            <div class="empty-state">
                <span class="empty-main">No threats detected — System is secure ✓</span>
            </div>
        `;
    }

    updateBlockedIps([]);
    resetThreatTable();
    logToTerminal("info", "History cleared from dashboard.");
}

function appendAlertCard(alert) {
    const container = $("alerts-feed");
    if (!container) return;

    const empty = container.querySelector(".empty-state");
    if (empty) empty.remove();

    const card = document.createElement("div");
    card.className = "alert-card";
    const sevBadge = document.createElement("span");
    const sevClass = severityClass(alert.severity);
    sevBadge.className = `badge alert-severity ${sevClass}`;
    sevBadge.textContent = alert.severity || "LOW";

    if (alert.severity === "CRITICAL") {
        card.classList.add("alert-critical");
    }

    const typeDiv = document.createElement("div");
    typeDiv.className = "alert-type";
    typeDiv.textContent = alert.type || "UNKNOWN";

    const metaDiv = document.createElement("div");
    metaDiv.className = "alert-meta";
    const ip = alert.attacker_ip || "N/A";
    metaDiv.textContent = `Attacker: ${ip}`;

    const tsDiv = document.createElement("div");
    tsDiv.className = "alert-timestamp";
    tsDiv.textContent = formatTime(alert.timestamp);

    const detailsDiv = document.createElement("div");
    detailsDiv.className = "alert-details";
    detailsDiv.textContent = alert.details || "";

    card.appendChild(sevBadge);
    card.appendChild(typeDiv);
    card.appendChild(tsDiv);
    card.appendChild(detailsDiv);
    card.appendChild(metaDiv);

    container.appendChild(card);
    container.scrollTop = container.scrollHeight;
}

function processNewAlerts(alerts) {
    if (!Array.isArray(alerts)) return;
    const newSet = new Set();
    for (const a of alerts) {
        const key = `${a.timestamp}|${a.type}|${a.details}|${a.attacker_ip}`;
        newSet.add(key);
        if (!lastAlertsTimestamps.has(key)) {
            appendAlertCard(a);
            logToTerminal(a.severity === "CRITICAL" ? "CRITICAL" : "HIGH", `${a.type} — ${a.details || ""}`);
            updateThreatTable(a);
            if (a.severity === "CRITICAL") {
                showCriticalToast(a);
            }
        }
    }
    lastAlertsTimestamps = newSet;
}

async function fetchStats() {
    try {
        const res = await fetch("/stats");
        if (!res.ok) throw new Error("Failed to fetch stats");
        const data = await res.json();
        isLive = !!data.live;
        updateStatusPill(isLive);

        updateStatsCards(data);
        updateProtocolBars(data.protocol_stats || {});
        updateTopIps(data.top_ips || []);
        updateRecentConnections(data.recent_connections || []);

        const cpuRing = $("ring-cpu");
        const memRing = $("ring-mem");
        const diskRing = $("ring-disk");
        const cpuLabel = $("ring-cpu-value");
        const memLabel = $("ring-mem-value");
        const diskLabel = $("ring-disk-value");
        if (cpuRing && memRing && diskRing && cpuLabel && memLabel && diskLabel) {
            setRing(cpuRing, cpuLabel, data.cpu_percent || 0);
            setRing(memRing, memLabel, data.memory_percent || 0);
            setRing(diskRing, diskLabel, data.disk_percent || 0);
        }

        updateProcesses(data.recent_processes || []);
        updateFileChanges(data.recent_file_changes || []);
        updateBlockedIps(data.blocked_ips || []);
        processNewAlerts(data.alerts || []);

        lastStats = data;
    } catch (e) {
        console.error(e);
        logToTerminal("high", "Failed to fetch /stats — dashboard may be stale.");
    }
}

async function fetchAlerts() {
    try {
        const res = await fetch("/alerts");
        if (!res.ok) throw new Error("Failed to fetch alerts");
        const data = await res.json();
        processNewAlerts(data || []);
    } catch (e) {
        console.error(e);
        logToTerminal("high", "Failed to fetch /alerts.");
    }
}

function setupClock() {
    const el = $("clock");
    function tick() {
        if (!el) return;
        const now = new Date();
        el.textContent = now.toLocaleString();
    }
    tick();
    setInterval(tick, 1000);
}

function setupButtons() {
    const startBtn = $("start-btn");
    const stopBtn = $("stop-btn");
    const clearBtn = $("clear-btn");
    if (startBtn) {
        startBtn.addEventListener("click", async () => {
            try {
                const res = await fetch("/start", { method: "POST" });
                const data = await res.json().catch(() => ({}));
                if (data.status === "started") {
                    isLive = true;
                    logToTerminal("info", "Integrated monitor started (live mode).");
                } else if (data.status === "demo_only") {
                    isLive = false;
                    logToTerminal("high", `Cannot start live monitor on this host (${data.message || "dependencies missing"}). Staying in demo mode.`);
                }
                updateStatusPill(isLive);
            } catch (e) {
                console.error(e);
                logToTerminal("high", "Failed to start monitor.");
            }
        });
    }
    if (stopBtn) {
        stopBtn.addEventListener("click", async () => {
            try {
                const res = await fetch("/stop", { method: "POST" });
                if (res.ok) {
                    isLive = false;
                    logToTerminal("info", "Monitoring stopped. Switched to demo mode.");
                    updateStatusPill(false);
                }
            } catch (e) {
                console.error(e);
                logToTerminal("high", "Failed to stop monitor.");
            }
        });
    }
    if (clearBtn) {
        clearBtn.addEventListener("click", async () => {
            try {
                const res = await fetch("/clear_history", { method: "POST" });
                if (!res.ok) throw new Error("clear failed");
                clearUiHistory();
            } catch (e) {
                console.error(e);
                logToTerminal("high", "Failed to clear dashboard history.");
            }
        });
    }
}

function init() {
    setupClock();
    setupButtons();
    updateStatusPill(isLive);
    logToTerminal("info", "Dashboard loaded. Polling backend for telemetry.");
    fetchStats();
    fetchAlerts();
    setInterval(fetchStats, POLL_INTERVAL_MS);
    setInterval(fetchAlerts, POLL_INTERVAL_MS);
}

document.addEventListener("DOMContentLoaded", init);

