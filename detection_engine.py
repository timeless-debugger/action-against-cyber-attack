import time
from datetime import datetime

class DetectionEngine:
    def __init__(self):
        self.alerts = []
        self.CPU_THRESHOLD = 90
        self.PACKET_THRESHOLD = 200
        self.PORT_SCAN_THRESHOLD = 15
        self.alerted = {}
        self.SEVERITY_SCORE = {
            "CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1
        }

    def check_port_scan(self, network_monitor):
        connections = network_monitor.connection_log
        ip_ports = {}
        for conn in connections:
            ip = conn['src_ip']
            port = conn['dst_port']
            if isinstance(port, int) or (isinstance(port, str) and port.isdigit()):
                if ip not in ip_ports:
                    ip_ports[ip] = set()
                ip_ports[ip].add(int(port) if isinstance(port, str) else port)
        
        for ip, ports in ip_ports.items():
            if len(ports) > 15:
                alert = {
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "details": f"{len(ports)} ports scanned by {ip}",
                    "attacker_ip": ip
                }
                return alert
        return None

    def check_bruteforce(self, network_monitor):
        connections = network_monitor.connection_log
        ip_attempts = {}
        for conn in connections:
            dst_port = conn['dst_port']
            if dst_port in [21, 22, 3389]:
                ip = conn['src_ip']
                ip_attempts[ip] = ip_attempts.get(ip, 0) + 1

        for ip, count in ip_attempts.items():
            if count > 10:
                alert = {
                    "type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "details": f"{count} login attempts from {ip}",
                    "attacker_ip": ip
                }
                return alert
        return None

    def check_ddos(self, network_monitor):
        current_time = time.time()
        current_packets = network_monitor.packet_count
        time_diff = current_time - network_monitor.last_time
        packet_diff = current_packets - network_monitor.last_packet_count
        if time_diff == 0:
            return None

        rate = packet_diff / time_diff
        network_monitor.last_time = current_time
        network_monitor.last_packet_count = current_packets
        if rate > 200:
            alert = {
                "type": "DDOS",
                "severity": "CRITICAL",
                "details": f"High traffic rate: {rate:.2f} packets/sec"
            }
            return alert
        return None

    def check_sensitive_ports(self, network_monitor):
        connections = network_monitor.connection_log
        sensitive_ports = [21, 22, 445, 3389]
        for conn in connections:
            dst_port = conn['dst_port']
            if isinstance(dst_port, str) and dst_port.isdigit():
                dst_port = int(dst_port)
            if dst_port in sensitive_ports:
                alert = {
                    "type": "SENSITIVE_ACCESS",
                    "severity": "HIGH",
                    "details": f"Access to port {conn['dst_port']} from {conn['src_ip']}",
                    "attacker_ip": conn['src_ip']
                }
                return alert
        return None

    def check_suspicious_process(self, system_monitor):
        stats = system_monitor.get_stats()
        processes = stats.get('recent_processes', [])
        for proc in processes:
            cpu_percent = proc.get('cpu_percent', 0) or 0
            if cpu_percent > 50:
                alert = {
                    "type": "SUSPICIOUS_PROCESS",
                    "severity": "HIGH",
                    "details": f"{proc['name']} using high CPU"
                }
                return alert
        return None

    def check_data_exfiltration(self, network_monitor):
        for ip, bytes_used in network_monitor.bandwidth_per_ip.items():
            if bytes_used > 5 * 1024 * 1024:
                alert = {
                    "type": "DATA_EXFILTRATION",
                    "severity": "CRITICAL",
                    "details": f"Large data sent to {ip}",
                    "attacker_ip": ip
                }
                return alert
        return None

    def check_arp_spoofing(self, network_monitor):
        """
        Look through network_monitor.connection_log (full list).
        Count connections per src_ip where dst_port == 'N/A'.
        If any src_ip has more than 50 such connections:
            return alert with type ARP_SPOOFING
        """
        ip_counts = {}
        for conn in network_monitor.connection_log:
            if conn.get('dst_port') == 'N/A':
                src_ip = conn['src_ip']
                ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1

        for ip, count in ip_counts.items():
            if count > 50:
                alert = {
                    "type": "ARP_SPOOFING",
                    "severity": "CRITICAL",
                    "details": f"ARP spoofing detected from {ip}",
                    "attacker_ip": ip
                }
                return alert
        return None

    def check_dns_tunneling(self, network_monitor):
        """
        Look through network_monitor.connection_log (full list).
        Count connections per src_ip where:
            dst_port == 53 AND protocol == 'UDP'
        If any src_ip has more than 20 such connections:
            return alert with type DNS_TUNNELING
        """
        ip_counts = {}
        for conn in network_monitor.connection_log:
            dst_port = conn.get('dst_port')
            protocol = conn.get('protocol', '')
            if dst_port == 53 and protocol == 'UDP':
                src_ip = conn['src_ip']
                ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1

        for ip, count in ip_counts.items():
            if count > 20:
                alert = {
                    "type": "DNS_TUNNELING",
                    "severity": "HIGH",
                    "details": f"DNS tunneling detected from {ip}",
                    "attacker_ip": ip
                }
                return alert
        return None

    def check_c2_beaconing(self, network_monitor):
        """
        Look through network_monitor.connection_log (full list).
        Count how many times each src_ip appears total.
        If any src_ip appears 6 or more times:
            return alert with type C2_BEACONING
        """
        ip_counts = {}
        for conn in network_monitor.connection_log:
            src_ip = conn['src_ip']
            ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1

        for ip, count in ip_counts.items():
            if count >= 6:
                alert = {
                    "type": "C2_BEACONING",
                    "severity": "CRITICAL",
                    "details": f"C2 beaconing detected from {ip} ({count} connections)",
                    "attacker_ip": ip
                }
                return alert
        return None

    def check_lateral_movement(self, network_monitor):
        """
        Look through network_monitor.connection_log (full list).
        For each src_ip, collect the set of dst_ips it connects to
        where BOTH src_ip AND dst_ip start with '192.168.' or '10.'
        If any src_ip connects to 4 or more different internal dst_ips:
            return alert with type LATERAL_MOVEMENT
        """
        def is_internal_ip(ip):
            return ip.startswith('192.168.') or ip.startswith('10.')

        ip_to_internal_dsts = {}
        for conn in network_monitor.connection_log:
            src_ip = conn['src_ip']
            dst_ip = conn['dst_ip']
            if is_internal_ip(src_ip) and is_internal_ip(dst_ip):
                if src_ip not in ip_to_internal_dsts:
                    ip_to_internal_dsts[src_ip] = set()
                ip_to_internal_dsts[src_ip].add(dst_ip)

        for ip, dst_ips in ip_to_internal_dsts.items():
            if len(dst_ips) >= 4:
                alert = {
                    "type": "LATERAL_MOVEMENT",
                    "severity": "HIGH",
                    "details": f"Lateral movement from {ip} to {len(dst_ips)} internal hosts",
                    "attacker_ip": ip
                }
                return alert
        return None

    def check_ransomware(self, system_monitor):
        """
        Look at system_monitor.file_changes list (full list).
        Count entries where timestamp is within last 10 seconds.
        If more than 20 file changes in last 10 seconds:
            return alert with type RANSOMWARE
        """
        now = datetime.now()
        recent_count = 0

        for change in system_monitor.file_changes:
            ts_str = change.get('timestamp', '')
            try:
                ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                diff = (now - ts).total_seconds()
                if diff <= 10:
                    recent_count += 1
            except (ValueError, TypeError):
                continue

        if recent_count > 20:
            alert = {
                "type": "RANSOMWARE",
                "severity": "CRITICAL",
                "details": f"Ransomware detected: {recent_count} file changes in 10 seconds"
            }
            return alert
        return None

    def check_reverse_shell(self, network_monitor, system_monitor):
        """
        Get recent_processes from system_monitor.get_stats()['recent_processes']
        Check if any process name contains cmd, bash, sh, powershell, nc, netcat
        AND check network_monitor.connection_log for incoming connection on high port
        """
        suspicious_shells = ['cmd', 'bash', 'sh', 'powershell', 'nc', 'netcat']
        allowed_ports = [3389, 8080, 443, 80, 8443]

        # Check for suspicious shell processes
        found_shell_process = False
        for proc in system_monitor.get_stats().get('recent_processes', []):
            proc_name = proc.get('name', '').lower()
            for shell in suspicious_shells:
                if shell in proc_name:
                    found_shell_process = True
                    break
            if found_shell_process:
                break

        if not found_shell_process:
            return None

        # Check for incoming connections on suspicious ports
        for conn in network_monitor.connection_log:
            direction = conn.get('direction', '')
            dst_port = conn.get('dst_port')

            if direction == 'INCOMING' and isinstance(dst_port, int):
                if dst_port > 1024 and dst_port not in allowed_ports:
                    # Find the process name for the alert message
                    for proc in system_monitor.get_stats().get('recent_processes', []):
                        proc_name = proc.get('name', 'unknown')
                        for shell in suspicious_shells:
                            if shell in proc_name.lower():
                                alert = {
                                    "type": "REVERSE_SHELL",
                                    "severity": "CRITICAL",
                                    "details": f"Reverse shell detected: {proc_name} with incoming connection on port {dst_port}"
                                }
                                return alert

        return None

    def analyze(self, system_monitor, network_monitor):
        """
        Run all detection checks, deduplicate alerts, sort by severity.
        """
        raw_alerts = []

        # Step 1: Run all checks
        result = self.check_port_scan(network_monitor)
        if result:
            raw_alerts.append(result)

        result = self.check_bruteforce(network_monitor)
        if result:
            raw_alerts.append(result)

        result = self.check_ddos(network_monitor)
        if result:
            raw_alerts.append(result)

        result = self.check_sensitive_ports(network_monitor)
        if result:
            raw_alerts.append(result)

        result = self.check_suspicious_process(system_monitor)
        if result:
            raw_alerts.append(result)

        result = self.check_data_exfiltration(network_monitor)
        if result:
            raw_alerts.append(result)

        result = self.check_arp_spoofing(network_monitor)
        if result:
            raw_alerts.append(result)

        result = self.check_dns_tunneling(network_monitor)
        if result:
            raw_alerts.append(result)

        result = self.check_c2_beaconing(network_monitor)
        if result:
            raw_alerts.append(result)

        result = self.check_lateral_movement(network_monitor)
        if result:
            raw_alerts.append(result)

        result = self.check_ransomware(system_monitor)
        if result:
            raw_alerts.append(result)

        result = self.check_reverse_shell(network_monitor, system_monitor)
        if result:
            raw_alerts.append(result)

        # Step 2: Deduplication
        final_alerts = []
        current_time = time.time()

        for alert in raw_alerts:
            key = (alert['type'], alert.get('attacker_ip', ''))
            if key not in self.alerted or (current_time - self.alerted[key] > 60):
                final_alerts.append(alert)
                self.alerted[key] = current_time

        # Step 3: Sort by severity score descending
        final_alerts.sort(
            key=lambda x: self.SEVERITY_SCORE.get(x.get('severity', 'LOW'), 1),
            reverse=True
        )

        # Step 4: Return sorted list
        return final_alerts
