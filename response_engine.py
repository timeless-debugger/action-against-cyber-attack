import os
import subprocess
import platform
import time
import threading
import psutil
from datetime import datetime


class ResponseEngine:

    def __init__(self, auto_defense=True):
        self.auto_defense = auto_defense
        self.blocked_ips={}
        self.blocked_duration=300
        self.UNBLOCK_AFTER = self.blocked_duration
        self.actions_log = []
        self._start_unblock_watcher()

    def _start_unblock_watcher(self):
        """
        Start a background daemon thread that:
        - Runs forever in a loop
        - Sleeps 60 seconds between each run
        - Calls self._auto_unblock() each iteration
        Thread must be daemon=True so it dies when main program exits.
        """
        def watcher_loop():
            while True:
                time.sleep(60)
                self._auto_unblock()

        watcher_thread = threading.Thread(target=watcher_loop, daemon=True)
        watcher_thread.start()

    def _auto_unblock(self):
        """
        Loop through a copy of self.blocked_ips items.
        For each (ip, blocked_time):
            if time.time() - blocked_time > self.UNBLOCK_AFTER:
                call self.unblock_ip(ip)
        Use list(self.blocked_ips.items()) to avoid 
        RuntimeError from dict size changing during iteration.
        """
        current_time = time.time()
        for ip, blocked_time in list(self.blocked_ips.items()):
            if current_time - blocked_time > self.UNBLOCK_AFTER:
                self.unblock_ip(ip)

    def block_ip(self, ip):
        if ip in self.blocked_ips:
            return
        rule_name=f"Block_{ip}"
        try:
            subprocess.run([
            "netsh", "advfirewall", "firewall",
            "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}"
        ], check=True)
            print(f"[DEFENSE] Blocked IP: {ip}")
            self.blocked_ips[ip] = time.time()
            self.actions_log.append(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] BLOCK_IP {ip}"
            )
        except Exception as e:
            print(f"[ERROR] Failed to block IP {ip}: {e}")

    def unblock_ip(self, ip):
        rule_name = f"Block_{ip}"
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall",
                "delete", "rule",
                f"name={rule_name}"
            ], check=True)  
            print(f"[DEFENSE] Unblocked IP: {ip}")
            self.blocked_ips.pop(ip, None)
            self.actions_log.append(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] UNBLOCK_IP {ip}"
            )
        except Exception as e:
            print(f"[ERROR] Failed to unblock IP {ip}: {e}")

    def kill_process(self, pid, name):
        try:
            process = psutil.Process(pid)
            process.kill()
            print(f"[DEFENSE] Killed process PID={pid}")
            self.actions_log.append(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] KILL_PROCESS {name}({pid})"
            )
        except Exception as e:
            print(f"[ERROR] Failed to kill process {pid}: {e}")

    def print_alert_box(self, alert):
        """
        Print a colored alert box to terminal.
        
        Color rules:
            CRITICAL severity: prefix = \033[41m\033[97m  (red bg, white text)
            HIGH severity:     prefix = \033[91m           (bright red text)
            MEDIUM severity:   prefix = \033[93m           (yellow text)
            anything else:     prefix = \033[94m           (blue text)
        reset = \033[0m

        Print this exact format (use the color prefix on the 
        ATTACK DETECTED line only, reset after it):
        """
        alert_type = alert.get('type', 'UNKNOWN')
        severity = alert.get('severity', 'UNKNOWN')
        attacker = alert.get('attacker_ip', 'N/A')
        details = alert.get('details', 'N/A')[:34]

        reset = "\033[0m"

        if severity == 'CRITICAL':
            prefix = "\033[41m\033[97m"
        elif severity == 'HIGH':
            prefix = "\033[91m"
        elif severity == 'MEDIUM':
            prefix = "\033[93m"
        else:
            prefix = "\033[94m"

        print("╔══════════════════════════════════════════════╗")
        print(f"║  {prefix}ATTACK DETECTED{reset}                          ║")
        print(f"║  Type     : {alert_type:<34}║")
        print(f"║  Severity : {severity:<34}║")
        print(f"║  Attacker : {attacker:<34}║")
        print(f"║  Details  : {details:<34}║")
        print("╚══════════════════════════════════════════════╝")

    def respond(self, alert):
        """
        Step 1: Always call self.print_alert_box(alert)

        Step 2: If not self.auto_defense:
            print("  Auto-defense disabled — logging only")
            return

        Step 3: Get attacker_ip = alert.get('attacker_ip')
                Get alert_type  = alert.get('type', '')

        Step 4: Response logic based on alert type
        """
        # Step 1: Print alert box
        self.print_alert_box(alert)

        # Step 2: Check auto_defense
        if not self.auto_defense:
            print("  Auto-defense disabled — logging only")
            return

        # Step 3: Get alert info
        attacker_ip = alert.get('attacker_ip')
        alert_type = alert.get('type', '')

        # Step 4: Response logic
        if alert_type in ['PORT_SCAN', 'BRUTE_FORCE', 'DDOS', 'ARP_SPOOFING', 
                          'C2_BEACONING', 'DNS_TUNNELING', 'SENSITIVE_ACCESS']:
            if attacker_ip:
                self.block_ip(attacker_ip)

        if alert_type == 'LATERAL_MOVEMENT':
            if attacker_ip:
                self.block_ip(attacker_ip)
            print("\033[91m[DEFENSE]\033[0m Lateral movement contained")

        if alert_type == 'DATA_EXFILTRATION':
            if attacker_ip:
                self.block_ip(attacker_ip)
            print("\033[91m[DEFENSE]\033[0m Data exfiltration blocked")

        if alert_type == 'REVERSE_SHELL':
            if attacker_ip:
                self.block_ip(attacker_ip)
            print("\033[41m\033[97m REVERSE SHELL CONTAINED \033[0m")

        if alert_type == 'SUSPICIOUS_PROCESS':
            details = alert.get('details', '')
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    if proc.info['name'] and proc.info['name'].lower() in details.lower():
                        self.kill_process(proc.info['pid'], proc.info['name'])
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        if alert_type == 'RANSOMWARE':
            if attacker_ip:
                self.block_ip(attacker_ip)
            print("\033[41m\033[97m RANSOMWARE DETECTED — ISOLATING SYSTEM \033[0m")
            self.actions_log.append(f"[{datetime.now()}] RANSOMWARE RESPONSE TRIGGERED")

        # Step 5: Print summary line
        print(f"\033[92m[DEFENSE COMPLETE]\033[0m {alert_type} handled at {datetime.now().strftime('%H:%M:%S')}")
