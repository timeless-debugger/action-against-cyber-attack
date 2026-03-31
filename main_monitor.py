import time
from network_monitor import NetworkMonitor
from system_monitor import SystemMonitor
from shared_utils import (
    print_header, clear_screen, save_to_csv, 
    get_timestamp, save_summary_report
)
from detection_engine import DetectionEngine
from response_engine import ResponseEngine
import threading
# ============================================
# MAIN MONITORING CLASS
# ============================================
class IntegratedMonitor:
    """Combines network and system monitoring"""
    
    def __init__(self):
        self.network_monitor = NetworkMonitor()
        self.system_monitor = SystemMonitor()
        self.running = False
        self.detector = DetectionEngine()
        self.responder = ResponseEngine()
        self.detection_thread = None
    
    def start(self):
        """Start both monitors"""
        print_header("INTEGRATED SECURITY MONITORING SYSTEM")
        print("\n Starting all monitoring systems...\n")
        
        # Start network monitor
        self.network_monitor.start()
        time.sleep(1)
        
        # Start system monitor
        self.system_monitor.start()
        time.sleep(1)
        
        self.running = True
        self.detection_thread = threading.Thread(
            target=self.detection_loop,
            daemon=True
        )
        self.detection_thread.start()

        print("\n All monitors are running!\n")
        print(" Threat detection engine started\n")
    def detection_loop(self):
        while self.running:
            try:
                alerts = self.detector.analyze(
                    self.system_monitor,
                    self.network_monitor
                )

                for alert in alerts:
                    print("\n SECURITY ALERT:", alert)
                    self.responder.respond(alert)

            except Exception as e:
                print("Detection Error:", e)

            time.sleep(5)
        
    def display_dashboard(self):
        """Display combined dashboard"""
        while self.running:
            clear_screen()
            
            print_header("INTEGRATED SECURITY MONITORING DASHBOARD")
            print(f" {get_timestamp()}\n")
            
            # Display network stats
            self.network_monitor.display_stats()
            
            # Display system stats
            self.system_monitor.display_stats()
            
            print("\n" + "=" * 90)
            print("Press Ctrl+C to stop and save all logs")
            print("=" * 90)
            
            time.sleep(3)  # Update every 3 seconds
    
    def stop(self):
        """Stop both monitors"""
        self.running = False
        
        print("\n\n  Stopping all monitors...\n")
        
        self.network_monitor.stop()
        self.system_monitor.stop()
    
    def save_logs(self):
        """Save all logs from both monitors"""
        print("\n Saving all logs...\n")
        
        timestamp = get_timestamp()
        
        # Get data from both monitors
        network_data = self.network_monitor.get_log_data()
        system_data = self.system_monitor.get_log_data()
        
        # === SAVE NETWORK LOGS ===
        
        # Network connections
        if network_data['connections']:
            filename = f"network_connections_{timestamp}.csv"
            fieldnames = ['timestamp', 'direction', 'src_ip', 'src_port', 
                         'dst_ip', 'dst_port', 'protocol', 'size_bytes']
            success, path = save_to_csv(filename, network_data['connections'], fieldnames)
            if success:
                print(f" Saved: {path}")
        
        # === SAVE SYSTEM LOGS ===
        
        # Resource usage
        if system_data['resources']:
            filename = f"system_resources_{timestamp}.csv"
            fieldnames = ['timestamp', 'cpu_percent', 'memory_percent', 
                         'memory_used_gb', 'disk_percent', 'disk_used_gb']
            success, path = save_to_csv(filename, system_data['resources'], fieldnames)
            if success:
                print(f" Saved: {path}")
        
        # Process log
        if system_data['processes']:
            filename = f"system_processes_{timestamp}.csv"
            fieldnames = ['timestamp', 'pid', 'name', 'cpu_percent', 'memory_percent']
            success, path = save_to_csv(filename, system_data['processes'], fieldnames)
            if success:
                print(f" Saved: {path}")
        
        # File changes
        if system_data['file_changes']:
            filename = f"file_changes_{timestamp}.csv"
            fieldnames = ['timestamp', 'action', 'path']
            success, path = save_to_csv(filename, system_data['file_changes'], fieldnames)
            if success:
                print(f" Saved: {path}")
        
        # Session log
        if system_data['sessions']:
            filename = f"user_sessions_{timestamp}.csv"
            fieldnames = list(system_data['sessions'][0].keys())
            success, path = save_to_csv(filename, system_data['sessions'], fieldnames)
            if success:
                print(f" Saved: {path}")
        
        # === SAVE SUMMARY REPORT ===
        
        net_stats = network_data['stats']
        sys_stats = self.system_monitor.get_stats()
        
        summary = {
            "NETWORK MONITORING SUMMARY": {
                "Total Packets": net_stats['packet_count'],
                "Total Data (MB)": f"{net_stats['total_bytes']/(1024*1024):.2f}",
                "TCP Packets": net_stats['protocol_stats']['TCP'],
                "UDP Packets": net_stats['protocol_stats']['UDP'],
                "Unique IPs Tracked": len(self.network_monitor.bandwidth_per_ip),
            },
            "SYSTEM MONITORING SUMMARY": {
                "Resource Snapshots": len(system_data['resources']),
                "Process Records": len(system_data['processes']),
                "File Changes Detected": len(system_data['file_changes']),
                "Session Events": len(system_data['sessions']),
            },
            "TOP 5 IPS BY BANDWIDTH": [
                f"{ip}: {bytes_used/(1024*1024):.2f} MB" 
                for ip, bytes_used in net_stats['top_ips']
            ],
            "TOP 5 PORTS": [
                f"Port {port}: {count} connections" 
                for port, count in net_stats['top_ports'][:5]
            ]
        }
        
        summary_filename = f"monitoring_summary_{timestamp}.txt"
        success, path = save_summary_report(summary_filename, summary)
        if success:
            print(f" Saved: {path}")
        
        print("\n All logs saved successfully!")
    
    def run(self):
        """Main run method"""
        try:
            # Start monitors
            self.start()
            
            # Wait for initialization
            time.sleep(2)
            
            # Display dashboard
            self.display_dashboard()
            
        except KeyboardInterrupt:
            # Stop monitors
            self.stop()
            
            # Save logs
            self.save_logs()
            
            # Final summary
            print("\n" + "=" * 90)
            print("FINAL STATISTICS")
            print("=" * 90)
            print(f"Network Packets: {self.network_monitor.packet_count}")
            print(f"Network Data: {self.network_monitor.total_bytes/(1024*1024):.2f} MB")
            print(f"Resource Logs: {len(self.system_monitor.resource_log)}")
            print(f"File Changes: {len(self.system_monitor.file_changes)}")
            print("=" * 90)
            print("\n Monitoring session complete!\n")


# ============================================
# MAIN ENTRY POINT
# ============================================
if __name__ == "__main__":
    monitor = IntegratedMonitor()
    monitor.run()