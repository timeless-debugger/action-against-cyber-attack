"""
NETWORK TRAFFIC MONITORING MODULE
Objective 1.1: Network Traffic Monitoring
"""

from scapy.all import sniff, IP, TCP, UDP
import psutil
import threading
import time
from collections import defaultdict
from shared_utils import get_display_timestamp, print_section

# ============================================
# NETWORK MONITOR CLASS
# ============================================
class NetworkMonitor:
    """Handles all network traffic monitoring"""
    
    def __init__(self):
        self.running = False
        self.packet_count = 0
        self.total_bytes = 0
        
        # Statistics
        self.protocol_stats = {"TCP": 0, "UDP": 0, "OTHER": 0}
        self.bandwidth_per_ip = defaultdict(int)
        self.port_usage = defaultdict(int)
        self.app_connections = defaultdict(int)
        self.connection_log = []
        
        # Thread reference
        self.capture_thread = None
        self.app_thread = None
        self.last_packet_count = 0
        self.last_time = time.time()
    
    def is_local_ip(self, ip):
        """Check if IP is from local network"""
        return (ip.startswith('192.168.') or 
                ip.startswith('10.') or 
                ip.startswith('172.16.') or
                ip.startswith('127.0.'))
    
    def process_packet(self, packet):
        """Process each captured packet"""
        if packet.haslayer(IP):
            self.packet_count += 1
            packet_size = len(packet)
            self.total_bytes += packet_size
            
            timestamp = get_display_timestamp()
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Track bandwidth per IP
            self.bandwidth_per_ip[src_ip] += packet_size
            self.bandwidth_per_ip[dst_ip] += packet_size
            
            # Determine protocol and ports
            protocol = "OTHER"
            src_port = "N/A"
            dst_port = "N/A"
            
            if packet.haslayer(TCP):
                protocol = "TCP"
                self.protocol_stats["TCP"] += 1
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                self.port_usage[dst_port] += 1
            elif packet.haslayer(UDP):
                protocol = "UDP"
                self.protocol_stats["UDP"] += 1
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                self.port_usage[dst_port] += 1
            else:
                self.protocol_stats["OTHER"] += 1
            
            # Determine direction
            direction = "OUTGOING" if self.is_local_ip(src_ip) else "INCOMING"
            
            # Log connection
            connection_record = {
                'timestamp': timestamp,
                'direction': direction,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': protocol,
                'size_bytes': packet_size
            }
            
            self.connection_log.append(connection_record)
            if len(self.connection_log) > 500:
                self.connection_log.pop(0)
    
    def track_applications(self):
        """Monitor which applications use network"""
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        connections = proc.net_connections(kind='inet')
                        if connections:
                            app_name = proc.info['name']
                            self.app_connections[app_name] += len(connections)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                pass
            time.sleep(5)
    
    def capture_packets(self):
        sniff(
            iface=[
                "VirtualBox Host-Only Ethernet Adapter",
                "Wi-Fi"
            ],
            prn=self.process_packet,
            store=0
        )
    
    def start(self):
        """Start network monitoring"""
        self.running = True
        
        # Start packet capture thread
        self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        self.capture_thread.start()
        
        # Start application monitoring thread
        self.app_thread = threading.Thread(target=self.track_applications, daemon=True)
        self.app_thread.start()
        
        print(" Network Monitor started")
    
    def stop(self):
        """Stop network monitoring"""
        self.running = False
        print("  Network Monitor stopped")
    
    def get_stats(self):
        """Return current statistics"""
        return {
            'packet_count': self.packet_count,
            'total_bytes': self.total_bytes,
            'protocol_stats': dict(self.protocol_stats),
            'top_ips': sorted(self.bandwidth_per_ip.items(), 
                            key=lambda x: x[1], reverse=True)[:5],
            'top_ports': sorted(self.port_usage.items(), 
                              key=lambda x: x[1], reverse=True)[:10],
            'top_apps': sorted(self.app_connections.items(), 
                             key=lambda x: x[1], reverse=True)[:10],
            'recent_connections': self.connection_log[-5:]
        }
    
    def display_stats(self):
        """Display network statistics"""
        stats = self.get_stats()
        
        print_section(" NETWORK TRAFFIC MONITORING")
        print(f"   Packets Captured: {stats['packet_count']}")
        print(f"   Total Data: {stats['total_bytes']/1024:.2f} KB ({stats['total_bytes']/(1024*1024):.2f} MB)")
        print()
        
        # Protocol stats
        print("  Protocol Distribution:")
        for proto, count in stats['protocol_stats'].items():
            print(f"    {proto}: {count}")
        print()
        
        # Top IPs
        print("  Top 5 IPs:")
        for ip, bytes_used in stats['top_ips']:
            print(f"    {ip}: {bytes_used/1024:.2f} KB")
        print()
        
        # Recent connections
        print("  Recent Connections:")
        for conn in stats['recent_connections']:
            arrow = "→" if conn['direction'] == "OUTGOING" else "←"
            print(f"    [{conn['timestamp']}] {conn['src_ip']}:{conn['src_port']} {arrow} "
                  f"{conn['dst_ip']}:{conn['dst_port']} ({conn['protocol']})")
    
    def get_log_data(self):
        """Return data for logging"""
        return {
            'connections': self.connection_log,
            'stats': self.get_stats()
        }