"""
SYSTEM BEHAVIOR MONITORING MODULE
Objective 1.2: System Behavior Monitoring
"""

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import time
import os
from shared_utils import get_display_timestamp, print_section

# ============================================
# FILE SYSTEM HANDLER
# ============================================
class SystemFileHandler(FileSystemEventHandler):
    """Handle file system events"""
    
    def __init__(self, file_changes_list):
        self.file_changes = file_changes_list
    
    def on_created(self, event):
        if not event.is_directory:
            self.file_changes.append({
                'timestamp': get_display_timestamp(),
                'action': 'CREATED',
                'path': event.src_path
            })
    
    def on_modified(self, event):
        if not event.is_directory:
            self.file_changes.append({
                'timestamp': get_display_timestamp(),
                'action': 'MODIFIED',
                'path': event.src_path
            })
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.file_changes.append({
                'timestamp': get_display_timestamp(),
                'action': 'DELETED',
                'path': event.src_path
            })


# ============================================
# SYSTEM MONITOR CLASS
# ============================================
class SystemMonitor:
    """Handles all system behavior monitoring"""
    
    def __init__(self, monitor_path=None):
        self.running = False
        
        # Monitoring path
        self.monitor_path = monitor_path or os.getcwd()
        
        # Data storage
        self.resource_log = []
        self.process_log = []
        self.file_changes = []
        self.session_log = []
        
        # File system observer
        self.file_observer = None
        
        # Thread references
        self.resource_thread = None
        self.process_thread = None
        self.session_thread = None
        self.file_thread = None
    
    def monitor_resources(self):
        """Monitor CPU, Memory, Disk"""
        while self.running:
            timestamp = get_display_timestamp()
            
            cpu = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            self.resource_log.append({
                'timestamp': timestamp,
                'cpu_percent': cpu,
                'memory_percent': memory.percent,
                'memory_used_gb': memory.used / (1024**3),
                'disk_percent': disk.percent,
                'disk_used_gb': disk.used / (1024**3)
            })
            
            if len(self.resource_log) > 1000:
                self.resource_log.pop(0)
            
            time.sleep(5)
    
    def monitor_processes(self):
        """Monitor running processes"""
        while self.running:
            timestamp = get_display_timestamp()
            
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            top_processes = sorted(processes, 
                                  key=lambda x: x['cpu_percent'] or 0, 
                                  reverse=True)[:5]
            
            for proc in top_processes:
                self.process_log.append({
                    'timestamp': timestamp,
                    'pid': proc['pid'],
                    'name': proc['name'],
                    'cpu_percent': proc['cpu_percent'] or 0,
                    'memory_percent': proc['memory_percent'] or 0
                })
            
            if len(self.process_log) > 1000:
                self.process_log.pop(0)
            
            time.sleep(10)
    
    def monitor_sessions(self):
        """Monitor user sessions"""
        known_sessions = set()
        
        while self.running:
            current_users = psutil.users()
            current_sessions = set()
            
            for user in current_users:
                session_id = f"{user.name}_{user.terminal}_{user.started}"
                current_sessions.add(session_id)
                
                if session_id not in known_sessions:
                    self.session_log.append({
                        'timestamp': get_display_timestamp(),
                        'action': 'LOGIN',
                        'user': user.name,
                        'terminal': user.terminal,
                        'host': user.host
                    })
                    known_sessions.add(session_id)
            
            logged_out = known_sessions - current_sessions
            for session_id in logged_out:
                self.session_log.append({
                    'timestamp': get_display_timestamp(),
                    'action': 'LOGOUT',
                    'session': session_id
                })
                known_sessions.remove(session_id)
            
            time.sleep(10)
    
    def start_file_monitoring(self):
        """Start file system monitoring"""
        event_handler = SystemFileHandler(self.file_changes)
        self.file_observer = Observer()
        self.file_observer.schedule(event_handler, self.monitor_path, recursive=True)
        self.file_observer.start()
    
    def start(self):
        """Start system monitoring"""
        self.running = True
        
        # Start resource monitoring
        self.resource_thread = threading.Thread(target=self.monitor_resources, daemon=True)
        self.resource_thread.start()
        
        # Start process monitoring
        self.process_thread = threading.Thread(target=self.monitor_processes, daemon=True)
        self.process_thread.start()
        
        # Start session monitoring
        self.session_thread = threading.Thread(target=self.monitor_sessions, daemon=True)
        self.session_thread.start()
        
        # Start file system monitoring
        self.start_file_monitoring()
        
        print(" System Monitor started")
    
    def stop(self):
        """Stop system monitoring"""
        self.running = False
        
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
        
        print("  System Monitor stopped")
    
    def get_stats(self):
        """Return current statistics"""
        latest_resource = self.resource_log[-1] if self.resource_log else None
        recent_processes = self.process_log[-5:] if self.process_log else []
        
        return {
            'latest_resource': latest_resource,
            'recent_processes': recent_processes,
            'file_changes_count': len(self.file_changes),
            'recent_file_changes': self.file_changes[-5:] if self.file_changes else [],
            'session_count': len(self.session_log),
            'active_users': len(psutil.users())
        }
    
    def display_stats(self):
        """Display system statistics"""
        stats = self.get_stats()
        
        print_section(" SYSTEM BEHAVIOR MONITORING")
        
        # Resources
        if stats['latest_resource']:
            res = stats['latest_resource']
            print(f"  CPU Usage:    {res['cpu_percent']:.2f}%")
            print(f"  Memory Usage: {res['memory_percent']:.2f}% ({res['memory_used_gb']:.2f} GB)")
            print(f"  Disk Usage:   {res['disk_percent']:.2f}% ({res['disk_used_gb']:.2f} GB)")
        print()
        
        # Top processes
        print("  Top Processes:")
        for proc in stats['recent_processes']:
            print(f"    {proc['name']}: CPU={proc['cpu_percent']:.1f}% MEM={proc['memory_percent']:.1f}%")
        print()
        
        # File changes
        print(f"  File Changes (Total: {stats['file_changes_count']}):")
        for change in stats['recent_file_changes']:
            print(f"    [{change['timestamp']}] {change['action']}: {change['path']}")
        print()
        
        # Sessions
        print(f"  Active Users: {stats['active_users']}")
    
    def get_log_data(self):
        """Return data for logging"""
        return {
            'resources': self.resource_log,
            'processes': self.process_log,
            'file_changes': self.file_changes,
            'sessions': self.session_log
        }