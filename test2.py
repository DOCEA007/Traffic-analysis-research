import time
import socket
import psutil
import win32evtlog
import win32evtlogutil
import win32con
from datetime import datetime, timedelta
from collections import defaultdict
import csv
import os
import threading
from typing import Dict, Set, Tuple

# Configuration
DEFENDER_DOMAINS = [
    "definitionupdates.microsoft.com",
    "go.microsoft.com",
    "wd.microsoft.com",
    "wdcp.microsoft.com",
    "download.microsoft.com"
]

DEFENDER_PROCESSES = [
    "MsMpEng.exe",
    "MpCmdRun.exe", 
    "svchost.exe",
    "NisSrv.exe"
]

PORTS = {80, 443}
POLL_SECONDS = 0.5
DNS_REFRESH_SECONDS = 60
EVENT_CHECK_SECONDS = 5

LOG_FILE = "defender_updates.csv"
SUMMARY_FILE = "defender_summary.txt"

# Event IDs for Windows Defender
DEFENDER_EVENT_IDS = {
    2000: "Signature update succeeded",
    2001: "Signature update failed",
    2002: "Engine update completed",
    2003: "Engine update failed", 
    2004: "Signature reversion",
    2005: "Platform update completed",
    2006: "Platform update failed",
    5007: "Configuration changed"
}

class DefenderUpdateMonitor:
    def __init__(self):
        self.target_ips: Dict[str, Set[str]] = {}
        self.last_dns_refresh = 0.0
        self.seen_connections = set()
        self.connection_data: Dict[Tuple, Dict] = {}
        self.last_event_time = datetime.now() - timedelta(minutes=5)
        self.update_detected = threading.Event()
        self.csv_file = None
        self.csv_writer = None
        
    def resolve_all_domains(self):
        """Resolve all Defender update domains to IPs"""
        for domain in DEFENDER_DOMAINS:
            ips = set()
            try:
                infos = socket.getaddrinfo(domain, None)
                for _, _, _, _, sockaddr in infos:
                    ips.add(sockaddr[0])
                self.target_ips[domain] = ips
            except socket.gaierror:
                self.target_ips[domain] = set()
        
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] DNS Resolution:")
        for domain, ips in self.target_ips.items():
            if ips:
                print(f"  {domain}: {', '.join(sorted(ips))}")

    def get_all_target_ips(self) -> Set[str]:
        """Get flat set of all target IPs"""
        all_ips = set()
        for ips in self.target_ips.values():
            all_ips.update(ips)
        return all_ips

    def find_domain_for_ip(self, ip: str) -> str:
        """Find which domain an IP belongs to"""
        for domain, ips in self.target_ips.items():
            if ip in ips:
                return domain
        return "unknown"

    def get_process_info(self, pid: int) -> Tuple[str, str]:
        """Get process name and exe path"""
        try:
            p = psutil.Process(pid)
            return p.name(), p.exe()
        except Exception:
            return "<unknown>", "<unavailable>"

    def init_csv_log(self):
        """Initialize CSV logging"""
        file_exists = os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0
        self.csv_file = open(LOG_FILE, "a", encoding="utf-8", newline="")
        self.csv_writer = csv.writer(self.csv_file)
        
        if not file_exists:
            self.csv_writer.writerow([
                "timestamp", "event_type", "domain", "status", 
                "local_ip", "local_port", "remote_ip", "remote_port",
                "bytes_sent", "bytes_recv", "process_name", "pid", "exe",
                "event_id", "event_message", "signature_version"
            ])
            self.csv_file.flush()

    def log_connection(self, conn_info: Dict, event_data: Dict = None):
        """Log connection to CSV"""
        row = [
            conn_info.get("timestamp", ""),
            conn_info.get("event_type", "connection"),
            conn_info.get("domain", ""),
            conn_info.get("status", ""),
            conn_info.get("local_ip", ""),
            conn_info.get("local_port", ""),
            conn_info.get("remote_ip", ""),
            conn_info.get("remote_port", ""),
            conn_info.get("bytes_sent", 0),
            conn_info.get("bytes_recv", 0),
            conn_info.get("process_name", ""),
            conn_info.get("pid", ""),
            conn_info.get("exe", ""),
            event_data.get("event_id", "") if event_data else "",
            event_data.get("message", "") if event_data else "",
            event_data.get("signature_version", "") if event_data else ""
        ]
        self.csv_writer.writerow(row)
        self.csv_file.flush()

    def monitor_network(self):
        """Monitor network connections for Defender update traffic"""
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Starting network monitoring...")
        print(f"Watching ports: {sorted(PORTS)}")
        print(f"Monitoring processes: {', '.join(DEFENDER_PROCESSES)}\n")
        
        while True:
            now = time.time()
            
            # Refresh DNS periodically
            if now - self.last_dns_refresh >= DNS_REFRESH_SECONDS:
                self.resolve_all_domains()
                self.last_dns_refresh = now

            try:
                conns = psutil.net_connections(kind="inet")
            except Exception as e:
                print(f"Error reading connections: {e}")
                time.sleep(POLL_SECONDS)
                continue

            target_ips = self.get_all_target_ips()
            
            for c in conns:
                if not c.raddr:
                    continue

                rip = c.raddr.ip if hasattr(c.raddr, 'ip') else c.raddr[0]
                rport = c.raddr.port if hasattr(c.raddr, 'port') else c.raddr[1]
                
                if rip not in target_ips or rport not in PORTS:
                    continue

                lip = c.laddr.ip if hasattr(c.laddr, 'ip') else c.laddr[0]
                lport = c.laddr.port if hasattr(c.laddr, 'port') else c.laddr[1]
                key = (c.pid, lip, lport, rip, rport)

                if not c.pid:
                    continue

                name, exe = self.get_process_info(c.pid)
                
                # Filter for Defender processes
                if not any(proc.lower() in name.lower() for proc in DEFENDER_PROCESSES):
                    continue

                domain = self.find_domain_for_ip(rip)
                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # Track connection data
                if key not in self.connection_data:
                    self.connection_data[key] = {
                        "first_seen": ts,
                        "domain": domain,
                        "process_name": name,
                        "exe": exe,
                        "pid": c.pid,
                        "local_ip": lip,
                        "local_port": lport,
                        "remote_ip": rip,
                        "remote_port": rport,
                        "initial_status": c.status
                    }

                # New connection
                if key not in self.seen_connections:
                    self.seen_connections.add(key)
                    
                    print(f"🔵 [{ts}] NEW CONNECTION")
                    print(f"   Process: {name} (PID: {c.pid})")
                    print(f"   Domain: {domain}")
                    print(f"   {lip}:{lport} → {rip}:{rport}")
                    print(f"   Status: {c.status}\n")
                    
                    conn_info = {
                        "timestamp": ts,
                        "event_type": "new_connection",
                        "domain": domain,
                        "status": c.status,
                        "local_ip": lip,
                        "local_port": lport,
                        "remote_ip": rip,
                        "remote_port": rport,
                        "bytes_sent": 0,
                        "bytes_recv": 0,
                        "process_name": name,
                        "pid": c.pid,
                        "exe": exe
                    }
                    self.log_connection(conn_info)
                    self.update_detected.set()

            time.sleep(POLL_SECONDS)

    def check_event_viewer(self):
        """Monitor Windows Event Viewer for Defender update events"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting Event Viewer monitoring...\n")
        
        server = 'localhost'
        logtype = 'Microsoft-Windows-Windows Defender/Operational'
        
        hand = None
        try:
            hand = win32evtlog.OpenEventLog(server, logtype)
        except Exception as e:
            print(f"⚠️  Could not open Event Log: {e}")
            print("   Run as Administrator to access Defender event logs\n")
            return

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        while True:
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                for event in events:
                    event_time = event.TimeGenerated
                    
                    if event_time <= self.last_event_time:
                        continue
                    
                    event_id = event.EventID & 0xFFFF
                    
                    if event_id in DEFENDER_EVENT_IDS:
                        self.last_event_time = event_time
                        
                        # Parse event data
                        try:
                            msg = win32evtlogutil.SafeFormatMessage(event, logtype)
                        except:
                            msg = str(event.StringInserts) if event.StringInserts else ""
                        
                        # Extract signature version if available
                        sig_version = ""
                        if event.StringInserts:
                            for insert in event.StringInserts:
                                if insert and "1." in str(insert) and len(str(insert)) > 10:
                                    sig_version = str(insert)
                                    break
                        
                        ts = event_time.strftime('%Y-%m-%d %H:%M:%S')
                        
                        if event_id == 2000:
                            print(f"✅ [{ts}] UPDATE SUCCEEDED (Event {event_id})")
                        elif event_id == 2001:
                            print(f"❌ [{ts}] UPDATE FAILED (Event {event_id})")
                        else:
                            print(f"ℹ️  [{ts}] {DEFENDER_EVENT_IDS[event_id]} (Event {event_id})")
                        
                        if sig_version:
                            print(f"   Signature Version: {sig_version}")
                        if msg and len(msg) < 200:
                            print(f"   Message: {msg[:200]}")
                        print()
                        
                        # Log event
                        event_data = {
                            "event_id": event_id,
                            "message": DEFENDER_EVENT_IDS.get(event_id, "Unknown"),
                            "signature_version": sig_version
                        }
                        
                        conn_info = {
                            "timestamp": ts,
                            "event_type": "event_viewer",
                            "domain": "",
                            "status": "",
                            "local_ip": "",
                            "local_port": "",
                            "remote_ip": "",
                            "remote_port": "",
                            "bytes_sent": 0,
                            "bytes_recv": 0,
                            "process_name": "Windows Defender",
                            "pid": "",
                            "exe": ""
                        }
                        self.log_connection(conn_info, event_data)
                        
                        # Generate summary report
                        if event_id in [2000, 2001]:
                            self.generate_summary_report(event_id, sig_version, ts)
                
            except Exception as e:
                if "No more data is available" not in str(e):
                    print(f"Event log error: {e}")
            
            time.sleep(EVENT_CHECK_SECONDS)

    def generate_summary_report(self, event_id: int, sig_version: str, event_time: str):
        """Generate a summary report correlating network and event data"""
        with open(SUMMARY_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"DEFENDER UPDATE DETECTED: {event_time}\n")
            f.write(f"{'='*70}\n")
            f.write(f"Event ID: {event_id} - {DEFENDER_EVENT_IDS.get(event_id)}\n")
            if sig_version:
                f.write(f"Signature Version: {sig_version}\n")
            f.write(f"\nRecent Network Activity:\n")
            f.write(f"{'-'*70}\n")
            
            # Show recent connections (last 5 minutes)
            cutoff_time = datetime.now() - timedelta(minutes=5)
            
            for key, data in self.connection_data.items():
                try:
                    conn_time = datetime.strptime(data["first_seen"], '%Y-%m-%d %H:%M:%S')
                    if conn_time >= cutoff_time:
                        f.write(f"\n  Time: {data['first_seen']}\n")
                        f.write(f"  Process: {data['process_name']} (PID: {data['pid']})\n")
                        f.write(f"  Domain: {data['domain']}\n")
                        f.write(f"  Connection: {data['local_ip']}:{data['local_port']} → {data['remote_ip']}:{data['remote_port']}\n")
                except:
                    pass
            
            f.write(f"\n{'='*70}\n\n")

    def run(self):
        """Run both monitors in parallel"""
        print("="*70)
        print("MICROSOFT DEFENDER UPDATE MONITOR")
        print("="*70)
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Logging to: {LOG_FILE}")
        print(f"Summary: {SUMMARY_FILE}\n")
        
        self.init_csv_log()
        
        # Start network monitoring thread
        network_thread = threading.Thread(target=self.monitor_network, daemon=True)
        network_thread.start()
        
        # Start event viewer monitoring thread
        event_thread = threading.Thread(target=self.check_event_viewer, daemon=True)
        event_thread.start()
        
        print("✅ Monitoring started. Press Ctrl+C to stop.\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n🛑 Monitoring stopped.")
            if self.csv_file:
                self.csv_file.close()


def main():
    print("\nIMPORTANT: Run this script as Administrator to access Event Viewer logs!\n")
    input("Press Enter to start monitoring...")
    
    monitor = DefenderUpdateMonitor()
    monitor.run()


if __name__ == "__main__":
    main()