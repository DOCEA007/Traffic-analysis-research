import time
import socket
import psutil
from datetime import datetime
import csv
import os
import subprocess
import threading
import re
from pathlib import Path

# ============================================================================
# CONFIGURATION
# ============================================================================

DOMAINS = {
    "Windows Defender": [
        "fe2cr.update.microsoft.com",
        "definitionupdates.microsoft.com",
        "wdcp.microsoft.com",
        "wd.microsoft.com",
        "security.microsoft.com",
        "*.update.microsoft.com",
        "*.wdcp.microsoft.com",
    ],
    "Norton": [
        "liveupdate.norton.com",
        "liveupdate.symantec.com",
        "api.norton.com",
        "cdn.norton.com",
    ],
    "McAfee": [
        "update.nai.com",
        "mfews.mcafee.com",
        "download.mcafee.com",
        "api.mcafee.com",
    ],
    "Kaspersky": [
        "updater.kaspersky.com",
        "dnl-eu.geo.kaspersky.com",
        "dnl-us.geo.kaspersky.com",
    ],
    "Avast": [
        "update.avast.com",
        "ff.avast.com",
        "api.avast.com",
    ],
    "AVG": [
        "update.avg.com",
        "api.avg.com",
    ],
    "Bitdefender": [
        "upgrade.bitdefender.com",
        "download.bitdefender.com",
        "api.bitdefender.com",
    ],
    "Malwarebytes": [
        "data-cdn.mbamupdates.com",
        "update.malwarebytes.com",
        "api.malwarebytes.com",
    ],
}


# Event IDs to look for (using wevtutil which doesn't need admin)
EVENT_CONFIGS = {
    "Windows Defender": {
        "log_names": ["Microsoft-Windows-Windows Defender/Operational", "System"],
        "event_ids": [2000, 2001, 2002, 2003, 2010, 2011, 2012, 2013, 1150, 1151],
        "keywords": ["update", "signature", "definition", "engine", "platform"]
    },
    "Norton": {
        "log_names": ["Application"],
        "event_ids": [101, 102, 103, 111],
        "keywords": ["liveupdate", "norton", "symantec"]
    },
    "McAfee": {
        "log_names": ["Application"],
        "event_ids": [1000, 1001, 1002],
        "keywords": ["mcafee", "update"]
    },
}

# Known AV process names to watch
AV_PROCESSES = {
    "Windows Defender": ["MsMpEng.exe", "MpCmdRun.exe", "NisSrv.exe"],
    "Norton": ["ns.exe", "nsWscSvc.exe", "NortonSecurity.exe"],
    "McAfee": ["mcshield.exe", "mfemms.exe", "mfefire.exe"],
    "Kaspersky": ["avp.exe", "avpui.exe"],
    "Avast": ["AvastSvc.exe", "AvastUI.exe"],
    "AVG": ["avgui.exe", "avgsvc.exe"],
    "Bitdefender": ["bdagent.exe", "vsserv.exe"],
    "Malwarebytes": ["mbamservice.exe", "mbam.exe"],
}

# ============================================================================
# USER INPUT
# ============================================================================

print("=" * 70)
print("ANTIVIRUS UPDATE MONITOR - NO ADMIN REQUIRED")
print("=" * 70)

ANTIVIRUS = [i.strip() for i in input("Enter Antiviruses (* for all): ").strip().split(',')] or ["Windows Defender"]
PORTS = {int(p) for p in (input("Enter ports (default 80,443,53): ").strip() or "80,443,53").split(",")}
IDENTIFIER = input("Enter process identifier (exe path/name/pid, blank for all): ").strip()
POLL_SECONDS = float(input("Enter delay between checks (default 0.5): ").strip() or "0.5")
DNS_REFRESH_SECONDS = 60
CHECK_LOGS = input("Monitor event logs? (y/n) [y]: ").strip().lower() != 'n'
CHECK_FILES = input("Monitor AV definition files? (y/n) [y]: ").strip().lower() != 'n'

if ANTIVIRUS == ["*"]:
    ANTIVIRUS = list(DOMAINS.keys())

OUT_FORMAT = (input("Save format (txt/csv) [txt]: ").strip().lower() or "txt")
LOG_FILE = "av_updates.csv" if OUT_FORMAT == "csv" else "av_updates.txt"

print("\n" + "=" * 70)
print("MONITORING CONFIGURATION")
print("=" * 70)
print(f"Antiviruses: {', '.join(ANTIVIRUS)}")
print(f"Ports: {sorted(PORTS)}")
print(f"Event Logs: {'Yes' if CHECK_LOGS else 'No'}")
print(f"Definition Files: {'Yes' if CHECK_FILES else 'No'}")
print(f"Output: {LOG_FILE}")
print("=" * 70 + "\n")

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def resolve_domain_ips(domain: str) -> set[str]:
    """Resolve domain to IP addresses"""
    ips = set()
    try:
        if domain.startswith("*."):
            domain = domain[2:]
        
        infos = socket.getaddrinfo(domain, None)
        for _, _, _, _, sockaddr in infos:
            ips.add(sockaddr[0])
    except socket.gaierror:
        pass
    return ips


def proc_info(pid: int):
    """Get process information"""
    try:
        p = psutil.Process(pid)
        return p.name(), pid, p.exe()
    except Exception:
        return "<unknown>", pid, "<unavailable>"


def log_event(f, writer, is_csv, event_type, message, details=None):
    """Log an event to file"""
    ts = datetime.now().isoformat(timespec="seconds")
    
    if is_csv:
        row = [ts, event_type, message]
        if details:
            row.extend(details)
        writer.writerow(row)
    else:
        line = f"[{ts}] [{event_type}] {message}"
        if details:
            line += f" | {' | '.join(str(d) for d in details)}"
        f.write(line + "\n")
    
    f.flush()
    print(f"[{ts}] [{event_type}] {message}")


# ============================================================================
# EVENT LOG MONITORING (NO ADMIN)
# ============================================================================

class EventLogMonitor(threading.Thread):
    """Monitor event logs using wevtutil (no admin required)"""
    def __init__(self, av_name, log_file, writer, is_csv):
        super().__init__(daemon=True)
        self.av_name = av_name
        self.log_file = log_file
        self.writer = writer
        self.is_csv = is_csv
        self.running = True
        self.last_check = datetime.now()
        
        config = EVENT_CONFIGS.get(av_name, {})
        self.log_names = config.get("log_names", ["Application"])
        self.event_ids = config.get("event_ids", [])
        self.keywords = config.get("keywords", [])
        
    def query_events_wevtutil(self, log_name, minutes=1):
        """Query events using wevtutil (doesn't require admin)"""
        events = []
        try:
            # Build query with event IDs if specified
            if self.event_ids:
                event_id_filter = " or ".join([f"EventID={eid}" for eid in self.event_ids])
                query = f"*[System[({event_id_filter}) and TimeCreated[timediff(@SystemTime) <= {minutes*60000}]]]"
            else:
                query = f"*[System[TimeCreated[timediff(@SystemTime) <= {minutes*60000}]]]"
            
            # Run wevtutil
            cmd = ["wevtutil", "qe", log_name, "/q:" + query, "/f:text", "/rd:true", "/c:50"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                events = self.parse_wevtutil_output(result.stdout)
        except Exception as e:
            pass  # Silently fail if log not accessible
        
        return events
    
    def parse_wevtutil_output(self, output):
        """Parse wevtutil text output"""
        events = []
        current_event = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith("Event["):
                if current_event:
                    events.append(current_event)
                current_event = {}
            elif ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key == "Event ID":
                    current_event['EventID'] = value
                elif key == "Source":
                    current_event['Source'] = value
                elif key == "Date":
                    current_event['TimeGenerated'] = value
                elif key == "Description":
                    current_event['Message'] = value
        
        if current_event:
            events.append(current_event)
        
        return events
    
    def run(self):
        """Monitor event logs continuously"""
        print(f"[EVENT MONITOR] Started monitoring {self.av_name} events (no admin)...")
        
        while self.running:
            try:
                for log_name in self.log_names:
                    events = self.query_events_wevtutil(log_name, minutes=1)
                    
                    for event in events:
                        event_id = event.get('EventID', '')
                        source = event.get('Source', '')
                        message = event.get('Message', '')
                        
                        # Filter by keywords if specified
                        if self.keywords:
                            text_to_check = f"{source} {message}".lower()
                            if not any(kw in text_to_check for kw in self.keywords):
                                continue
                        
                        # Truncate message
                        if len(message) > 200:
                            message = message[:197] + "..."
                        
                        log_event(
                            self.log_file,
                            self.writer,
                            self.is_csv,
                            f"EVENT/{self.av_name}",
                            f"EventID={event_id} Source={source}",
                            [event.get('TimeGenerated', ''), message]
                        )
                
            except Exception as e:
                print(f"[EVENT MONITOR] Error: {e}")
            
            time.sleep(30)  # Check every 30 seconds


# ============================================================================
# FILE MONITORING
# ============================================================================

class DefinitionFileMonitor(threading.Thread):
    """Monitor antivirus definition file changes"""
    def __init__(self, av_name, log_file, writer, is_csv):
        super().__init__(daemon=True)
        self.av_name = av_name
        self.log_file = log_file
        self.writer = writer
        self.is_csv = is_csv
        self.running = True
        self.file_times = {}
        
        # Common definition file locations
        self.paths = self.get_definition_paths(av_name)
    
    def get_definition_paths(self, av_name):
        """Get definition file paths for different AVs"""
        paths = []
        
        if av_name == "Windows Defender":
            base = Path("C:/ProgramData/Microsoft/Windows Defender/Definition Updates")
            if base.exists():
                paths.extend([
                    base / "Updates",
                    base / "Default",
                ])
        
        elif av_name == "Norton":
            paths.extend([
                Path("C:/ProgramData/Norton/Definitions"),
                Path("C:/ProgramData/Symantec/Definitions"),
            ])
        
        elif av_name == "McAfee":
            paths.extend([
                Path("C:/ProgramData/McAfee/VirusScan"),
                Path("C:/ProgramData/McAfee/Endpoint Security/Endpoint Security Platform"),
            ])
        
        return [p for p in paths if p.exists()]
    
    def run(self):
        """Monitor definition files"""
        if not self.paths:
            print(f"[FILE MONITOR] No accessible paths found for {self.av_name}")
            return
        
        print(f"[FILE MONITOR] Monitoring {len(self.paths)} paths for {self.av_name}...")
        
        # Initialize file times
        for path in self.paths:
            try:
                for file in path.rglob("*"):
                    if file.is_file():
                        self.file_times[str(file)] = file.stat().st_mtime
            except Exception:
                pass
        
        while self.running:
            try:
                for path in self.paths:
                    for file in path.rglob("*"):
                        if not file.is_file():
                            continue
                        
                        try:
                            current_mtime = file.stat().st_mtime
                            file_str = str(file)
                            
                            if file_str not in self.file_times:
                                # New file
                                self.file_times[file_str] = current_mtime
                                log_event(
                                    self.log_file,
                                    self.writer,
                                    self.is_csv,
                                    f"FILE/{self.av_name}",
                                    f"New definition file",
                                    [file.name, str(file)]
                                )
                            elif current_mtime > self.file_times[file_str]:
                                # Modified file
                                self.file_times[file_str] = current_mtime
                                log_event(
                                    self.log_file,
                                    self.writer,
                                    self.is_csv,
                                    f"FILE/{self.av_name}",
                                    f"Definition file updated",
                                    [file.name, str(file)]
                                )
                        except Exception:
                            pass
            except Exception as e:
                print(f"[FILE MONITOR] Error: {e}")
            
            time.sleep(10)  # Check every 10 seconds


# ============================================================================
# MAIN NETWORK MONITORING
# ============================================================================

def main():
    last_dns_refresh = 0.0
    target_ips: set[str] = set()
    seen_connections = set()

    # Flatten domains
    DOMAIN_LIST = [d for av in ANTIVIRUS for d in DOMAINS.get(av, [])]
    DOMAIN_STR = ", ".join(DOMAIN_LIST)

    # Get AV process names to watch
    PROCESS_NAMES = set()
    for av in ANTIVIRUS:
        PROCESS_NAMES.update(p.lower() for p in AV_PROCESSES.get(av, []))

    # Open log file
    is_csv = (OUT_FORMAT == "csv")
    file_exists = os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0

    f = open(LOG_FILE, "a", encoding="utf-8", newline="")
    writer = csv.writer(f) if is_csv else None

    # Write headers
    if is_csv and not file_exists:
        writer.writerow([
            "timestamp", "event_type", "message", "detail_1", "detail_2", 
            "detail_3", "detail_4", "detail_5", "detail_6"
        ])
        f.flush()
    else:
        f.write(f"\n{'='*70}\n")
        f.write(f"SESSION START: {datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"Domains: {DOMAIN_STR}\n")
        f.write(f"Ports: {sorted(PORTS)}\n")
        f.write(f"{'='*70}\n")
        f.flush()

    # Start monitors
    monitors = []
    
    if CHECK_LOGS:
        for av in ANTIVIRUS:
            if av in EVENT_CONFIGS:
                monitor = EventLogMonitor(av, f, writer, is_csv)
                monitor.start()
                monitors.append(monitor)
    
    if CHECK_FILES:
        for av in ANTIVIRUS:
            monitor = DefinitionFileMonitor(av, f, writer, is_csv)
            monitor.start()
            monitors.append(monitor)

    print(f"\n[NETWORK MONITOR] Watching {len(DOMAIN_LIST)} domains on ports {sorted(PORTS)}...\n")

    # Main monitoring loop
    try:
        while True:
            now = time.time()

            # Refresh DNS periodically
            if now - last_dns_refresh >= DNS_REFRESH_SECONDS or not target_ips:
                target_ips.clear()
                for domain in DOMAIN_LIST:
                    target_ips |= resolve_domain_ips(domain)

                last_dns_refresh = now
                if target_ips:
                    log_event(
                        f, writer, is_csv,
                        "DNS_REFRESH",
                        f"Resolved {len(target_ips)} IPs",
                        [DOMAIN_STR, ", ".join(sorted(target_ips))]
                    )

            # Check network connections
            try:
                conns = psutil.net_connections(kind="inet")
            except Exception as e:
                print(f"[ERROR] Reading connections: {e}")
                time.sleep(POLL_SECONDS)
                continue

            for c in conns:
                if not c.raddr:
                    continue

                rip = getattr(c.raddr, "ip", None) or c.raddr[0]
                rport = getattr(c.raddr, "port", None) or c.raddr[1]

                if rip not in target_ips or rport not in PORTS:
                    continue

                lip = getattr(c.laddr, "ip", None) or c.laddr[0]
                lport = getattr(c.laddr, "port", None) or c.laddr[1]
                key = (c.pid, lip, lport, rip, rport, c.status)

                if key in seen_connections:
                    continue
                seen_connections.add(key)

                ident = IDENTIFIER.casefold()

                if c.pid:
                    name, pid, exe = proc_info(c.pid)
                    
                    # Check if it's an AV process
                    is_av_process = name.lower() in PROCESS_NAMES
                    
                    if not ident or any(ident in v.casefold() for v in (str(pid), name, exe)):
                        event_type_prefix = "AV-NET" if is_av_process else "NETWORK"
                        log_event(
                            f, writer, is_csv,
                            f"{event_type_prefix}/{c.status}",
                            f"{name} (PID={pid})",
                            [lip, lport, rip, rport, exe]
                        )
                else:
                    if not ident:
                        log_event(
                            f, writer, is_csv,
                            f"NETWORK/{c.status}",
                            "Unknown process",
                            [lip, lport, rip, rport, "N/A", "N/A"]
                        )

            time.sleep(POLL_SECONDS)

    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Stopping monitors...")
        for monitor in monitors:
            monitor.running = False
        f.close()
        print("[SHUTDOWN] Complete.")


if __name__ == "__main__":
    main()