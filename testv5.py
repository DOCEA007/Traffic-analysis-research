import time
import socket
import psutil
from datetime import datetime
import csv
import os
import subprocess
import threading
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
        # Check/communication domains (nimbus) - these are monitored but not logged
        "nimbus.bitdefender.net",
        "eu.nimbus.bitdefender.net",
        "elb-ned-gcp.nimbus.bitdefender.net",
        # Update domains - these trigger logging
        "upgr-mmxxiii-cl-ts.2d8cd.cdn.bitdefender.net",
        "*.cdn.bitdefender.net",
    ],
    "Malwarebytes": [
        "data-cdn.mbamupdates.com",
        "update.malwarebytes.com",
        "api.malwarebytes.com",
    ],
}

# Domains that indicate actual updates (not just checks/communication)
UPDATE_DOMAINS = {
    "Windows Defender": [
        "fe2cr.update.microsoft.com",
        "definitionupdates.microsoft.com",
        "*.update.microsoft.com",
    ],
    "Bitdefender": [
        "upgr-mmxxiii-cl-ts.2d8cd.cdn.bitdefender.net",
        "*.cdn.bitdefender.net",
    ],
}

# Domains that are just checks (not actual updates)
CHECK_DOMAINS = {
    "Bitdefender": [
        "nimbus.bitdefender.net",
        "eu.nimbus.bitdefender.net",
        "elb-ned-gcp.nimbus.bitdefender.net",
        "*.nimbus.bitdefender.net",
    ],
}

# Processes that indicate UPDATE when connecting to UPDATE domains
UPDATE_PROCESS_NAMES = {
    "Bitdefender": ["downloader.exe", "updatesrv.exe"],
}

EVENT_CONFIGS = {
    "Windows Defender": {
        "log_names": ["Microsoft-Windows-Windows Defender/Operational"],
        "event_ids": [2000, 2001, 2002, 2010, 2011, 1150, 1151],
        "keywords": ["update", "definition", "signature", "engine"]
    }
}

AV_PROCESSES = {
    "Windows Defender": ["MsMpEng.exe", "NisSrv.exe", "MpCmdRun.exe"],
    "Norton": ["ns.exe", "NortonSecurity.exe"],
    "McAfee": ["mcshield.exe", "mfemms.exe"],
    "Kaspersky": ["avp.exe"],
    "Avast": ["AvastSvc.exe"],
    "AVG": ["avgsvc.exe"],
    "Bitdefender": ["bdagent.exe", "vsserv.exe", "bdservicehost.exe"],
    "Malwarebytes": ["mbamservice.exe"],
}

UPDATE_PROCESSES = {
    "Windows Defender": ["MpCmdRun.exe"],
    "Norton": ["lucomserver.exe"],
    "McAfee": ["mcupdate.exe"],
    "Kaspersky": ["avp.exe"],
    "Bitdefender": ["bdagent.exe", "bdservicehost.exe", "updatesrv.exe"],
}

# Correlation between CHECK → FILE update
PENDING_CHECKS = {}
CHECK_WINDOW = 60  # seconds

DNS_REFRESH_SECONDS = 60

# Connection tracking for grouping by domain
CONNECTION_TRACKER = {}  # {domain: {"count": int, "latest_ts": str, "av_name": str, "update_type": str}}

# ============================================================================
# USER INPUT
# ============================================================================

print("=" * 70)
print("ANTIVIRUS UPDATE MONITOR (NO ADMIN REQUIRED)")
print("=" * 70)

ANTIVIRUS = [i.strip() for i in input("Enter Antiviruses (* for all): ").split(",") if i.strip()]
if not ANTIVIRUS:
    ANTIVIRUS = ["Windows Defender"]
if ANTIVIRUS == ["*"]:
    ANTIVIRUS = list(DOMAINS.keys())

PORTS = {int(p) for p in (input("Ports [80,443,53]: ").strip() or "80,443,53").split(",")}
IDENTIFIER = input("Process filter (blank = all): ").strip()
POLL_SECONDS = float(input("Poll delay [0.5]: ").strip() or "0.5")
CHECK_LOGS = input("Monitor event logs? [Y/n]: ").lower() != "n"
CHECK_FILES = input("Monitor definition files? [Y/n]: ").lower() != "n"
DEBUG_MODE = input("Debug mode (show DNS resolution)? [y/N]: ").lower() == "y"

OUT_FORMAT = (input("Output format txt/csv [txt]: ").lower() or "txt")
LOG_FILE = "av_updates.csv" if OUT_FORMAT == "csv" else "av_updates.txt"

print("\nMonitoring:", ", ".join(ANTIVIRUS))
print("Ports:", sorted(PORTS))
print("Output:", LOG_FILE)
print("=" * 70 + "\n")

# ============================================================================
# HELPERS
# ============================================================================

def resolve_domain_ips(domain):
    ips = set()
    try:
        original_domain = domain
        if domain.startswith("*."):
            # For wildcards, try to resolve the base domain
            # This won't catch all subdomains but helps with CDN IPs
            domain = domain[2:]
            # Also try common subdomains for CDN patterns
            common_subs = ["cdn", "update", "upgrade", "download"]
            for sub in common_subs:
                try:
                    subdomain = f"{sub}.{domain}"
                    for info in socket.getaddrinfo(subdomain, None):
                        ips.add(info[4][0])
                except:
                    pass
        for info in socket.getaddrinfo(domain, None):
            ips.add(info[4][0])
        # Suppress individual domain resolution in debug (too verbose)
    except Exception as e:
        pass  # Silently fail
    return ips

def proc_info(pid):
    try:
        p = psutil.Process(pid)
        return p.name(), pid, p.exe()
    except Exception:
        return "<unknown>", pid, "<unknown>"

def get_av_from_process(process_name):
    """Determine which antivirus a process belongs to"""
    process_lower = process_name.lower()
    for av_name, processes in AV_PROCESSES.items():
        for proc in processes:
            if proc.lower() == process_lower:
                return av_name
    return None

def log_event(f, writer, is_csv, etype, msg, details=None):
    ts = datetime.now().strftime("%H:%M:%S")
    ts_full = datetime.now().isoformat(timespec="seconds")
    
    # Parse the event type to extract AV name and update type
    parts = etype.split("/")
    av_name = None
    update_type = "CHECK"
    event_source = parts[0] if parts else ""
    
    if len(parts) >= 2:
        # Extract AV name from event type (EVENT/Windows Defender, FILE/Bitdefender, etc.)
        if event_source in ["EVENT", "FILE"] and len(parts) > 1:
            av_name = parts[1]
            update_type = parts[2] if len(parts) > 2 else "UPDATE"
        elif event_source == "AV-NET":
            # For AV-NET/UPDATE/ESTABLISHED format
            update_type = parts[1] if len(parts) > 1 else "CHECK"
            # Try to determine AV from process name
            if msg:
                process_match = msg.split("(")[0].strip() if "(" in msg else msg
                av_name = get_av_from_process(process_match)
    
    # Try to determine AV from process name if not already found
    if not av_name and msg:
        process_match = msg.split("(")[0].strip() if "(" in msg else msg
        av_name = get_av_from_process(process_match)
    
    # Get domain info for display and tracking
    domain_name = ""
    if details and len(details) >= 1:
        domain_name = details[0]
    
    # Track connections by domain (only for network events)
    if event_source in ["AV-NET", "NETWORK"] and domain_name:
        # Create a key for tracking (av_name + domain)
        # Use process name if AV name not found
        display_name = av_name
        if not display_name and msg:
            process_match = msg.split("(")[0].strip() if "(" in msg else msg
            display_name = process_match
        
        tracker_key = f"{display_name or 'Unknown'}:{domain_name}"
        
        if tracker_key not in CONNECTION_TRACKER:
            CONNECTION_TRACKER[tracker_key] = {
                "count": 0,
                "latest_ts": ts,
                "display_name": display_name or "Unknown",
                "domain": domain_name,
                "update_type": update_type
            }
        
        CONNECTION_TRACKER[tracker_key]["count"] += 1
        CONNECTION_TRACKER[tracker_key]["latest_ts"] = ts
        # Update type to UPDATE if this is an UPDATE (don't downgrade)
        if update_type == "UPDATE":
            CONNECTION_TRACKER[tracker_key]["update_type"] = update_type
        
        # Print grouped connection info
        tracker = CONNECTION_TRACKER[tracker_key]
        count = tracker["count"]
        latest_ts = tracker["latest_ts"]
        final_update_type = tracker["update_type"]
        
        if count == 1:
            # First connection - show immediately
            if final_update_type == "UPDATE":
                output = f"[{latest_ts}] ✓ {tracker['display_name']}: UPDATE → {domain_name}"
            else:
                output = f"[{latest_ts}]   {tracker['display_name']}: → {domain_name}"
            print(output)
        else:
            # Multiple connections - show with count
            if final_update_type == "UPDATE":
                output = f"[{latest_ts}] ✓ {tracker['display_name']}: UPDATE → {domain_name} ({count} times)"
            else:
                output = f"[{latest_ts}]   {tracker['display_name']}: → {domain_name} ({count} times)"
            # Print on UPDATE or every 5th connection to avoid spam
            if final_update_type == "UPDATE" or count % 5 == 0:
                print(output)
    else:
        # For FILE and EVENT, show immediately
        domain_info = f" → {domain_name}" if domain_name else ""
        
        if update_type == "UPDATE":
            if av_name:
                output = f"[{ts}] ✓ {av_name}: UPDATE detected{domain_info}"
            else:
                output = f"[{ts}] ✓ UPDATE detected: {msg}{domain_info}"
            print(output)
        elif event_source in ["FILE", "EVENT"]:
            if av_name:
                output = f"[{ts}]   {av_name}: {update_type}{domain_info}"
            else:
                output = f"[{ts}]   {event_source}: {update_type}{domain_info}"
            print(output)
    
    # Always write everything to file for record keeping with full details
    if is_csv:
        # CSV format: timestamp, event_type, message, and all details
        writer.writerow([ts_full, etype, msg] + (details or []))
    else:
        # Detailed text format with all information
        f.write(f"[{ts_full}] [{etype}] {msg}")
        if details:
            # Check event type to format details appropriately
            if event_source in ["AV-NET", "NETWORK"] and len(details) >= 6:
                # Network connection details: [domain, remote_ip, remote_port, local_ip, local_port, exe_path, av_name]
                domain = details[0] if len(details) > 0 else "N/A"
                remote_ip = details[1] if len(details) > 1 else "N/A"
                remote_port = details[2] if len(details) > 2 else "N/A"
                local_ip = details[3] if len(details) > 3 else "N/A"
                local_port = details[4] if len(details) > 4 else "N/A"
                exe_path = details[5] if len(details) > 5 else "N/A"
                av_name_log = details[6] if len(details) > 6 else (av_name or "Unknown")
                
                f.write(f" | Domain: {domain} | Remote: {remote_ip}:{remote_port} | Local: {local_ip}:{local_port} | Exe: {exe_path} | AV: {av_name_log} | UpdateType: {update_type}")
            elif event_source == "EVENT" and len(details) >= 4:
                # Event log details: [time_gen, event_id, source, message, av_name]
                time_gen = details[0] if len(details) > 0 else "N/A"
                event_id = details[1] if len(details) > 1 else "N/A"
                source = details[2] if len(details) > 2 else "N/A"
                event_msg = details[3] if len(details) > 3 else "N/A"
                av_name_log = details[4] if len(details) > 4 else (av_name or "Unknown")
                
                f.write(f" | Time: {time_gen} | EventID: {event_id} | Source: {source} | Message: {event_msg} | AV: {av_name_log}")
            elif event_source == "FILE" and len(details) >= 3:
                # File update details: [file_path, file_name, correlation, av_name]
                file_path = details[0] if len(details) > 0 else "N/A"
                file_name = details[1] if len(details) > 1 else "N/A"
                correlation = details[2] if len(details) > 2 else "N/A"
                av_name_log = details[3] if len(details) > 3 else (av_name or "Unknown")
                
                f.write(f" | FilePath: {file_path} | FileName: {file_name} | {correlation} | AV: {av_name_log}")
            else:
                # Fallback: write all details
                f.write(" | " + " | ".join([f"{i}: {d}" for i, d in enumerate(details)]))
        else:
            # No details but include AV name if available
            if av_name:
                f.write(f" | AV: {av_name}")
        f.write("\n")
    f.flush()

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
        self.seen_events = set()  # Track seen events to avoid duplicates
        
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
        if DEBUG_MODE:
            print(f"[EVENT MONITOR] Started monitoring {self.av_name} events...")
        
        while self.running:
            try:
                for log_name in self.log_names:
                    events = self.query_events_wevtutil(log_name, minutes=1)
                    
                    for event in events:
                        event_id = event.get('EventID', '')
                        source = event.get('Source', '')
                        message = event.get('Message', '')
                        time_gen = event.get('TimeGenerated', '')
                        
                        # Create unique key to avoid duplicate events
                        event_key = (event_id, source, time_gen, message[:100])
                        if event_key in self.seen_events:
                            continue
                        self.seen_events.add(event_key)
                        
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
                            f"EVENT/{self.av_name}/UPDATE",
                            f"EventID={event_id} Source={source}",
                            [time_gen, event_id, source, message, self.av_name]
                        )
                
            except Exception as e:
                pass  # Silently handle errors
            
            time.sleep(30)  # Check every 30 seconds

# ============================================================================
# FILE MONITOR
# ============================================================================

class DefinitionFileMonitor(threading.Thread):
    def __init__(self, av, f, writer, is_csv):
        super().__init__(daemon=True)
        self.av = av
        self.f = f
        self.writer = writer
        self.is_csv = is_csv
        self.files = {}
        self.running = True
        self.paths = []
        
        # Set up paths for different AVs
        if av == "Windows Defender":
            base = Path("C:/ProgramData/Microsoft/Windows Defender/Definition Updates")
            if base.exists():
                self.paths.append(base)
        elif av == "Bitdefender":
            # Common Bitdefender paths
            possible_paths = [
                Path("C:/ProgramData/Bitdefender"),
                Path("C:/Program Files/Bitdefender"),
                Path("C:/Program Files (x86)/Bitdefender"),
                Path("C:/ProgramData/Bitdefender Agent"),
            ]
            for p in possible_paths:
                if p.exists():
                    # Look for update/definition folders
                    for subfolder in ["Updates", "Update", "Definitions", "Defs", "BDUpdate"]:
                        subpath = p / subfolder
                        if subpath.exists():
                            self.paths.append(subpath)
                    # Also monitor the base directory
                    self.paths.append(p)
                    break

    def run(self):
        if not self.paths:
            return
        while self.running:
            for p in self.paths:
                for file in p.rglob("*"):
                    if not file.is_file():
                        continue
                    try:
                        m = file.stat().st_mtime
                        key = str(file)
                        if key not in self.files:
                            self.files[key] = m
                        elif m > self.files[key]:
                            self.files[key] = m

                            # correlate with last CHECK
                            update_type = "UPDATE"
                            last_check_time = PENDING_CHECKS.get(self.av.lower(), 0)
                            if time.time() - last_check_time <= CHECK_WINDOW:
                                correlated = True
                                del PENDING_CHECKS[self.av.lower()]
                            else:
                                correlated = False

                            log_event(
                                self.f, self.writer, self.is_csv,
                                f"FILE/{self.av}/{update_type}",
                                f"Definition file: {file.name}",
                                [str(file), file.name, f"Correlated={correlated}", self.av]
                            )
                    except Exception:
                        pass
            time.sleep(10)

# ============================================================================
# MAIN
# ============================================================================

def main():
    is_csv = OUT_FORMAT == "csv"
    f = open(LOG_FILE, "a", encoding="utf-8", newline="")
    writer = csv.writer(f) if is_csv else None

    DOMAIN_LIST = [d for av in ANTIVIRUS for d in DOMAINS.get(av, [])]
    # Build list of UPDATE domains (only log connections to these)
    UPDATE_DOMAIN_LIST = []
    for av in ANTIVIRUS:
        if av in UPDATE_DOMAINS:
            UPDATE_DOMAIN_LIST.extend(UPDATE_DOMAINS[av])
    
    PROCESS_NAMES = {
        p.lower()
        for av in ANTIVIRUS
        for p in AV_PROCESSES.get(av, [])
    }

    target_ips = set()
    update_domain_ips = set()  # IPs that belong to UPDATE domains only
    ip_to_domain = {}  # Map IP to domain name for debugging
    seen = set()
    last_dns = 0

    monitors = []
    if CHECK_FILES:
        for av in ANTIVIRUS:
            m = DefinitionFileMonitor(av, f, writer, is_csv)
            m.start()
            monitors.append(m)
    
    if CHECK_LOGS:
        for av in ANTIVIRUS:
            if av in EVENT_CONFIGS:
                m = EventLogMonitor(av, f, writer, is_csv)
                m.start()
                monitors.append(m)

    print("\n[Monitoring started]\n")
    if DEBUG_MODE:
        print(f"[DEBUG] Domains: {len(DOMAIN_LIST)}")
        print(f"[DEBUG] Processes: {len(PROCESS_NAMES)}")
        print(f"[DEBUG] Ports: {sorted(PORTS)}\n")

    try:
        while True:
            now = time.time()
            if now - last_dns > DNS_REFRESH_SECONDS or not target_ips:
                target_ips.clear()
                update_domain_ips.clear()
                ip_to_domain.clear()
                
                # Resolve all domains (for monitoring)
                for d in DOMAIN_LIST:
                    ips = resolve_domain_ips(d)
                    target_ips |= ips
                    for ip in ips:
                        ip_to_domain[ip] = d
                
                # Resolve UPDATE domains separately (for logging filter)
                for d in UPDATE_DOMAIN_LIST:
                    ips = resolve_domain_ips(d)
                    update_domain_ips |= ips
                    for ip in ips:
                        ip_to_domain[ip] = d
                
                last_dns = now
                if DEBUG_MODE:
                    print(f"[DEBUG] Resolved {len(target_ips)} IPs ({len(update_domain_ips)} update IPs)")

            for c in psutil.net_connections(kind="inet"):
                if not c.raddr:
                    continue

                rip = c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0]
                rport = c.raddr.port if hasattr(c.raddr, "port") else c.raddr[1]

                if not c.pid:
                    continue

                name, pid, exe = proc_info(c.pid)
                if IDENTIFIER and IDENTIFIER.lower() not in f"{name}{pid}{exe}".lower():
                    continue

                # Check if this is an AV process we're monitoring
                is_av_process = name.lower() in PROCESS_NAMES
                is_bitdefender = any(bd_proc.lower() in name.lower() for bd_proc in AV_PROCESSES.get("Bitdefender", []))
                
                # For Bitdefender: only process if it's connecting to UPDATE domains (skip nimbus checks)
                if is_bitdefender and "Bitdefender" in ANTIVIRUS:
                    if rip not in update_domain_ips:
                        # Skip nimbus/check connections for Bitdefender
                        continue
                    # Must also be on monitored port
                    if rport not in PORTS:
                        continue
                elif is_av_process:
                    # For other AV processes, check if connection matches target IPs OR if it's on monitored ports
                    if rip not in target_ips:
                        # Still log if it's an AV process on monitored ports (might be a new IP)
                        if rport not in PORTS:
                            continue
                    elif rport not in PORTS:
                        continue
                else:
                    # For non-AV processes, log if IP matches target domains (to see all connections)
                    if rip not in target_ips or rport not in PORTS:
                        continue

                key = (c.pid, rip, rport)
                if key in seen:
                    continue
                seen.add(key)

                # Get domain name for classification
                domain_name = ip_to_domain.get(rip, rip)
                # Clean up domain name (remove wildcard prefix)
                if domain_name.startswith("*."):
                    domain_name = domain_name[2:]

                # Determine if this is a CHECK or UPDATE
                update_type = "CHECK"
                
                # Check if domain is a known CHECK domain (nimbus for Bitdefender)
                is_check_domain = False
                if is_bitdefender and "Bitdefender" in CHECK_DOMAINS:
                    for check_domain in CHECK_DOMAINS["Bitdefender"]:
                        check_base = check_domain.replace("*.", "")
                        if check_base in domain_name or domain_name == check_domain:
                            is_check_domain = True
                            break
                
                # Check if domain is an UPDATE domain
                is_update_domain = rip in update_domain_ips
                
                # Check if process is an UPDATE process
                is_update_process = False
                for av_name, procs in UPDATE_PROCESSES.items():
                    if name.lower() in (p.lower() for p in procs):
                        is_update_process = True
                        break
                
                # Check if process name indicates UPDATE (e.g., downloader.exe for Bitdefender)
                if is_bitdefender and "Bitdefender" in UPDATE_PROCESS_NAMES:
                    if name.lower() in (p.lower() for p in UPDATE_PROCESS_NAMES["Bitdefender"]):
                        is_update_process = True
                
                # Classification logic:
                # 1. If connecting to CHECK domain (nimbus) → CHECK
                # 2. If connecting to UPDATE domain (CDN) → UPDATE
                # 3. If downloader.exe/updatesrv.exe connecting to CDN → UPDATE
                # 4. If UPDATE process but not to known domains → still CHECK (might be initial check)
                if is_check_domain:
                    update_type = "CHECK"
                elif is_update_domain:
                    update_type = "UPDATE"
                    # Extra confirmation: if it's an UPDATE process, definitely UPDATE
                    if is_update_process:
                        update_type = "UPDATE"
                elif is_update_process and is_bitdefender and is_update_domain:
                    # UPDATE process connecting to UPDATE domain
                    update_type = "UPDATE"

                prefix = "AV-NET" if is_av_process else "NETWORK"

                # store pending check if it's a check
                if prefix == "AV-NET" and update_type == "CHECK":
                    PENDING_CHECKS[name.lower()] = time.time()
                
                # Get local address info
                lip = c.laddr.ip if hasattr(c.laddr, "ip") else c.laddr[0]
                lport = c.laddr.port if hasattr(c.laddr, "port") else c.laddr[1]

                log_event(
                    f, writer, is_csv,
                    f"{prefix}/{update_type}/{c.status}",
                    f"{name} (PID={pid})",
                    [domain_name, rip, rport, lip, lport, exe, av_name or "Unknown"]
                )

            time.sleep(POLL_SECONDS)

    except KeyboardInterrupt:
        print("\n[SHUTDOWN]")
        for m in monitors:
            m.running = False
        f.close()

if __name__ == "__main__":
    main()
