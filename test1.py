import time
import socket
import psutil
from datetime import datetime
import csv  
import os
import xml.etree.ElementTree as ET
import subprocess
import json

# Network monitoring configuration
DOMAIN = input("Enter domain (default: microsoft.com for Windows Defender): ").strip() or "microsoft.com"
PORTS = {int(p) for p in (input("Enter ports (default 80,443): ").strip() or "80,443").split(",")}
IDENTIFIER = input("Enter unique identifier for the process (exe path, process name or pid): ").strip()
POLL_SECONDS = float(input("Enter delay between checks (default 0.5): ").strip() or "0.5")
DNS_REFRESH_SECONDS = 60

OUT_FORMAT = (input("Save format (txt/csv/json) [json]: ").strip().lower() or "json")  
if OUT_FORMAT == "csv":
    LOG_FILE = "traffic.csv"
elif OUT_FORMAT == "json":
    LOG_FILE = "av_monitor.json"
else:
    LOG_FILE = "traffic.txt"

EVENT_LOG_FILE = "av_events.json"

# Windows Defender Event Log configuration
DEFENDER_EVENT_LOG = "Microsoft-Windows-Windows Defender/Operational"
DEFENDER_EVENT_IDS = {
    2000: "Real-time protection configuration changed",
    2001: "Antimalware scan started",
    2010: "Antimalware engine started",
    2020: "Signature update started",
    2021: "Signature update completed",
    2022: "Signature update failed",
    2030: "Signature download started",
    2031: "Signature downloaded successfully",
    3002: "Real-time protection feature changed",
    5007: "Configuration changed"
}


def resolve_domain_ips(domain: str) -> set[str]:
    """Resolve domain to IP addresses"""
    ips = set()
    try:
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


def read_event_log_powershell(log_name: str, event_ids: list, max_events: int = 50):
    """
    Read Windows Event Log using PowerShell (no admin required)
    Returns list of events with timestamps and details
    """
    events = []
    
    # Build filter for event IDs
    id_filter = " or ".join([f"Id={eid}" for eid in event_ids])
    
    # PowerShell command to get recent events
    ps_command = f"""
    Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events} -ErrorAction SilentlyContinue | 
    Where-Object {{ {id_filter} }} | 
    Select-Object TimeCreated, Id, Message, LevelDisplayName |
    ConvertTo-Json -Depth 3
    """
    
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            # Parse JSON output
            data = json.loads(result.stdout)
            
            # Handle both single event and array of events
            if isinstance(data, dict):
                data = [data]
            
            for event in data:
                events.append({
                    "timestamp": event.get("TimeCreated"),
                    "event_id": event.get("Id"),
                    "level": event.get("LevelDisplayName"),
                    "message": event.get("Message", "")[:200]  # Truncate long messages
                })
                
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"[WARNING] Could not read event log: {e}")
    
    return events


def parse_recent_defender_events():
    """Get recent Windows Defender events related to updates"""
    event_ids = list(DEFENDER_EVENT_IDS.keys())
    events = read_event_log_powershell(DEFENDER_EVENT_LOG, event_ids, max_events=100)
    
    parsed_events = []
    for event in events:
        event_id = event.get("event_id")
        description = DEFENDER_EVENT_IDS.get(event_id, "Unknown event")
        
        parsed_events.append({
            "timestamp": event.get("timestamp"),
            "event_id": event_id,
            "description": description,
            "level": event.get("level"),
            "message_preview": event.get("message", "")[:150]
        })
    
    return parsed_events


def detect_update_sequence(events):
    """
    Analyze events to detect update sequences:
    - Update started (2020/2030)
    - Update completed (2021/2031)
    - Update failed (2022)
    """
    sequences = []
    
    # Sort events by timestamp (newest first)
    sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)
    
    i = 0
    while i < len(sorted_events):
        event = sorted_events[i]
        event_id = event.get("event_id")
        
        # Look for update start events
        if event_id in [2020, 2030]:
            sequence = {
                "start_time": event.get("timestamp"),
                "start_event": event_id,
                "status": "in_progress",
                "end_time": None,
                "end_event": None
            }
            
            # Look ahead for completion/failure
            for j in range(i + 1, min(i + 20, len(sorted_events))):
                next_event = sorted_events[j]
                next_id = next_event.get("event_id")
                
                if next_id in [2021, 2031]:
                    sequence["status"] = "completed"
                    sequence["end_time"] = next_event.get("timestamp")
                    sequence["end_event"] = next_id
                    break
                elif next_id == 2022:
                    sequence["status"] = "failed"
                    sequence["end_time"] = next_event.get("timestamp")
                    sequence["end_event"] = next_id
                    break
            
            sequences.append(sequence)
        
        i += 1
    
    return sequences


def log_event(data, log_file, format_type):
    """Log event to file in specified format"""
    if format_type == "json":
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(data) + "\n")
    elif format_type == "csv":
        # Handled separately in main loop
        pass
    else:  # txt
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(str(data) + "\n")


def main():
    last_dns_refresh = 0.0
    last_event_check = 0.0
    target_ips: set[str] = set()
    seen_connections = set()
    seen_event_ids = set()
    
    EVENT_CHECK_INTERVAL = 30  # Check events every 30 seconds

    print(f"\n=== Antivirus Update Monitor ===")
    print(f"Network: Watching {DOMAIN} on ports {sorted(PORTS)}")
    print(f"Events: Monitoring Windows Defender event log")
    print(f"Output: {LOG_FILE} (network) + {EVENT_LOG_FILE} (events)")
    print(f"Poll interval: {POLL_SECONDS}s\n")

    # Initialize log files
    is_csv = (OUT_FORMAT == "csv")
    is_json = (OUT_FORMAT == "json")
    file_exists = os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0

    if is_csv:
        f = open(LOG_FILE, "a", encoding="utf-8", newline="")
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["time", "domain", "status", "local_ip", "local_port", 
                           "remote_ip", "remote_port", "process_name", "pid", "exe"])
    elif is_json:
        f = open(LOG_FILE, "a", encoding="utf-8")
        writer = None
    else:
        f = open(LOG_FILE, "a", encoding="utf-8")
        writer = None
        f.write(f"\n--- {datetime.now().isoformat(timespec='seconds')} domain={DOMAIN} ---\n")
        f.flush()

    print("Starting monitoring... Press Ctrl+C to stop\n")

    try:
        while True:
            now = time.time()
            
            # Refresh DNS
            if now - last_dns_refresh >= DNS_REFRESH_SECONDS or not target_ips:
                target_ips = resolve_domain_ips(DOMAIN)
                last_dns_refresh = now
                print(f"[{datetime.now().isoformat(timespec='seconds')}] DNS: {DOMAIN} -> {', '.join(sorted(target_ips)) or '<none>'}")

            # Check Event Log periodically
            if now - last_event_check >= EVENT_CHECK_INTERVAL:
                last_event_check = now
                print(f"\n[{datetime.now().isoformat(timespec='seconds')}] Checking Windows Defender events...")
                
                events = parse_recent_defender_events()
                
                # Filter new events
                new_events = []
                for event in events:
                    event_key = (event["timestamp"], event["event_id"])
                    if event_key not in seen_event_ids:
                        seen_event_ids.add(event_key)
                        new_events.append(event)
                
                if new_events:
                    print(f"  Found {len(new_events)} new event(s):")
                    for event in new_events:
                        print(f"    [{event['timestamp']}] ID {event['event_id']}: {event['description']}")
                        
                        # Log to event file
                        log_event(event, EVENT_LOG_FILE, "json")
                        
                        # Highlight update-related events
                        if event['event_id'] in [2020, 2021, 2030, 2031]:
                            print(f"      ⚠ UPDATE EVENT DETECTED!")
                    
                    # Analyze update sequences
                    sequences = detect_update_sequence(events)
                    if sequences:
                        print(f"\n  Update Sequences Detected:")
                        for seq in sequences[:3]:  # Show last 3 sequences
                            status_symbol = "✓" if seq["status"] == "completed" else "✗" if seq["status"] == "failed" else "⋯"
                            print(f"    {status_symbol} {seq['start_time']} -> Status: {seq['status']}")
                else:
                    print("  No new events")
                
                print()

            # Monitor network connections
            try:
                conns = psutil.net_connections(kind="inet")
            except Exception as e:
                print(f"Error reading connections: {e}")
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

                ts = datetime.now().isoformat(timespec="seconds")

                if c.pid:
                    name, pid, exe = proc_info(c.pid)
                    ident = IDENTIFIER.casefold()
                    
                    if (not ident) or any(ident in v.casefold() for v in (str(pid), name, exe)):
                        connection_data = {
                            "timestamp": ts,
                            "domain": DOMAIN,
                            "status": c.status,
                            "local_ip": lip,
                            "local_port": lport,
                            "remote_ip": rip,
                            "remote_port": rport,
                            "process_name": name,
                            "pid": pid,
                            "exe": exe
                        }
                        
                        line = (f"[{ts}] NEW {c.status}  {lip}:{lport} -> {rip}:{rport}  "
                               f"{name} pid={pid} exe={exe}")
                        print(line)
                        
                        if is_json:
                            f.write(json.dumps(connection_data) + "\n")
                        elif is_csv:
                            writer.writerow([ts, DOMAIN, c.status, lip, lport, rip, rport, name, pid, exe])
                        else:
                            f.write(line + "\n")
                        f.flush()
                else:
                    ident = IDENTIFIER.casefold()
                    if (not ident) or (ident in "none"):
                        connection_data = {
                            "timestamp": ts,
                            "domain": DOMAIN,
                            "status": c.status,
                            "local_ip": lip,
                            "local_port": lport,
                            "remote_ip": rip,
                            "remote_port": rport,
                            "process_name": "",
                            "pid": None,
                            "exe": ""
                        }
                        
                        line = f"[{ts}] NEW {c.status}  {lip}:{lport} -> {rip}:{rport}  (pid=None)"
                        print(line)
                        
                        if is_json:
                            f.write(json.dumps(connection_data) + "\n")
                        elif is_csv:
                            writer.writerow([ts, DOMAIN, c.status, lip, lport, rip, rport, "", "", ""])
                        else:
                            f.write(line + "\n")
                        f.flush()

            time.sleep(POLL_SECONDS)
            
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped by user")
    finally:
        f.close()
        print(f"\nLogs saved to: {LOG_FILE} and {EVENT_LOG_FILE}")


if __name__ == "__main__":
    main()