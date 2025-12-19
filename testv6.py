import time
import socket
import psutil
import csv
import threading
from pathlib import Path
from datetime import datetime
import re
import xml.etree.ElementTree as ET

# =============================================================================
# CONFIG (single place)
# =============================================================================

AV_CONFIG = {
    "Windows Defender": {
        "processes": {"msmpeng.exe", "mpcmdrun.exe", "nissrv.exe"},
        # net_rules: hostname -> role
        # For Defender you asked: only fe2cr.update.microsoft.com
        "net_rules": {
            "fe2cr.update.microsoft.com": "CHECK_NET",
        },
        "sequence": None,
        "apply": {
            "type": "defender_defs_dir",
            "path": Path(r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates"),
        },
    },

    "Avast": {
        # include the ones you’ve observed can participate
        "processes": {"avastsvc.exe", "icarus.exe", "aswengsrv.exe", "aswtoolssvc.exe", "avastui.exe"},
        "net_rules": {
            # You want CHECK = shepherd + honzik within a window (any order)
            "shepherd.avcdn.net": "AVAST_SEQ",
            "honzik.avcdn.net": "AVAST_SEQ",
        },
        "sequence": {
            "hosts": ("shepherd.avcdn.net", "honzik.avcdn.net"),
            "window_seconds": 30,
            "cooldown_seconds": 20,
        },
        "apply": {
            "type": "avast_aswdefs",
            "path": Path(r"C:\Program Files\Avast Software\Avast\defs\aswdefs.ini"),
        },
    },

    # Bitdefender configuration with XML and file monitoring
    "Bitdefender": {
        "processes": {"bdagent.exe", "bdservicehost.exe", "vsserv.exe", "updatesrv.exe", "downloader.exe"},
        "net_rules": {
            "nimbus.bitdefender.net": "CHECK_NET",
            "eu.nimbus.bitdefender.net": "CHECK_NET",
            "elb-ned-gcp.nimbus.bitdefender.net": "CHECK_NET",
            # Update domains - these trigger logging
            "upgr-mmxxiii-cl-ts.2d8cd.cdn.bitdefender.net": "UPDATE_NET",
            "*.cdn.bitdefender.net": "UPDATE_NET",
        },
        "sequence": None,
        "apply": {
            "type": "bitdefender_files",
            "paths": [
                Path("C:/ProgramData/Bitdefender"),
                Path("C:/Program Files/Bitdefender"),
                Path("C:/Program Files (x86)/Bitdefender"),
                Path("C:/ProgramData/Bitdefender Agent"),
            ],
            "subfolders": ["Updates", "Update", "Definitions", "Defs", "BDUpdate"],
        },
        "xml_path": Path("C:/Program Files/Bitdefender/Bitdefender Security/update_statistics.xml"),
    },
}

# =============================================================================
# USER INPUT
# =============================================================================

print("=" * 70)
print("ANTIVIRUS UPDATE MONITOR (NO ADMIN REQUIRED)")
print("=" * 70)

ANTIVIRUS = [i.strip() for i in input("Enter Antiviruses (* for all): ").split(",") if i.strip()]
if not ANTIVIRUS:
    ANTIVIRUS = ["Windows Defender", "Avast"]
if ANTIVIRUS == ["*"]:
    ANTIVIRUS = list(AV_CONFIG.keys())

PORTS = {int(p) for p in (input("Ports [80,443]: ").strip() or "80,443").split(",")}
POLL_SECONDS = float(input("Poll delay [0.5]: ").strip() or "0.5")
DNS_REFRESH_SECONDS = float(input("DNS refresh seconds [10]: ").strip() or "10")
DEBUG_MODE = input("Debug mode? [y/N]: ").lower() == "y"

OUT_FORMAT = (input("Output format txt/csv [txt]: ").lower() or "txt")
LOG_FILE = "av_updates.csv" if OUT_FORMAT == "csv" else "av_updates.txt"

print("\nMonitoring:", ", ".join(ANTIVIRUS))
print("Ports:", sorted(PORTS))
print("Output:", LOG_FILE)
print("=" * 70 + "\n")

# =============================================================================
# GLOBAL STATE
# =============================================================================

RUNNING = True
LOCK = threading.Lock()

# resolved maps per AV:
# RESOLVED[av]["ip_to_hosts"] = {ip: set(hosts)}
# RESOLVED[av]["host_to_ips"] = {host: set(ips)}
RESOLVED = {av: {"ip_to_hosts": {}, "host_to_ips": {}} for av in ANTIVIRUS}

# last CHECK timestamps for correlation with "apply"
LAST_CHECK = {av: 0.0 for av in ANTIVIRUS}

# Avast sequence state
AVAST_SEQ_STATE = {
    "shepherd.avcdn.net": 0.0,
    "honzik.avcdn.net": 0.0,
    "last_emit": 0.0,
}

# De-dupe net events (so you don’t spam the console)
SEEN = {}  # (pid, rip, rport, status, av) -> last_ts


# =============================================================================
# LOGGING
# =============================================================================

def now_iso():
    return datetime.now().isoformat(timespec="seconds")

def log_event(f, writer, is_csv, etype, msg, details=None):
    line = f"[{now_iso()}] [{etype}] {msg}"
    if DEBUG_MODE and details:
        line += " | " + " | ".join(map(str, details))
    print(line)

    if is_csv:
        writer.writerow([now_iso(), etype, msg] + (details or []))
    else:
        f.write(f"[{now_iso()}] [{etype}] {msg}")
        if details:
            f.write(" | " + " | ".join(map(str, details)))
        f.write("\n")
    f.flush()


# =============================================================================
# DNS RESOLUTION (active; does not use DNS cache)
# =============================================================================

def resolve_host_ips(host: str) -> set[str]:
    ips = set()
    try:
        # getaddrinfo returns both v4/v6 if available
        for info in socket.getaddrinfo(host, None):
            ip = info[4][0]
            if ip:
                ips.add(ip)
    except Exception:
        pass
    return ips

class ResolverThread(threading.Thread):
    def __init__(self, f, writer, is_csv):
        super().__init__(daemon=True)
        self.f = f
        self.writer = writer
        self.is_csv = is_csv

    def run(self):
        while RUNNING:
            try:
                for av in ANTIVIRUS:
                    rules = AV_CONFIG[av].get("net_rules", {})
                    host_to_ips = {}
                    ip_to_hosts = {}

                    for host in rules.keys():
                        ips = resolve_host_ips(host)
                        host_l = host.lower()
                        host_to_ips[host_l] = ips
                        for ip in ips:
                            ip_to_hosts.setdefault(ip, set()).add(host_l)

                    with LOCK:
                        RESOLVED[av]["host_to_ips"] = host_to_ips
                        RESOLVED[av]["ip_to_hosts"] = ip_to_hosts

                if DEBUG_MODE:
                    parts = []
                    with LOCK:
                        for av in ANTIVIRUS:
                            parts.append(f"{av}: {len(RESOLVED[av]['ip_to_hosts'])} IPs")
                    log_event(self.f, self.writer, self.is_csv, "DEBUG/DNS", " | ".join(parts))

            except Exception as e:
                if DEBUG_MODE:
                    log_event(self.f, self.writer, self.is_csv, "DEBUG/DNS_ERR", str(e))

            time.sleep(DNS_REFRESH_SECONDS)


# =============================================================================
# APPLIED UPDATE MONITORS
# =============================================================================

_latest_re = re.compile(r"^\s*Latest\s*=\s*(\d+)\s*$", re.MULTILINE)

def read_avast_latest(path: Path) -> str | None:
    try:
        txt = path.read_text(errors="ignore")
        m = _latest_re.search(txt)
        return m.group(1) if m else None
    except Exception:
        return None

class AvastAppliedMonitor(threading.Thread):
    def __init__(self, f, writer, is_csv):
        super().__init__(daemon=True)
        self.f = f
        self.writer = writer
        self.is_csv = is_csv
        self.path = AV_CONFIG["Avast"]["apply"]["path"]
        self.prev = read_avast_latest(self.path)

    def run(self):
        if "Avast" not in ANTIVIRUS:
            return

        if self.prev:
            log_event(self.f, self.writer, self.is_csv, "INIT/Avast", f"Latest={self.prev}", [str(self.path)])

        while RUNNING:
            cur = read_avast_latest(self.path)
            if cur and self.prev and cur != self.prev:
                with LOCK:
                    correlated = (time.time() - LAST_CHECK.get("Avast", 0)) <= (10 * 60)
                log_event(
                    self.f, self.writer, self.is_csv,
                    "UPDATE/APPLIED/Avast",
                    f"Definitions advanced {self.prev} -> {cur}",
                    [str(self.path), f"CorrelatedWithCheck={correlated}"]
                )
                self.prev = cur
            time.sleep(1)

class DefenderAppliedMonitor(threading.Thread):
    def __init__(self, f, writer, is_csv):
        super().__init__(daemon=True)
        self.f = f
        self.writer = writer
        self.is_csv = is_csv
        self.path = AV_CONFIG["Windows Defender"]["apply"]["path"]
        self.prev_mtime = 0.0

    def newest_mtime(self) -> float:
        newest = 0.0
        try:
            for p in self.path.rglob("*"):
                if p.is_file():
                    newest = max(newest, p.stat().st_mtime)
        except Exception:
            pass
        return newest

    def run(self):
        if "Windows Defender" not in ANTIVIRUS:
            return
        if not self.path.exists():
            log_event(self.f, self.writer, self.is_csv, "INIT/Defender", "Defs directory not found", [str(self.path)])
            return

        self.prev_mtime = self.newest_mtime()
        while RUNNING:
            cur = self.newest_mtime()
            if cur > self.prev_mtime:
                with LOCK:
                    correlated = (time.time() - LAST_CHECK.get("Windows Defender", 0)) <= (10 * 60)
                log_event(
                    self.f, self.writer, self.is_csv,
                    "UPDATE/APPLIED/Defender",
                    "Definition folder changed",
                    [str(self.path), f"CorrelatedWithCheck={correlated}"]
                )
                self.prev_mtime = cur
            time.sleep(2)

class BitdefenderFileMonitor(threading.Thread):
    """Monitor Bitdefender definition files for changes"""
    def __init__(self, f, writer, is_csv):
        super().__init__(daemon=True)
        self.f = f
        self.writer = writer
        self.is_csv = is_csv
        self.files = {}  # {file_path: mtime}
        self.paths = []
        
        # Set up paths from config
        config = AV_CONFIG.get("Bitdefender", {})
        apply_config = config.get("apply", {})
        possible_paths = apply_config.get("paths", [])
        subfolders = apply_config.get("subfolders", [])
        
        for p in possible_paths:
            if p.exists():
                # Look for update/definition folders
                for subfolder in subfolders:
                    subpath = p / subfolder
                    if subpath.exists():
                        self.paths.append(subpath)
                # Also monitor the base directory
                self.paths.append(p)
                break

    def run(self):
        if "Bitdefender" not in ANTIVIRUS:
            return
        if not self.paths:
            return
            
        while RUNNING:
            for p in self.paths:
                try:
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
                                
                                # Correlate with last CHECK
                                with LOCK:
                                    correlated = (time.time() - LAST_CHECK.get("Bitdefender", 0)) <= (10 * 60)
                                
                                log_event(
                                    self.f, self.writer, self.is_csv,
                                    "UPDATE/APPLIED/Bitdefender",
                                    f"Definition file: {file.name}",
                                    [str(file), file.name, f"CorrelatedWithCheck={correlated}"]
                                )
                        except Exception:
                            pass
                except Exception:
                    pass
            time.sleep(10)

class BitdefenderXMLMonitor(threading.Thread):
    """Monitor Bitdefender update_statistics.xml to detect pending updates"""
    def __init__(self, f, writer, is_csv):
        super().__init__(daemon=True)
        self.f = f
        self.writer = writer
        self.is_csv = is_csv
        self.running = True
        config = AV_CONFIG.get("Bitdefender", {})
        self.xml_path = config.get("xml_path", Path("C:/Program Files/Bitdefender/Bitdefender Security/update_statistics.xml"))
        self.last_state = {}  # Track last state per component: {component: state_key}
        self.last_no_update_time = {}  # Track when "no update" was last seen: {component: timestamp}
        self.initial_state_logged = {}  # Track if initial state has been logged: {component: bool}
        
    def parse_xml(self):
        """Parse the update_statistics.xml file and extract update information"""
        if not self.xml_path.exists():
            return None
        
        try:
            tree = ET.parse(self.xml_path)
            root = tree.getroot()
            
            results = {
                "Antivirus": {},
                "Antiphishing": {}
            }
            
            # Parse Antivirus section
            antivirus = root.find("Antivirus")
            if antivirus is not None:
                check_elem = antivirus.find("Check")
                update_elem = antivirus.find("Update")
                
                if check_elem is not None:
                    results["Antivirus"]["check"] = {
                        "time": check_elem.get("time", "0"),
                        "succtime": check_elem.get("succtime", "0"),
                        "error": check_elem.get("error", "0"),
                        "id": check_elem.get("id", "0"),
                        "location": check_elem.get("location", ""),
                        "updavailable": check_elem.get("updavailable", "0"),
                        "updtime": check_elem.get("updtime", "0"),
                        "server": check_elem.get("server", ""),
                    }
                
                if update_elem is not None:
                    results["Antivirus"]["update"] = {
                        "time": update_elem.get("time", "0"),
                        "succtime": update_elem.get("succtime", "0"),
                        "error": update_elem.get("error", "0"),
                        "id": update_elem.get("id", "0"),
                        "location": update_elem.get("location", ""),
                        "size": update_elem.get("size", "0"),
                        "server": update_elem.get("server", ""),
                        "updater": update_elem.get("updater", ""),
                        "updtime": update_elem.get("updtime", "0"),
                    }
            
            # Parse Antiphishing section
            antiphishing = root.find("Antiphishing")
            if antiphishing is not None:
                check_elem = antiphishing.find("Check")
                update_elem = antiphishing.find("Update")
                
                if check_elem is not None:
                    results["Antiphishing"]["check"] = {
                        "time": check_elem.get("time", "0"),
                        "succtime": check_elem.get("succtime", "0"),
                        "error": check_elem.get("error", "0"),
                        "id": check_elem.get("id", "0"),
                        "location": check_elem.get("location", ""),
                        "updavailable": check_elem.get("updavailable", "0"),
                        "updtime": check_elem.get("updtime", "0"),
                        "server": check_elem.get("server", ""),
                    }
                
                if update_elem is not None:
                    results["Antiphishing"]["update"] = {
                        "time": update_elem.get("time", "0"),
                        "succtime": update_elem.get("succtime", "0"),
                        "error": update_elem.get("error", "0"),
                        "id": update_elem.get("id", "0"),
                        "location": update_elem.get("location", ""),
                        "size": update_elem.get("size", "0"),
                        "server": update_elem.get("server", ""),
                        "updater": update_elem.get("updater", ""),
                        "updtime": update_elem.get("updtime", "0"),
                    }
            
            return results
        except Exception as e:
            if DEBUG_MODE:
                log_event(self.f, self.writer, self.is_csv, "DEBUG/XML_ERR", f"Error parsing XML: {e}")
            return None
    
    def analyze_update_status(self, component_name, data):
        """Analyze update status for a component (Antivirus or Antiphishing)"""
        status = {
            "has_update_available": False,
            "update_scheduled": False,
            "update_completed": False,
            "details": {}
        }
        
        check_data = data.get("check", {})
        update_data = data.get("update", {})
        
        # Check if update is available (updavailable = "1")
        updavailable = check_data.get("updavailable", "0")
        if updavailable == "1":
            status["has_update_available"] = True
            status["details"]["updavailable"] = "1"
        
        # Check if update is scheduled or completed (Update time > 0 and size > 0)
        update_time = int(update_data.get("time", "0"))
        update_size = int(update_data.get("size", "0"))
        update_succtime = int(update_data.get("succtime", "0"))
        
        if update_time > 0 and update_size > 0:
            if update_succtime > 0:
                status["update_completed"] = True
                status["details"]["update_completed"] = True
                status["details"]["size"] = update_size
                status["details"]["update_time"] = update_time
                status["details"]["succtime"] = update_succtime
            else:
                status["update_scheduled"] = True
                status["details"]["update_scheduled"] = True
                status["details"]["size"] = update_size
                status["details"]["update_time"] = update_time
        
        # Additional info
        status["details"]["check_time"] = check_data.get("time", "0")
        status["details"]["updtime"] = check_data.get("updtime", "0")  # Last update timestamp from XML
        status["details"]["server"] = check_data.get("server", "")
        status["details"]["location"] = check_data.get("location", "")
        status["details"]["id"] = check_data.get("id", "0")
        
        return status
    
    def format_time_since(self, timestamp_str):
        """Format time since a Unix timestamp"""
        try:
            timestamp = int(timestamp_str)
            if timestamp == 0:
                return "Never"
            
            now = int(time.time())
            diff_seconds = now - timestamp
            
            if diff_seconds < 60:
                return f"{diff_seconds}s ago"
            elif diff_seconds < 3600:
                minutes = diff_seconds // 60
                return f"{minutes}m ago"
            elif diff_seconds < 86400:
                hours = diff_seconds // 3600
                return f"{hours}h ago"
            else:
                days = diff_seconds // 86400
                return f"{days}d ago"
        except:
            return "Unknown"
    
    def run(self):
        """Monitor XML file continuously"""
        if "Bitdefender" not in ANTIVIRUS:
            return
            
        if DEBUG_MODE:
            log_event(self.f, self.writer, self.is_csv, "DEBUG/XML", f"Started monitoring Bitdefender update_statistics.xml...")
        
        while RUNNING:
            try:
                if not self.xml_path.exists():
                    time.sleep(30)
                    continue
                
                # Parse XML
                xml_data = self.parse_xml()
                if not xml_data:
                    time.sleep(30)
                    continue
                
                # Check Antivirus updates
                if "Antivirus" in xml_data and xml_data["Antivirus"]:
                    av_status = self.analyze_update_status("Antivirus", xml_data["Antivirus"])
                    component = "Antivirus"
                    
                    # Create comprehensive state key to detect any changes
                    state_key = (
                        av_status["details"].get("updavailable", "0"),
                        av_status["details"].get("update_time", "0"),
                        av_status["details"].get("succtime", "0"),
                        av_status["details"].get("id", "0"),
                        av_status["details"].get("updtime", "0")
                    )
                    
                    # Check if state changed
                    last_state_key = self.last_state.get(component)
                    state_changed = (last_state_key != state_key)
                    is_initial_state = (component not in self.initial_state_logged)
                    
                    # Update last state
                    self.last_state[component] = state_key
                    
                    # Determine if there's an update or not
                    has_update = (av_status["has_update_available"] or av_status["update_scheduled"] or av_status["update_completed"])
                    
                    # Track last "no update" time (when we last logged "no update")
                    if not has_update:
                        # If state changed and we're logging "no update", record the time
                        if state_changed:
                            self.last_no_update_time[component] = time.time()
                    else:
                        # Clear last no update time when update is detected
                        if component in self.last_no_update_time:
                            del self.last_no_update_time[component]
                    
                    # Only log if state changed (or if it's the initial state)
                    if state_changed or is_initial_state:
                        # Get updtime for use in details
                        updtime = av_status["details"].get("updtime", "0")
                        
                        # On initial state, always log as CHECK (not UPDATE) to show current status
                        if is_initial_state:
                            update_type = "CHECK"
                            self.initial_state_logged[component] = True
                        else:
                            update_type = "UPDATE" if has_update else "CHECK"
                        
                        # Build message
                        if is_initial_state:
                            # On initial state, just show current status with last update time
                            if updtime and updtime != "0":
                                time_since = self.format_time_since(updtime)
                                message = f"Last update: {time_since}"
                                if av_status["details"].get("size"):
                                    message += f" (Size: {av_status['details']['size']} bytes)"
                            else:
                                message = "No update pending"
                        else:
                            # On state change, show what changed
                            msg_parts = []
                            if av_status["has_update_available"]:
                                msg_parts.append("Update AVAILABLE")
                            if av_status["update_scheduled"]:
                                msg_parts.append("Update SCHEDULED")
                            if av_status["update_completed"]:
                                msg_parts.append("Update COMPLETED")
                            if not msg_parts:
                                msg_parts.append("No update pending")
                            
                            message = " | ".join(msg_parts)
                            
                            # Add size if available
                            if av_status["details"].get("size"):
                                message += f" (Size: {av_status['details']['size']} bytes)"
                            
                            # Add time since last update
                            if updtime and updtime != "0":
                                time_since = self.format_time_since(updtime)
                                message += f" | Last update: {time_since}"
                            elif component in self.last_no_update_time:
                                # Show time since last "no update" was logged
                                time_since = self.format_time_since(str(int(self.last_no_update_time[component])))
                                message += f" | No update for: {time_since}"
                        
                        details = [
                            str(self.xml_path),
                            f"Component=Antivirus",
                            f"UpdAvailable={av_status['details'].get('updavailable', '0')}",
                            f"UpdateTime={av_status['details'].get('update_time', '0')}",
                            f"Size={av_status['details'].get('size', '0')}",
                            f"Server={av_status['details'].get('server', 'N/A')}",
                            f"LastUpdTime={updtime}",
                        ]
                        
                        log_event(
                            self.f, self.writer, self.is_csv,
                            f"XML/Bitdefender/{update_type}",
                            f"Antivirus: {message}",
                            details
                        )
                
                # Check Antiphishing updates
                if "Antiphishing" in xml_data and xml_data["Antiphishing"]:
                    ap_status = self.analyze_update_status("Antiphishing", xml_data["Antiphishing"])
                    component = "Antiphishing"
                    
                    # Create comprehensive state key to detect any changes
                    state_key = (
                        ap_status["details"].get("updavailable", "0"),
                        ap_status["details"].get("update_time", "0"),
                        ap_status["details"].get("succtime", "0"),
                        ap_status["details"].get("id", "0"),
                        ap_status["details"].get("updtime", "0")
                    )
                    
                    # Check if state changed
                    last_state_key = self.last_state.get(component)
                    state_changed = (last_state_key != state_key)
                    is_initial_state = (component not in self.initial_state_logged)
                    
                    # Update last state
                    self.last_state[component] = state_key
                    
                    # Determine if there's an update or not
                    has_update = (ap_status["has_update_available"] or ap_status["update_scheduled"] or ap_status["update_completed"])
                    
                    # Track last "no update" time (when we last logged "no update")
                    if not has_update:
                        # If state changed and we're logging "no update", record the time
                        if state_changed:
                            self.last_no_update_time[component] = time.time()
                    else:
                        # Clear last no update time when update is detected
                        if component in self.last_no_update_time:
                            del self.last_no_update_time[component]
                    
                    # Only log if state changed (or if it's the initial state)
                    if state_changed or is_initial_state:
                        # Get updtime for use in details
                        updtime = ap_status["details"].get("updtime", "0")
                        
                        # On initial state, always log as CHECK (not UPDATE) to show current status
                        if is_initial_state:
                            update_type = "CHECK"
                            self.initial_state_logged[component] = True
                        else:
                            update_type = "UPDATE" if has_update else "CHECK"
                        
                        # Build message
                        if is_initial_state:
                            # On initial state, just show current status with last update time
                            if updtime and updtime != "0":
                                time_since = self.format_time_since(updtime)
                                message = f"Last update: {time_since}"
                                if ap_status["details"].get("size"):
                                    message += f" (Size: {ap_status['details']['size']} bytes)"
                            else:
                                message = "No update pending"
                        else:
                            # On state change, show what changed
                            msg_parts = []
                            if ap_status["has_update_available"]:
                                msg_parts.append("Update AVAILABLE")
                            if ap_status["update_scheduled"]:
                                msg_parts.append("Update SCHEDULED")
                            if ap_status["update_completed"]:
                                msg_parts.append("Update COMPLETED")
                            if not msg_parts:
                                msg_parts.append("No update pending")
                            
                            message = " | ".join(msg_parts)
                            
                            # Add size if available
                            if ap_status["details"].get("size"):
                                message += f" (Size: {ap_status['details']['size']} bytes)"
                            
                            # Add time since last update
                            if updtime and updtime != "0":
                                time_since = self.format_time_since(updtime)
                                message += f" | Last update: {time_since}"
                            elif component in self.last_no_update_time:
                                # Show time since last "no update" was logged
                                time_since = self.format_time_since(str(int(self.last_no_update_time[component])))
                                message += f" | No update for: {time_since}"
                        
                        details = [
                            str(self.xml_path),
                            f"Component=Antiphishing",
                            f"UpdAvailable={ap_status['details'].get('updavailable', '0')}",
                            f"UpdateTime={ap_status['details'].get('update_time', '0')}",
                            f"Size={ap_status['details'].get('size', '0')}",
                            f"Server={ap_status['details'].get('server', 'N/A')}",
                            f"LastUpdTime={updtime}",
                        ]
                        
                        log_event(
                            self.f, self.writer, self.is_csv,
                            f"XML/Bitdefender/{update_type}",
                            f"Antiphishing: {message}",
                            details
                        )
                
            except Exception as e:
                if DEBUG_MODE:
                    log_event(self.f, self.writer, self.is_csv, "DEBUG/XML_ERR", f"Error: {e}")
            
            time.sleep(30)  # Check every 30 seconds


# =============================================================================
# NETWORK MONITOR (process-verified + Avast sequence)
# =============================================================================

def get_av_for_process(pname_lower: str) -> str | None:
    for av in ANTIVIRUS:
        if pname_lower in AV_CONFIG[av]["processes"]:
            return av
    return None

def avast_sequence_observe(f, writer, is_csv, observed_host: str, pname: str):
    seq = AV_CONFIG["Avast"]["sequence"]
    if not seq:
        return

    h1, h2 = (seq["hosts"][0].lower(), seq["hosts"][1].lower())
    window_s = seq["window_seconds"]
    cooldown_s = seq["cooldown_seconds"]

    observed_host = observed_host.lower()
    if observed_host not in (h1, h2):
        return

    now = time.time()
    with LOCK:
        AVAST_SEQ_STATE[observed_host] = now
        t1 = AVAST_SEQ_STATE[h1]
        t2 = AVAST_SEQ_STATE[h2]
        last_emit = AVAST_SEQ_STATE["last_emit"]

    # Any-order: both within window
    if t1 and t2 and abs(t1 - t2) <= window_s:
        if (now - last_emit) >= cooldown_s:
            with LOCK:
                AVAST_SEQ_STATE["last_emit"] = now
                LAST_CHECK["Avast"] = now

            log_event(
                f, writer, is_csv,
                "CHECK/Avast",
                f"Detected CHECK pattern: {h1} + {h2} within {window_s}s (any order)",
                [f"proc={pname}"]
            )

class NetworkMonitor(threading.Thread):
    def __init__(self, f, writer, is_csv):
        super().__init__(daemon=True)
        self.f = f
        self.writer = writer
        self.is_csv = is_csv
        self.proc_cache = {}  # pid -> (name_lower, exe, ts)

    def proc_info_cached(self, pid: int):
        now = time.time()
        hit = self.proc_cache.get(pid)
        if hit and (now - hit[2] < 5):
            return hit[0], hit[1]
        try:
            p = psutil.Process(pid)
            name = p.name().lower()
            exe = p.exe()
            self.proc_cache[pid] = (name, exe, now)
            return name, exe
        except Exception:
            return None, None

    def run(self):
        while RUNNING:
            now = time.time()

            # sweep SEEN
            for k, t0 in list(SEEN.items()):
                if now - t0 > 60:
                    del SEEN[k]

            for c in psutil.net_connections(kind="inet"):
                if not c.raddr or not c.pid:
                    continue

                rip = getattr(c.raddr, "ip", None) or c.raddr[0]
                rport = getattr(c.raddr, "port", None) or c.raddr[1]
                if rport not in PORTS:
                    continue

                pname, pexe = self.proc_info_cached(c.pid)
                if not pname:
                    continue

                av = get_av_for_process(pname)
                if not av:
                    continue  # critical: prevents Chrome/browser triggering anything

                with LOCK:
                    ip_to_hosts = RESOLVED[av]["ip_to_hosts"].copy()

                if rip not in ip_to_hosts:
                    # optional debug for discovering new hosts / mismatched CDN answers
                    if DEBUG_MODE:
                        log_event(self.f, self.writer, self.is_csv, f"NET/UNMAPPED/{av}", f"{pname} -> {rip}", [rport, c.status])
                    continue

                key = (c.pid, rip, rport, c.status, av)
                if key in SEEN:
                    continue
                SEEN[key] = now

                hosts = sorted(ip_to_hosts.get(rip, []))
                rules = {k.lower(): v for k, v in AV_CONFIG[av].get("net_rules", {}).items()}

                # --- Avast special: sequence needs host attribution.
                # If the resolved IP is shared by BOTH shepherd and honzik, we can’t safely know
                # which hostname this TLS session used (SNI would solve it). Avoid false positives:
                if av == "Avast":
                    h1 = AV_CONFIG["Avast"]["sequence"]["hosts"][0].lower()
                    h2 = AV_CONFIG["Avast"]["sequence"]["hosts"][1].lower()

                    has_h1 = h1 in hosts
                    has_h2 = h2 in hosts

                    if has_h1 and has_h2:
                        if DEBUG_MODE:
                            log_event(self.f, self.writer, self.is_csv, "NET/Avast/AMBIG", f"{pname} -> {rip}", hosts)
                        # still log a generic hit, but don’t count toward sequence
                        log_event(self.f, self.writer, self.is_csv, "NET/Avast/HIT", f"{pname} -> avcdn IP", [rip, rport, c.status, pexe])
                        continue

                    # Unambiguous: exactly one of the sequence hosts maps to this IP
                    if has_h1:
                        log_event(self.f, self.writer, self.is_csv, "NET/CHECK/Avast", f"{pname} -> {h1}", [rip, rport, c.status, pexe])
                        avast_sequence_observe(self.f, self.writer, self.is_csv, h1, pname)
                        continue
                    if has_h2:
                        log_event(self.f, self.writer, self.is_csv, "NET/UPDATE_NET/Avast", f"{pname} -> {h2}", [rip, rport, c.status, pexe])
                        avast_sequence_observe(self.f, self.writer, self.is_csv, h2, pname)
                        continue

                    # Some other avast rule host mapped here
                    log_event(self.f, self.writer, self.is_csv, "NET/Avast/HIT", f"{pname} -> {hosts[0] if hosts else rip}", [rip, rport, c.status, pexe])
                    continue

                # --- Other AVs: decide role by the first matched host role (or default)
                role = "HIT"
                for h in hosts:
                    if h in rules:
                        role = rules[h]
                        break

                if role == "CHECK_NET":
                    with LOCK:
                        LAST_CHECK[av] = now
                    log_event(self.f, self.writer, self.is_csv, f"CHECK/{av}", f"{pname} -> {hosts[0] if hosts else rip}",
                              [rip, rport, c.status, pexe])

                elif role == "UPDATE_NET":
                    log_event(self.f, self.writer, self.is_csv, f"UPDATE/NET/{av}", f"{pname} -> {hosts[0] if hosts else rip}",
                              [rip, rport, c.status, pexe])

                else:
                    if DEBUG_MODE:
                        log_event(self.f, self.writer, self.is_csv, f"NET/{av}", f"{pname} -> {hosts[0] if hosts else rip}",
                                  [rip, rport, c.status, role, pexe])

            time.sleep(POLL_SECONDS)


# =============================================================================
# MAIN
# =============================================================================

def main():
    is_csv = OUT_FORMAT == "csv"
    f = open(LOG_FILE, "a", encoding="utf-8", newline="")
    writer = csv.writer(f) if is_csv else None

    threads = [
        ResolverThread(f, writer, is_csv),
        NetworkMonitor(f, writer, is_csv),
    ]

    if "Avast" in ANTIVIRUS:
        threads.append(AvastAppliedMonitor(f, writer, is_csv))
    if "Windows Defender" in ANTIVIRUS:
        threads.append(DefenderAppliedMonitor(f, writer, is_csv))
    if "Bitdefender" in ANTIVIRUS:
        threads.append(BitdefenderXMLMonitor(f, writer, is_csv))
        threads.append(BitdefenderFileMonitor(f, writer, is_csv))

    for t in threads:
        t.start()

    print("\n[Monitoring started]\n")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        global RUNNING
        RUNNING = False
        time.sleep(0.5)
        f.close()
        print("\n[SHUTDOWN]")

if __name__ == "__main__":
    main()
