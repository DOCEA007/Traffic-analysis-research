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
    "Bitdefender": ["bdagent.exe", "vsserv.exe"],
    "Malwarebytes": ["mbamservice.exe"],
}

# Explicit updater binaries → UPDATE
UPDATE_PROCESSES = {
    "Windows Defender": ["MpCmdRun.exe"],
    "Norton": ["lucomserver.exe"],
    "McAfee": ["mcupdate.exe"],
    "Kaspersky": ["avp.exe"],
}

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

OUT_FORMAT = (input("Output format txt/csv [txt]: ").lower() or "txt")
LOG_FILE = "av_updates.csv" if OUT_FORMAT == "csv" else "av_updates.txt"

DNS_REFRESH_SECONDS = 60

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
        if domain.startswith("*."):
            domain = domain[2:]
        for info in socket.getaddrinfo(domain, None):
            ips.add(info[4][0])
    except Exception:
        pass
    return ips


def proc_info(pid):
    try:
        p = psutil.Process(pid)
        return p.name(), pid, p.exe()
    except Exception:
        return "<unknown>", pid, "<unknown>"


def log_event(f, writer, is_csv, etype, msg, details=None):
    ts = datetime.now().isoformat(timespec="seconds")
    print(f"[{ts}] [{etype}] {msg}")

    if is_csv:
        writer.writerow([ts, etype, msg] + (details or []))
    else:
        f.write(f"[{ts}] [{etype}] {msg}")
        if details:
            f.write(" | " + " | ".join(map(str, details)))
        f.write("\n")
    f.flush()

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
        if av == "Windows Defender":
            base = Path("C:/ProgramData/Microsoft/Windows Defender/Definition Updates")
            if base.exists():
                self.paths.append(base)

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
                            log_event(
                                self.f, self.writer, self.is_csv,
                                f"FILE/{self.av}/UPDATE",
                                "Definition file updated",
                                [file.name]
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
    PROCESS_NAMES = {
        p.lower()
        for av in ANTIVIRUS
        for p in AV_PROCESSES.get(av, [])
    }

    target_ips = set()
    seen = set()
    last_dns = 0

    monitors = []
    if CHECK_FILES:
        for av in ANTIVIRUS:
            m = DefinitionFileMonitor(av, f, writer, is_csv)
            m.start()
            monitors.append(m)

    print("[NETWORK MONITOR] Started\n")

    try:
        while True:
            now = time.time()
            if now - last_dns > DNS_REFRESH_SECONDS or not target_ips:
                target_ips.clear()
                for d in DOMAIN_LIST:
                    target_ips |= resolve_domain_ips(d)
                last_dns = now

            for c in psutil.net_connections(kind="inet"):
                if not c.raddr:
                    continue

                rip = c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0]
                rport = c.raddr.port if hasattr(c.raddr, "port") else c.raddr[1]

                if rip not in target_ips or rport not in PORTS:
                    continue

                key = (c.pid, rip, rport)
                if key in seen:
                    continue
                seen.add(key)

                if not c.pid:
                    continue

                name, pid, exe = proc_info(c.pid)

                if IDENTIFIER and IDENTIFIER.lower() not in f"{name}{pid}{exe}".lower():
                    continue

                update_type = "CHECK"
                for procs in UPDATE_PROCESSES.values():
                    if name.lower() in (p.lower() for p in procs):
                        update_type = "UPDATE"

                prefix = "AV-NET" if name.lower() in PROCESS_NAMES else "NETWORK"

                log_event(
                    f, writer, is_csv,
                    f"{prefix}/{update_type}/{c.status}",
                    f"{name} (PID={pid})",
                    [rip, rport, exe]
                )

            time.sleep(POLL_SECONDS)

    except KeyboardInterrupt:
        print("\n[SHUTDOWN]")
        for m in monitors:
            m.running = False
        f.close()

if __name__ == "__main__":
    main()
