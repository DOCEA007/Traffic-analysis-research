import time
import socket
import psutil
from datetime import datetime, timezone, timedelta
import csv
import os
import json
import subprocess
import platform
import re
from typing import Any, Dict, List, Optional, Tuple

# ----------------------------
# CONFIG: domains per AV
# ----------------------------
DOMAINS = {
    "Windows Defender": [
        "fe2cr.update.microsoft.com",
        "definitionupdates.microsoft.com",
        "wdcp.microsoft.com",
        "wdcpalt.microsoft.com",
        "download.windowsupdate.com",
        "dl.delivery.mp.microsoft.com",
        "delivery.mp.microsoft.com",
        "ctldl.windowsupdate.com",
        "b1.download.windowsupdate.com",
        "au.download.windowsupdate.com",
        "au.b1.download.windowsupdate.com",
        "tlu.dl.delivery.mp.microsoft.com",
    ],
    # Add more AVs here (exact FQDNs work best with your current approach)
    "ESET": ["repository.eset.com"],
    "Kaspersky": ["downloads.kaspersky-labs.com", "ds.kaspersky.com", "downloads.upd.kaspersky.com"],
    "Sophos": ["dci.sophosupd.com", "dci.sophosupd.net"],
    "Malwarebytes": ["data-cdn.mbamupdates.com"],
    "Trellix/McAfee": ["update.nai.com"],
}

# ----------------------------
# INPUTS
# ----------------------------
ANTIVIRUS = [i.strip() for i in input("Enter Antiviruses (* for all): ").strip().split(',') if i.strip()] or ["Windows Defender"]
PORTS = {int(p) for p in (input("Enter ports (default 80,443,53): ").strip() or "80,443,53").split(",")}
IDENTIFIER = input("Enter unique identifier for the process (exe path, process name or pid): ").strip()
POLL_SECONDS = float(input("Enter delay between checks (default 0.5): ").strip() or "0.5")
DNS_REFRESH_SECONDS = 60

# Variant 3 additions:
EVENT_POLL_SECONDS = float(input("Event log poll interval seconds (default 5): ").strip() or "5")
CORRELATE_WINDOW_SECONDS = int(input("Correlation window seconds (default 120): ").strip() or "120")
RETENTION_SECONDS = max(600, CORRELATE_WINDOW_SECONDS * 5)  # keep some history

OUT_FORMAT = (input("Save format (txt/csv) [txt]: ").strip().lower() or "txt")
LOG_FILE = "monitor.csv" if OUT_FORMAT == "csv" else "monitor.txt"

if ANTIVIRUS == ["*"]:
    ANTIVIRUS = list(DOMAINS.keys())

# Defender definition KB often appears in WU logs; keep optional.
KB_DEFENDER = "KB2267602"

# ----------------------------
# HELPERS
# ----------------------------
def resolve_domain_ips(domain: str) -> set[str]:
    ips = set()
    try:
        infos = socket.getaddrinfo(domain, None)
        for _, _, _, _, sockaddr in infos:
            ips.add(sockaddr[0])
    except socket.gaierror:
        pass
    return ips

def proc_info(pid: int):
    try:
        p = psutil.Process(pid)
        return p.name(), pid, p.exe()
    except Exception:
        return "<unknown>", pid, "<unavailable>"

def iso_now() -> str:
    return datetime.now().isoformat(timespec="seconds")

def epoch_seconds(dt: datetime) -> float:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc).timestamp()
    return dt.timestamp()

def find_powershell() -> Optional[str]:
    # Prefer Windows PowerShell if present; fallback to pwsh if installed.
    for exe in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
        try:
            r = subprocess.run([exe, "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return exe
        except Exception:
            continue
    return None

PS = find_powershell()

def ps_json(command: str) -> Any:
    """
    Runs a PowerShell command and returns parsed JSON output.
    """
    if not PS:
        return None
    full = [
        PS, "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command", command
    ]
    r = subprocess.run(full, capture_output=True, text=True)
    if r.returncode != 0:
        return None
    out = r.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None

def parse_ps_datetime(val: Any) -> Optional[datetime]:
    """
    PowerShell ConvertTo-Json may emit:
      - ISO strings, or
      - /Date(1734530930123)/ style
    """
    if val is None:
        return None
    if isinstance(val, str):
        s = val.strip()
        m = re.match(r"^/Date\((\-?\d+)\)/$", s)
        if m:
            ms = int(m.group(1))
            return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
        try:
            # fromisoformat supports offsets in Python 3.11+
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None

def write_txt(f, line: str):
    f.write(line + "\n")
    f.flush()

# ----------------------------
# EVENT LOG POLLING (Variant 3)
# ----------------------------
EVENT_SPECS = [
    # Actual Defender update signal (and failures)
    ("Microsoft-Windows-Windows Defender/Operational", [2000, 2001, 2002, 2003, 2010, 1151]),
    # Windows Update download/install markers (Variant 3)
    ("Microsoft-Windows-WindowsUpdateClient/Operational", [19, 20, 31, 34]),
    # BITS transfer markers (optional; bytes often appear in XML/message)
    ("Microsoft-Windows-Bits-Client/Operational", [3, 4, 59, 60]),
]

def fetch_recent_events(log_name: str, ids: List[int], minutes: int = 10) -> List[Dict[str, Any]]:
    """
    Fetch events from last N minutes for given IDs.
    Returns list of dict with: TimeCreated, Id, ProviderName, RecordId, Message, LogName
    """
    if platform.system().lower() != "windows":
        return []
    if not PS:
        return []

    id_list = ",".join(str(i) for i in ids)
    # ConvertTo-Json for safe parsing
    cmd = (
        f"$st=(Get-Date).AddMinutes(-{minutes});"
        f"Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; Id=@({id_list}); StartTime=$st}} "
        f"| Select-Object TimeCreated, Id, ProviderName, RecordId, Message "
        f"| ConvertTo-Json -Compress"
    )

    data = ps_json(cmd)
    if data is None:
        return []
    if isinstance(data, dict):
        data = [data]
    out = []
    for e in data:
        e["LogName"] = log_name
        out.append(e)
    return out

# ----------------------------
# MAIN
# ----------------------------
def main():
    # flatten domains
    DOMAIN_LIST = [d for av in ANTIVIRUS for d in DOMAINS.get(av, [])]
    DOMAIN_STR = ", ".join(DOMAIN_LIST)

    print(f"Checking antivirus(es): {', '.join(ANTIVIRUS)}")
    print(f"Domains: {DOMAIN_STR}")
    print(f"Watching ports: {sorted(PORTS)}")
    print(f"Event logs: polling every {EVENT_POLL_SECONDS}s; correlation window {CORRELATE_WINDOW_SECONDS}s\n")

    is_csv = (OUT_FORMAT == "csv")
    file_exists_and_has_data = os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0

    f = open(LOG_FILE, "a", encoding="utf-8", newline="")

    writer = csv.writer(f) if is_csv else None
    if is_csv and not file_exists_and_has_data:
        writer.writerow([
            "time",
            "type",                  # NET / EVENT / CORRELATION
            "antivirus",
            "domain",
            "status_or_event_id",
            "local_ip", "local_port",
            "remote_ip", "remote_port",
            "process_name", "pid", "exe",
            "log_name", "provider", "record_id",
            "message",
            "correlated_net_count",
            "correlated_wu_count",
            "correlated_bits_count"
        ])
        f.flush()
    elif not is_csv:
        write_txt(f, f"\n--- {iso_now()} start domains={DOMAIN_STR} ports={sorted(PORTS)} ---")

    # DNS resolution state
    last_dns_refresh = 0.0
    target_ips: set[str] = set()

    # Dedup + buffers for correlation
    seen_net = set()
    seen_event = set()  # (logname, recordid)

    recent_net: List[Dict[str, Any]] = []
    recent_ev: List[Dict[str, Any]] = []

    last_event_poll = 0.0

    def log_row(row: List[Any]):
        if is_csv:
            writer.writerow(row)
            f.flush()
        else:
            # Render something readable
            t, typ, av, dom, seid, lip, lport, rip, rport, pname, pid, exe, logn, prov, rid, msg, cn, cw, cb = row
            if typ == "NET":
                write_txt(f, f"[{t}] NET {av} {dom} {seid} {lip}:{lport}->{rip}:{rport} {pname} pid={pid} exe={exe}")
            elif typ == "EVENT":
                write_txt(f, f"[{t}] EVENT {logn} id={seid} rid={rid} {msg[:300]}")
            else:
                write_txt(f, f"[{t}] CORRELATION {msg} net={cn} wu={cw} bits={cb}")

    def prune(now_epoch: float):
        cutoff = now_epoch - RETENTION_SECONDS
        recent_net[:] = [x for x in recent_net if x["t_epoch"] >= cutoff]
        recent_ev[:] = [x for x in recent_ev if x["t_epoch"] >= cutoff]

    while True:
        now = time.time()

        # Refresh DNS → target IPs
        if now - last_dns_refresh >= DNS_REFRESH_SECONDS or not target_ips:
            target_ips.clear()
            for domain in DOMAIN_LIST:
                target_ips |= resolve_domain_ips(domain)

            last_dns_refresh = now
            print(f"[{iso_now()}] Resolved {len(DOMAIN_LIST)} domains -> {len(target_ips)} IPs")

        # --- NETWORK WATCH ---
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
            if key in seen_net:
                continue
            seen_net.add(key)

            ts = iso_now()
            ident = IDENTIFIER.casefold()

            pname = pid = exe = ""
            if c.pid:
                pname, pid, exe = proc_info(c.pid)

            # match identifier if provided
            if ident:
                hay = " ".join([str(pid), str(pname), str(exe)]).casefold()
                if ident not in hay:
                    continue

            # We don't truly know which domain mapped to this IP (CDNs), but we log the AV + domain-set string.
            av_name = ",".join(ANTIVIRUS)
            dom_label = DOMAIN_STR

            net_rec = {
                "t_epoch": time.time(),
                "time": ts,
                "av": av_name,
                "domain": dom_label,
                "status": c.status,
                "lip": lip, "lport": lport,
                "rip": rip, "rport": rport,
                "pname": pname, "pid": pid, "exe": exe,
            }
            recent_net.append(net_rec)

            log_row([
                ts, "NET", av_name, dom_label, c.status,
                lip, lport, rip, rport,
                pname, pid, exe,
                "", "", "",
                "", "", "", ""
            ])

        # --- EVENT LOG WATCH (Variant 3) ---
        if now - last_event_poll >= EVENT_POLL_SECONDS:
            last_event_poll = now

            # pull recent events for each log spec
            new_events: List[Dict[str, Any]] = []
            for log_name, ids in EVENT_SPECS:
                events = fetch_recent_events(log_name, ids, minutes=10)
                for e in events:
                    rid = e.get("RecordId")
                    key = (log_name, rid)
                    if rid is None or key in seen_event:
                        continue
                    seen_event.add(key)
                    new_events.append(e)

            # normalize + store + log
            for e in sorted(new_events, key=lambda x: x.get("RecordId", 0)):
                t = parse_ps_datetime(e.get("TimeCreated")) or datetime.now()
                t_epoch = epoch_seconds(t if isinstance(t, datetime) else datetime.now())
                ts = (t.astimezone().isoformat(timespec="seconds") if isinstance(t, datetime) else iso_now())

                log_name = e.get("LogName", "")
                eid = int(e.get("Id", 0) or 0)
                prov = e.get("ProviderName", "")
                rid = e.get("RecordId", "")
                msg = (e.get("Message") or "").replace("\r\n", " ").strip()

                ev_rec = {
                    "t_epoch": t_epoch,
                    "time": ts,
                    "log": log_name,
                    "id": eid,
                    "provider": prov,
                    "record_id": rid,
                    "message": msg
                }
                recent_ev.append(ev_rec)

                log_row([
                    ts, "EVENT", "", "", str(eid),
                    "", "", "", "",
                    "", "", "",
                    log_name, prov, str(rid),
                    msg,
                    "", "", ""
                ])

                # If we see Defender "updated successfully" (Event 2000), emit correlation record
                if log_name.endswith("Windows Defender/Operational") and eid == 2000:
                    window_start = t_epoch - CORRELATE_WINDOW_SECONDS
                    # recent NET "checks" just before update
                    net_hits = [n for n in recent_net if window_start <= n["t_epoch"] <= t_epoch]
                    # recent WU events in that window
                    wu_hits = [
                        ev for ev in recent_ev
                        if ev["log"].endswith("WindowsUpdateClient/Operational")
                        and window_start <= ev["t_epoch"] <= t_epoch
                    ]
                    # recent BITS events in that window
                    bits_hits = [
                        ev for ev in recent_ev
                        if ev["log"].endswith("Bits-Client/Operational")
                        and window_start <= ev["t_epoch"] <= t_epoch
                    ]

                    # Optional: highlight KB2267602 presence if any
                    kb_note = ""
                    if any(KB_DEFENDER in (ev["message"] or "") for ev in wu_hits):
                        kb_note = f" (WU mentions {KB_DEFENDER})"

                    corr_msg = (
                        f"Defender update SUCCESS (Event 2000){kb_note}. "
                        f"Matched last {CORRELATE_WINDOW_SECONDS}s: "
                        f"{len(net_hits)} NET connections, {len(wu_hits)} WU events, {len(bits_hits)} BITS events."
                    )

                    log_row([
                        iso_now(), "CORRELATION", "Windows Defender", "", "2000",
                        "", "", "", "",
                        "", "", "",
                        "", "", "",
                        corr_msg,
                        str(len(net_hits)), str(len(wu_hits)), str(len(bits_hits))
                    ])

            prune(time.time())

        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main()
