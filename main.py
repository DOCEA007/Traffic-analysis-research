import time
import socket
import psutil
from datetime import datetime
import csv  
import os   

DOMAIN = input("Enter domain: ").strip() or "fe2cr.update.microsoft.com"
PORTS = {int(p) for p in (input("Enter ports (default 80,443,53): ").strip() or "80,443,53").split(",")}
IDENTIFIER = input("Enter unique identifier for the process (exe path, process name or pid): ").strip()
POLL_SECONDS = float(input("Enter delay between checks (default 0.5): ").strip() or "0.5")
DNS_REFRESH_SECONDS = 60

OUT_FORMAT = (input("Save format (txt/csv) [txt]: ").strip().lower() or "txt")  
LOG_FILE = "traffic.csv" if OUT_FORMAT == "csv" else "traffic.txt"              


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


def main():
    last_dns_refresh = 0.0
    target_ips: set[str] = set()
    seen = set()

    print(f"Watching for connections to {DOMAIN} ports={sorted(PORTS)} ...")

    is_csv = (OUT_FORMAT == "csv")  
    file_exists_and_has_data = os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0  

    f = open(LOG_FILE, "a", encoding="utf-8", newline="")
    writer = csv.writer(f) if is_csv else None             

    if is_csv:  
        if not file_exists_and_has_data:
            writer.writerow(["time", "domain", "status", "local_ip", "local_port", "remote_ip", "remote_port", "process_name", "pid", "exe"])
            f.flush()
    else:  
        f.write(f"\n--- {datetime.now().isoformat(timespec='seconds')} domain={DOMAIN} ports={sorted(PORTS)} ---\n")
        f.flush()

    while True:
        now = time.time()
        if now - last_dns_refresh >= DNS_REFRESH_SECONDS or not target_ips:
            target_ips = resolve_domain_ips(DOMAIN)
            last_dns_refresh = now
            print(f"[{datetime.now().isoformat(timespec='seconds')}] {DOMAIN} resolves to: {', '.join(sorted(target_ips)) or '<none>'}")

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

            if key in seen:
                continue
            seen.add(key)

            ts = datetime.now().isoformat(timespec="seconds")

            if c.pid:
                name, pid, exe = proc_info(c.pid)
                line = (f"[{ts}] NEW {c.status}  {lip}:{lport} -> {rip}:{rport}  "
                        f"{name} pid={pid} exe={exe}")
                ident = IDENTIFIER.casefold()
                if (not ident) or any(ident in v.casefold() for v in (str(pid), name, exe)):
                    print(line)
                    if is_csv:  
                        writer.writerow([ts, DOMAIN, c.status, lip, lport, rip, rport, name, pid, exe])
                    else:       
                        f.write(line + "\n")
                    f.flush()   
            else:
                ident = IDENTIFIER.casefold()
                # pid/name/exe do not exist here, so only match against "None" (or allow empty)
                if (not ident) or (ident in "none"):
                    line = f"[{ts}] NEW {c.status}  {lip}:{lport} -> {rip}:{rport}  (pid=None)"
                    print(line)
                    if is_csv:
                        writer.writerow([ts, DOMAIN, c.status, lip, lport, rip, rport, "", "", ""])
                    else:
                        f.write(line + "\n")
                    f.flush()
  

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
