import time
import socket
import psutil
from datetime import datetime
import csv  
import os   
import time


DOMAIN = "fe2cr.update.microsoft.com"
DELAY = 0.5
OUTPUT = "dnsoutput.txt"
CHECKS = 10



def resolve_domain_ips(domain: str) -> set[str]:
    ips = set()
    try:
        infos = socket.getaddrinfo(domain, None)
        for _, _, _, _, sockaddr in infos:
            ips.add(sockaddr[0])
    except socket.gaierror:
        pass
    return ips

last = resolve_domain_ips(DOMAIN)
starttime = time.time()
changes=[]
while True:
    time.sleep(DELAY)
    ips = resolve_domain_ips(DOMAIN)
    if ips != last:
        newtime = time.time()
        change = newtime-starttime
        print(f"New change detected after: {change}")
        changes.append(change)
        starttime = newtime
    last = ips
    if len(changes)-1 == CHECKS:
        break
changes.pop(0)
with open(OUTPUT, "a+") as file:
    file.seek(0)  # go to start so we can read existing content
    oldchanges = [float(line.strip()) for line in file if line.strip()]
    print(f"Found: {oldchanges}")

    complete = oldchanges + changes
    print(complete)

    # append the new ones (don't rewrite the whole file)
    if oldchanges:   # optional: ensure a newline before appending if file isn't empty
        file.write("\n")
    file.write("\n".join(map(str, changes)))

print(f"Finished {CHECKS} changes, the total times are: {", ".join(list(map(str, changes)))}")
print(f"Average time: {sum(changes)/len(changes)}")
    