from runner import run_scan
from parser import parse_scan

target = "scanme.nmap.org"
result = run_scan(target)

if result.success:
    hosts = parse_scan(result)
    for host in hosts:
        print(host)

    else:
        print("Scan failed: ", result.error)