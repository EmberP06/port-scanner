import socket
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.cve_lookup import lookup_cves

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt"
}

def scan_port(host, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except socket.error:
        return None

def get_banner(host, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner if banner else None
    except:
        return None

def get_service(port):
    return COMMON_SERVICES.get(port, "Unknown")

def run_scan(host, start_port, end_port, threads=100):
    print(f"\n{'='*55}")
    print(f"  Target   : {host}")
    print(f"  Ports    : {start_port} - {end_port}")
    print(f"  Threads  : {threads}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")

    open_ports = []
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        completed = 0
        for future in as_completed(futures):
            completed += 1
            print(f"  Progress: {completed}/{len(ports)} ports scanned", end="\r")
            result = future.result()
            if result:
                open_ports.append(result)

    print(f"\n")
    open_ports.sort()

    results = []
    for port in open_ports:
        service = get_service(port)
        banner  = get_banner(host, port)
        banner_str = f"  →  {banner}" if banner else ""
        print(f"  [OPEN]  Port {port:5d}  |  {service}{banner_str}")

        # CVE lookup
        print(f"           Looking up CVEs for {service}...")
        cves = lookup_cves(service)
        if cves:
            for cve in cves:
                severity_color = "⚠️ " if cve['severity'] in ("HIGH", "CRITICAL") else "ℹ️ "
                print(f"           {severity_color} {cve['id']}  |  Score: {cve['score']}  |  {cve['severity']}")
                print(f"              {cve['description']}")
        else:
            print(f"           No CVEs found.")

        results.append({"port": port, "service": service, "banner": banner, "cves": cves})
        print()

    print(f"{'='*55}")
    print(f"  Scan complete — {len(open_ports)} open port(s) found.")
    print(f"  Finished : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")
    return results

if __name__ == "__main__":
    import os
    os.makedirs("reports", exist_ok=True)

    from modules.report import generate_html, generate_json

    parser = argparse.ArgumentParser(description="Port Scanner with CVE Lookup")
    parser.add_argument("host", help="Target host (e.g. 127.0.0.1)")
    parser.add_argument("--start",   type=int, default=1,    help="Start port")
    parser.add_argument("--end",     type=int, default=1024, help="End port")
    parser.add_argument("--threads", type=int, default=100,  help="Number of threads")
    args = parser.parse_args()

    results = run_scan(args.host, args.start, args.end, args.threads)

    html_file = generate_html(args.host, results, args.start, args.end)
    json_file = generate_json(args.host, results, args.start, args.end)

    print(f"  Reports saved:")
    print(f"    HTML → {html_file}")
    print(f"    JSON → {json_file}\n")