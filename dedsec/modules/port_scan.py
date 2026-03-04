import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dedsec.core.utils import section, info, warn, error
from dedsec.core.colors import Colors

TOP_PORTS = [
    (21,    "FTP"),
    (22,    "SSH"),
    (23,    "Telnet"),
    (25,    "SMTP"),
    (53,    "DNS"),
    (80,    "HTTP"),
    (110,   "POP3"),
    (111,   "RPCBind"),
    (135,   "MSRPC"),
    (139,   "NetBIOS"),
    (143,   "IMAP"),
    (443,   "HTTPS"),
    (445,   "SMB"),
    (993,   "IMAPS"),
    (995,   "POP3S"),
    (1723,  "PPTP"),
    (3306,  "MySQL"),
    (3389,  "RDP"),
    (5432,  "PostgreSQL"),
    (5900,  "VNC"),
    (6379,  "Redis"),
    (8080,  "HTTP-Proxy"),
    (8443,  "HTTPS-Alt"),
    (8888,  "HTTP-Alt"),
    (27017, "MongoDB"),
]

DANGEROUS_PORTS = {23, 445, 3389, 5900, 6379, 27017, 3306, 5432, 1723, 111, 135, 139}


def _scan_port(host, port, service, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, service, result == 0
    except Exception:
        return port, service, False


def run(url, domain, timeout=10):
    section("Port Scan", "📡")
    results = {"open": [], "closed": [], "summary": ""}

    connect_timeout = min(timeout, 3)
    open_ports = []
    closed_ports = []

    print(f"  Scanning {len(TOP_PORTS)} ports on {domain}...")
    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = {
            executor.submit(_scan_port, domain, port, service, connect_timeout): (port, service)
            for port, service in TOP_PORTS
        }
        for future in as_completed(futures):
            port, service, is_open = future.result()
            if is_open:
                open_ports.append((port, service))
            else:
                closed_ports.append((port, service))

    open_ports.sort(key=lambda x: x[0])
    closed_ports.sort(key=lambda x: x[0])

    if open_ports:
        print(f"\n{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}Open Ports:{Colors.RESET}")
        for port, service in open_ports:
            danger_flag = ""
            if port in DANGEROUS_PORTS:
                danger_flag = f"  {Colors.RED}⚠ DANGEROUS{Colors.RESET}"
            print(f"    {Colors.GREEN}●{Colors.RESET}  {Colors.BOLD}{port:5}{Colors.RESET}  {Colors.CYAN}{service:<15}{Colors.RESET}{danger_flag}")
    else:
        info("Open Ports", f"{Colors.DIM}None found{Colors.RESET}")

    dangerous_open = [p for p, s in open_ports if p in DANGEROUS_PORTS]
    if dangerous_open:
        warn(f"Potentially dangerous ports open: {', '.join(str(p) for p in dangerous_open)}")

    if len(open_ports) > 10:
        warn(f"Large attack surface: {len(open_ports)} open ports detected!")

    summary = f"{len(open_ports)} open / {len(closed_ports)} closed out of {len(TOP_PORTS)} scanned"
    info("Summary", summary)

    results["open"]    = [{"port": p, "service": s} for p, s in open_ports]
    results["closed"]  = [{"port": p, "service": s} for p, s in closed_ports]
    results["summary"] = summary
    return results
