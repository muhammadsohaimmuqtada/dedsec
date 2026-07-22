import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from dedsec.core.colors import Colors
from dedsec.core.utils import safe_request, section, info, warn, error

TOP_PORTS = [
    (21,    "FTP"),
    (22,    "SSH"),
    (23,    "Telnet"),
    (25,    "SMTP"),
    (53,    "DNS"),
    (69,    "TFTP"),
    (79,    "Finger"),
    (80,    "HTTP"),
    (88,    "Kerberos"),
    (110,   "POP3"),
    (111,   "RPCBind"),
    (119,   "NNTP"),
    (135,   "MSRPC"),
    (139,   "NetBIOS"),
    (143,   "IMAP"),
    (179,   "BGP"),
    (389,   "LDAP"),
    (443,   "HTTPS"),
    (445,   "SMB"),
    (464,   "Kerberos-chpw"),
    (500,   "IKE/IPSec"),
    (512,   "rexec"),
    (513,   "rlogin"),
    (514,   "rsh"),
    (587,   "SMTP-Submit"),
    (631,   "IPP/CUPS"),
    (636,   "LDAPS"),
    (873,   "rsync"),
    (902,   "VMware"),
    (993,   "IMAPS"),
    (995,   "POP3S"),
    (1099,  "Java-RMI"),
    (1194,  "OpenVPN"),
    (1433,  "MSSQL"),
    (1521,  "Oracle"),
    (1723,  "PPTP"),
    (2049,  "NFS"),
    (2181,  "ZooKeeper"),
    (2375,  "Docker-API"),
    (2376,  "Docker-TLS"),
    (3306,  "MySQL"),
    (3389,  "RDP"),
    (4369,  "Erlang-EPMD"),
    (4848,  "GlassFish"),
    (5000,  "Dev/Flask"),
    (5432,  "PostgreSQL"),
    (5601,  "Kibana"),
    (5900,  "VNC"),
    (6379,  "Redis"),
    (7001,  "WebLogic"),
    (7474,  "Neo4j"),
    (8009,  "AJP"),
    (8080,  "HTTP-Proxy"),
    (8161,  "ActiveMQ"),
    (8443,  "HTTPS-Alt"),
    (8888,  "HTTP-Alt"),
    (9000,  "SonarQube"),
    (9200,  "Elasticsearch"),
    (9300,  "ES-Node"),
    (11211, "Memcached"),
    (15672, "RabbitMQ"),
    (27017, "MongoDB"),
]

DANGEROUS_PORTS = {
    23, 69, 79, 111, 135, 139, 179, 389, 445, 512, 513, 514,
    873, 902, 1099, 1723, 2049, 2181, 2375, 2376, 3306, 3389,
    4369, 4848, 5432, 5900, 6379, 7001, 7474, 8009, 8161,
    9000, 9200, 9300, 11211, 15672, 27017,
}

HTTP_PORTS = {80, 8080, 8888, 5000, 8000, 3000, 4000}
BANNER_TIMEOUT = 2


def _scan_port(host, port, service, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(min(timeout, 3))
        result = sock.connect_ex((host, port))
        sock.close()
        return port, service, result == 0
    except Exception:
        return port, service, False


def _grab_banner(host, port, timeout=BANNER_TIMEOUT):
    """Connect to an open port and read the service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in HTTP_PORTS:
            sock.send(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        raw = sock.recv(512)
        sock.close()
        return raw.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return None


def _http_fingerprint(host, port, timeout=5):
    """For HTTP(S) ports grab Server and X-Powered-By from a real HTTP request."""
    scheme = "https" if port in (443, 8443) else "http"
    target_url = f"{scheme}://{host}:{port}/"
    resp = safe_request(target_url, timeout=timeout)
    if not resp:
        return {}
    headers = {}
    for h in ("server", "x-powered-by", "x-aspnet-version", "via"):
        v = resp.headers.get(h)
        if v:
            headers[h] = v
    return headers


def run(url, domain, timeout=10):
    section("Port Scan", "📡")
    results = {"open": [], "closed": [], "summary": ""}

    connect_timeout = min(timeout, 3)
    open_ports = []
    closed_ports = []

    print(f"  Scanning {len(TOP_PORTS)} ports on {domain}...")
    with ThreadPoolExecutor(max_workers=min(65, len(TOP_PORTS))) as executor:
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

    # --- Banner grabbing for open ports ---
    banners = {}
    http_headers_map = {}

    if open_ports:
        def _banner_job(port, service):
            banner = _grab_banner(domain, port)
            http_hdrs = {}
            if port in HTTP_PORTS or port in (443, 8443, 8080, 8888):
                http_hdrs = _http_fingerprint(domain, port, timeout)
            return port, banner, http_hdrs

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(_banner_job, port, service): (port, service)
                for port, service in open_ports
            }
            for future in as_completed(futures):
                port, banner, http_hdrs = future.result()
                if banner:
                    banners[port] = banner
                if http_hdrs:
                    http_headers_map[port] = http_hdrs

    # --- Output open ports ---
    if open_ports:
        print(f"\n{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}Open Ports:{Colors.RESET}")
        for port, service in open_ports:
            danger_flag = f"  {Colors.RED}\u26a0 DANGEROUS{Colors.RESET}" if port in DANGEROUS_PORTS else ""
            print(f"    {Colors.GREEN}\u25cf{Colors.RESET}  {Colors.BOLD}{port:5}{Colors.RESET}  {Colors.CYAN}{service:<18}{Colors.RESET}{danger_flag}")
            if port in banners:
                banner_short = banners[port].replace("\n", " ").replace("\r", "")[:120]
                print(f"           {Colors.DIM}Banner: {banner_short}{Colors.RESET}")
            if port in http_headers_map:
                for hk, hv in http_headers_map[port].items():
                    print(f"           {Colors.DIM}{hk}: {hv}{Colors.RESET}")
    else:
        info("Open Ports", f"{Colors.DIM}None found{Colors.RESET}")

    dangerous_open = [p for p, s in open_ports if p in DANGEROUS_PORTS]
    if dangerous_open:
        warn(f"Potentially dangerous ports open: {', '.join(str(p) for p in dangerous_open)}")

    if len(open_ports) > 10:
        warn(f"Large attack surface: {len(open_ports)} open ports detected!")

    summary = f"{len(open_ports)} open / {len(closed_ports)} closed out of {len(TOP_PORTS)} scanned"
    info("Summary", summary)

    results["open"] = [
        {
            "port": p,
            "service": s,
            "banner": banners.get(p),
            "http_headers": http_headers_map.get(p, {}),
        }
        for p, s in open_ports
    ]
    results["closed"] = [{"port": p, "service": s} for p, s in closed_ports]
    results["summary"] = summary
    return results
