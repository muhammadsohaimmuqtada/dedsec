import errno
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from dedsec.core.colors import Colors
from dedsec.core.utils import info, safe_request, section

TOP_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"),
    (69, "TFTP"), (79, "Finger"), (80, "HTTP"), (88, "Kerberos"), (110, "POP3"),
    (111, "RPCBind"), (119, "NNTP"), (135, "MSRPC"), (139, "NetBIOS"), (143, "IMAP"),
    (179, "BGP"), (389, "LDAP"), (443, "HTTPS"), (445, "SMB"), (464, "Kerberos-chpw"),
    (500, "IKE/IPSec"), (512, "rexec"), (513, "rlogin"), (514, "rsh"), (587, "SMTP-Submit"),
    (631, "IPP/CUPS"), (636, "LDAPS"), (873, "rsync"), (902, "VMware"), (993, "IMAPS"),
    (995, "POP3S"), (1099, "Java-RMI"), (1194, "OpenVPN"), (1433, "MSSQL"), (1521, "Oracle"),
    (1723, "PPTP"), (2049, "NFS"), (2181, "ZooKeeper"), (2375, "Docker-API"), (2376, "Docker-TLS"),
    (3306, "MySQL"), (3389, "RDP"), (4369, "Erlang-EPMD"), (4848, "GlassFish"), (5000, "Dev/Flask"),
    (5432, "PostgreSQL"), (5601, "Kibana"), (5900, "VNC"), (6379, "Redis"), (7001, "WebLogic"),
    (7474, "Neo4j"), (8009, "AJP"), (8080, "HTTP-Proxy"), (8161, "ActiveMQ"), (8443, "HTTPS-Alt"),
    (8888, "HTTP-Alt"), (9000, "SonarQube"), (9200, "Elasticsearch"), (9300, "ES-Node"),
    (11211, "Memcached"), (15672, "RabbitMQ"), (27017, "MongoDB"),
]

REVIEW_PORTS = {
    23, 69, 79, 111, 135, 139, 389, 445, 512, 513, 514, 873, 1099, 2049,
    2181, 2375, 3306, 3389, 4848, 5432, 5900, 6379, 7001, 8009, 8161, 9000,
    9200, 9300, 11211, 15672, 27017,
}
HTTP_PORTS = {80, 443, 5000, 8080, 8443, 8888}


def _classify_connect_code(code):
    if code == 0:
        return "open"
    if code == errno.ECONNREFUSED:
        return "closed"
    if code == errno.ETIMEDOUT:
        return "filtered"
    if code in {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN}:
        return "unreachable"
    return "error"


def _scan_port(host, port, service, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(min(float(timeout), 3.0))
            code = sock.connect_ex((host, port))
            return port, service, _classify_connect_code(code), code
    except socket.timeout:
        return port, service, "filtered", errno.ETIMEDOUT
    except OSError as exc:
        code = exc.errno or -1
        return port, service, _classify_connect_code(code), code
    except Exception:
        return port, service, "error", -1


def _grab_banner(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in {80, 5000, 8080, 8888}:
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            raw = sock.recv(512)
        return raw.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return None


def _http_fingerprint(host, port, timeout):
    scheme = "https" if port in {443, 8443} else "http"
    response = safe_request(
        f"{scheme}://{host}:{port}/",
        timeout=timeout,
        allow_redirects=False,
        cache=False,
    )
    if response is None:
        return {}
    return {
        header: response.headers[header]
        for header in ("server", "x-powered-by", "via")
        if header in response.headers
    }


def _entries(items):
    return [
        {"port": port, "service": service, "socket_code": code}
        for port, service, code in sorted(items)
    ]


def run(url, domain, timeout=10):
    section("Port Exposure Scan", "📡")
    results = {
        "open": [],
        "closed": [],
        "filtered": [],
        "unreachable": [],
        "errors": [],
        "summary": "",
        "observations": [],
    }
    states = {
        "open": [],
        "closed": [],
        "filtered": [],
        "unreachable": [],
        "error": [],
    }

    print(f"  Scanning {len(TOP_PORTS)} bounded TCP ports on {domain}...")
    with ThreadPoolExecutor(max_workers=min(32, len(TOP_PORTS))) as executor:
        futures = [
            executor.submit(_scan_port, domain, port, service, timeout)
            for port, service in TOP_PORTS
        ]
        for future in as_completed(futures):
            port, service, state, code = future.result()
            states[state].append((port, service, code))

    open_ports = sorted((port, service) for port, service, _ in states["open"])
    banners = {}
    http_headers = {}

    def _enrich(port, service):
        banner = _grab_banner(domain, port)
        headers = _http_fingerprint(domain, port, timeout) if port in HTTP_PORTS else {}
        return port, banner, headers

    if open_ports:
        with ThreadPoolExecutor(max_workers=min(8, len(open_ports))) as executor:
            futures = [executor.submit(_enrich, port, service) for port, service in open_ports]
            for future in as_completed(futures):
                port, banner, headers = future.result()
                if banner:
                    banners[port] = banner
                if headers:
                    http_headers[port] = headers

        print(f"\n{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}Open Ports:{Colors.RESET}")
        for port, service in open_ports:
            review = f"  {Colors.YELLOW}review exposure{Colors.RESET}" if port in REVIEW_PORTS else ""
            print(f"    {Colors.GREEN}●{Colors.RESET}  {Colors.BOLD}{port:5}{Colors.RESET}  {Colors.CYAN}{service:<18}{Colors.RESET}{review}")
            if port in banners:
                print(f"           {Colors.DIM}Banner: {banners[port].replace(chr(10), ' ')[:120]}{Colors.RESET}")
            for key, value in http_headers.get(port, {}).items():
                print(f"           {Colors.DIM}{key}: {value}{Colors.RESET}")
            if port in REVIEW_PORTS:
                results["observations"].append(
                    {
                        "port": port,
                        "service": service,
                        "classification": "exposure-review",
                        "note": "Open service requires context-specific access-control/version review; port number alone is not a vulnerability.",
                    }
                )

    results["open"] = [
        {
            "port": port,
            "service": service,
            "banner": banners.get(port),
            "http_headers": http_headers.get(port, {}),
        }
        for port, service in open_ports
    ]
    results["closed"] = _entries(states["closed"])
    results["filtered"] = _entries(states["filtered"])
    results["unreachable"] = _entries(states["unreachable"])
    results["errors"] = _entries(states["error"])

    results["summary"] = (
        f"{len(states['open'])} open / {len(states['closed'])} closed / "
        f"{len(states['filtered'])} filtered-timeout / {len(states['unreachable'])} unreachable / "
        f"{len(states['error'])} error out of {len(TOP_PORTS)} scanned"
    )
    info("Summary", results["summary"])
    return results
