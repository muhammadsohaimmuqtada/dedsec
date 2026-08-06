import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit


@dataclass
class NetworkPathResult:
    address: str
    family: str
    port: int
    state: str
    error_code: Optional[int]
    error: Optional[str]
    duration_seconds: float


def _state_from_errno(code: int) -> str:
    if code == 0:
        return "reachable"
    if code == errno.ECONNREFUSED:
        return "refused"
    if code in {
        errno.ETIMEDOUT,
        getattr(errno, "EINPROGRESS", -1),
        getattr(errno, "EALREADY", -1),
        getattr(errno, "EAGAIN", -1),
        getattr(errno, "EWOULDBLOCK", -1),
    }:
        return "filtered_or_timeout"
    if code in {
        getattr(errno, "EHOSTUNREACH", -1),
        getattr(errno, "ENETUNREACH", -1),
        getattr(errno, "EHOSTDOWN", -1),
    }:
        return "unreachable"
    return "error"


def resolve_target_paths(target_url: str) -> Dict[str, Any]:
    parsed = urlsplit(target_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    addresses: Dict[Tuple[int, str], None] = {}
    try:
        for family, socktype, proto, canonname, sockaddr in socket.getaddrinfo(
            host,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        ):
            del socktype, proto, canonname
            addresses[(family, sockaddr[0])] = None
    except socket.gaierror as exc:
        return {
            "host": host,
            "port": port,
            "dns": "failed",
            "error": str(exc),
            "addresses": [],
        }
    items = [
        {
            "family": "ipv6" if family == socket.AF_INET6 else "ipv4",
            "address": address,
        }
        for family, address in sorted(addresses, key=lambda item: (item[0], item[1]))
    ]
    return {"host": host, "port": port, "dns": "resolved", "addresses": items}


def _probe_one(family: int, address: str, port: int, timeout: float) -> NetworkPathResult:
    started = time.monotonic()
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(max(0.1, float(timeout)))
        code = sock.connect_ex((address, port))
        state = _state_from_errno(int(code))
        error = None if code == 0 else errno.errorcode.get(int(code), "errno-%s" % code)
        return NetworkPathResult(
            address=address,
            family="ipv6" if family == socket.AF_INET6 else "ipv4",
            port=port,
            state=state,
            error_code=int(code),
            error=error,
            duration_seconds=round(time.monotonic() - started, 3),
        )
    except socket.timeout as exc:
        return NetworkPathResult(
            address=address,
            family="ipv6" if family == socket.AF_INET6 else "ipv4",
            port=port,
            state="filtered_or_timeout",
            error_code=getattr(errno, "ETIMEDOUT", None),
            error=str(exc) or "timeout",
            duration_seconds=round(time.monotonic() - started, 3),
        )
    except OSError as exc:
        code = int(exc.errno or -1)
        return NetworkPathResult(
            address=address,
            family="ipv6" if family == socket.AF_INET6 else "ipv4",
            port=port,
            state=_state_from_errno(code),
            error_code=code,
            error=str(exc),
            duration_seconds=round(time.monotonic() - started, 3),
        )
    finally:
        sock.close()


def probe_target_paths(
    target_url: str,
    timeout: float = 3.0,
    max_workers: int = 8,
) -> Dict[str, Any]:
    resolved = resolve_target_paths(target_url)
    if resolved.get("dns") != "resolved":
        return resolved
    parsed = urlsplit(target_url)
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    entries = []
    for item in resolved.get("addresses", []):
        family = socket.AF_INET6 if item["family"] == "ipv6" else socket.AF_INET
        entries.append((family, item["address"]))
    results: List[NetworkPathResult] = []
    with ThreadPoolExecutor(max_workers=max(1, min(int(max_workers), len(entries) or 1))) as pool:
        futures = {
            pool.submit(_probe_one, family, address, port, timeout): (family, address)
            for family, address in entries
        }
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: (item.family, item.address))
    states: Dict[str, int] = {}
    for item in results:
        states[item.state] = states.get(item.state, 0) + 1
    return {
        "host": resolved.get("host"),
        "port": port,
        "dns": "resolved",
        "addresses": [asdict(item) for item in results],
        "states": dict(sorted(states.items())),
        "any_reachable": any(item.state == "reachable" for item in results),
    }
