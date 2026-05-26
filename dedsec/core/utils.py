import socket
from functools import lru_cache
from typing import Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from dedsec.core.colors import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "DEDSEC-Recon/1.0"}
DEFAULT_VERIFY_TLS = True
def _build_retry(total_retries: int, backoff_factor: float) -> urllib3.util.Retry:
    return urllib3.util.Retry(
        total=max(total_retries, 0),
        connect=max(total_retries - 1, 0),
        read=max(total_retries - 1, 0),
        status=max(total_retries - 1, 0),
        backoff_factor=max(backoff_factor, 0.0),
        status_forcelist={429, 500, 502, 503, 504},
        allowed_methods={"GET", "HEAD"},
        raise_on_status=False,
    )


def _build_session(total_retries: int = 3, backoff_factor: float = 0.5, pool_connections: int = 20, pool_maxsize: int = 40):
    session = requests.Session()
    adapter = HTTPAdapter(
        max_retries=_build_retry(total_retries=total_retries, backoff_factor=backoff_factor),
        pool_connections=max(pool_connections, 1),
        pool_maxsize=max(pool_maxsize, 1),
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


_SESSION = _build_session()


def configure_http_session(total_retries: int = 3, backoff_factor: float = 0.5, pool_connections: int = 20, pool_maxsize: int = 40):
    global _SESSION
    _SESSION = _build_session(
        total_retries=total_retries,
        backoff_factor=backoff_factor,
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
    )

def safe_request(url, timeout=10, method="GET", allow_redirects=True, verify=DEFAULT_VERIFY_TLS, session=None):
    client = session or _SESSION
    request = getattr(client, method.lower(), None)
    if request is None:
        return None

    try:
        return request(
            url,
            headers=HEADERS,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
        )
    except requests.exceptions.SSLError:
        if not verify:
            return None
        try:
            return request(
                url,
                headers=HEADERS,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=False,
            )
        except Exception:
            return None
    except Exception:
        return None


def normalize_target(raw_target: str, default_scheme: str = "https") -> Tuple[str, str]:
    candidate = (raw_target or "").strip()
    if not candidate:
        raise ValueError("Target cannot be empty.")

    if "://" not in candidate:
        candidate = f"{default_scheme}://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http/https URLs are supported.")
    if not parsed.hostname:
        raise ValueError("Target must include a valid host.")

    netloc = parsed.hostname.lower()
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    normalized_url = urlunparse(
        (
            parsed.scheme.lower(),
            netloc,
            parsed.path or "",
            "",
            parsed.query or "",
            "",
        )
    )
    return normalized_url, parsed.hostname.lower()


def get_domain(url):
    return urlparse(url).hostname

def get_base_url(url):
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return url
    return f"{parsed.scheme}://{parsed.netloc}"

def append_query_param(url, param, value):
    separator = "&" if urlparse(url).query else "?"
    return f"{url}{separator}{param}={value}"

def normalize_asset_url(base_url, asset_url):
    if asset_url.startswith("//"):
        return f"{urlparse(base_url).scheme}:{asset_url}"
    return urljoin(base_url, asset_url)


@lru_cache(maxsize=512)
def cached_resolve_ipv4(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


@lru_cache(maxsize=512)
def cached_resolve_ips(domain: str):
    ips = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
        except Exception:
            continue
        for entry in infos:
            ips.add(entry[4][0])
    return tuple(sorted(ips))


def clear_runtime_caches():
    cached_resolve_ipv4.cache_clear()
    cached_resolve_ips.cache_clear()

def section(title, icon):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'─'*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{icon}  {title}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'─'*60}{Colors.RESET}")

def info(key, value):
    print(f"{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}{key}:{Colors.RESET} {value}")

def warn(msg):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")

def error(msg):
    print(f"{Colors.RED}[-]{Colors.RESET} {msg}")
