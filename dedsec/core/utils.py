import socket
import random
import math
from difflib import SequenceMatcher
from functools import lru_cache
from typing import Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from dedsec.core.colors import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

DEFAULT_VERIFY_TLS = True

def _get_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

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

# Simple LRU cache for the base request to prevent duplicate hits across modules
_REQUEST_CACHE = {}

def configure_http_session(total_retries: int = 3, backoff_factor: float = 0.5, pool_connections: int = 20, pool_maxsize: int = 40):
    global _SESSION
    _SESSION = _build_session(
        total_retries=total_retries,
        backoff_factor=backoff_factor,
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
    )

def safe_request(url, timeout=10, method="GET", allow_redirects=True, verify=DEFAULT_VERIFY_TLS, session=None):
    # Cache GET requests to the landing page or base domain to save server/client load
    cache_key = (url, method, allow_redirects, verify)
    if method.upper() == "GET" and cache_key in _REQUEST_CACHE:
        return _REQUEST_CACHE[cache_key]

    client = session or _SESSION
    request = getattr(client, method.lower(), None)
    if request is None:
        return None

    try:
        resp = request(
            url,
            headers=_get_headers(),
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
        )
        if method.upper() == "GET":
            _REQUEST_CACHE[cache_key] = resp
        return resp
    except requests.exceptions.SSLError:
        if not verify:
            return None
        try:
            resp = request(
                url,
                headers=_get_headers(),
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=False,
            )
            if method.upper() == "GET":
                _REQUEST_CACHE[cache_key] = resp
            return resp
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
    global _REQUEST_CACHE
    _REQUEST_CACHE.clear()

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


# ---------------------------------------------------------------------------
# Phase 2 Core Helpers: Entropy, Soft-404, Wildcard DNS
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    """Calculate Shannon Entropy (randomness score) of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occ = {}
    for char in data:
        occ[char] = occ.get(char, 0) + 1
    for count in occ.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def get_soft404_profile(base_url: str, timeout: int = 8) -> dict:
    """
    Probe non-existent random paths to build a baseline profile of custom 404 / error pages.
    """
    random_paths = [
        "/dedsec_nonexistent_8f3a91",
        "/dedsec_404_test_992b1c",
        "/random_not_found_773x01"
    ]
    profiles = []
    for path in random_paths:
        target = urljoin(base_url, path)
        resp = safe_request(target, timeout=timeout, allow_redirects=True)
        if resp:
            profiles.append({
                "status_code": resp.status_code,
                "length": len(resp.text),
                "text_snippet": resp.text[:1500]
            })
    
    if not profiles:
        return {}

    # Pick common status code & average length
    status_codes = [p["status_code"] for p in profiles]
    lengths = [p["length"] for p in profiles]
    common_status = max(set(status_codes), key=status_codes.count)
    avg_length = sum(lengths) // len(lengths)
    
    return {
        "status_code": common_status,
        "avg_length": avg_length,
        "sample_text": profiles[0]["text_snippet"] if profiles else ""
    }


def is_soft_404(response, soft404_profile: dict) -> bool:
    """
    Compare a candidate HTTP response against the baseline Soft-404 profile.
    Returns True if the response is essentially a soft 404 custom error page.
    """
    if not response or not soft404_profile:
        return False
        
    base_status = soft404_profile.get("status_code")
    base_len = soft404_profile.get("avg_length", 0)
    base_sample = soft404_profile.get("sample_text", "")

    # If the candidate status matches soft-404 status (e.g. 200) and text is almost identical
    if response.status_code == base_status and base_sample:
        candidate_sample = response.text[:1500]
        # Length diff percentage
        if base_len > 0:
            len_diff_pct = abs(len(response.text) - base_len) / base_len
            if len_diff_pct < 0.10: # within 10% length match
                # Similarity ratio
                ratio = SequenceMatcher(None, base_sample, candidate_sample).quick_ratio()
                if ratio > 0.88:
                    return True

    return False


def get_wildcard_ips(domain: str) -> set:
    """
    Check if a domain resolves non-existent subdomains to a wildcard IP set.
    """
    test_subdomains = [
        f"dedsec-random-wildcard-1a2b3c.{domain}",
        f"nonexistent-test-subdomain-8877.{domain}",
        f"check-wildcard-dns-9911.{domain}"
    ]
    wildcard_ips = set()
    for sub in test_subdomains:
        ip = cached_resolve_ipv4(sub)
        if ip:
            wildcard_ips.add(ip)
    return wildcard_ips


def is_wildcard_ip(ip: str, wildcard_ips: set) -> bool:
    """Check if an IP belongs to a wildcard DNS catch-all."""
    return bool(ip and ip in wildcard_ips)
