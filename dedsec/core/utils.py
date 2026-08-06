import math
import socket
import threading
from contextlib import contextmanager
from difflib import SequenceMatcher
from functools import lru_cache
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import requests
import urllib3
from requests.adapters import HTTPAdapter

from dedsec.core.colors import Colors

DEFAULT_VERIFY_TLS = True
DEFAULT_HEADERS = {
    "User-Agent": "DEDSEC/1.3 authorized-security-recon",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}
EXTERNAL_INTELLIGENCE_HOSTS = {
    "crt.sh",
    "api.certspotter.com",
    "api.hackertarget.com",
    "ip-api.com",
}


class SafeResponse:
    """Transparent response proxy whose truth value means transport success.

    requests.Response.__bool__ is False for HTTP 4xx/5xx. Legacy DEDSEC modules
    historically used ``if not response`` to mean network failure, which caused
    real 404/403 responses to be mislabeled as request failures. This proxy keeps
    the complete requests.Response API while making any received HTTP response
    truthy. ``response.ok`` and ``status_code`` retain their normal semantics.
    """

    def __init__(self, response):
        object.__setattr__(self, "_response", response)

    def __getattr__(self, name):
        return getattr(self._response, name)

    def __setattr__(self, name, value):
        setattr(self._response, name, value)

    def __bool__(self):
        return True

    def __repr__(self):
        return repr(self._response)


def _truthy_response(response):
    if response is None or isinstance(response, SafeResponse):
        return response
    return SafeResponse(response)


def _get_headers() -> Dict[str, str]:
    return dict(DEFAULT_HEADERS)


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


def _build_session(total_retries=3, backoff_factor=0.5, pool_connections=20, pool_maxsize=40):
    session = requests.Session()
    adapter = HTTPAdapter(
        max_retries=_build_retry(total_retries, backoff_factor),
        pool_connections=max(pool_connections, 1),
        pool_maxsize=max(pool_maxsize, 1),
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


_SESSION = _build_session()
_REQUEST_CACHE = {}
_CACHE_LOCK = threading.RLock()
_BOUND_CONTEXT = None
_BOUND_TRANSPORT = None
_BINDING_LOCK = threading.RLock()


def configure_http_session(total_retries=3, backoff_factor=0.5, pool_connections=20, pool_maxsize=40):
    global _SESSION
    old_session = _SESSION
    _SESSION = _build_session(total_retries, backoff_factor, pool_connections, pool_maxsize)
    try:
        old_session.close()
    except Exception:
        pass


def bind_scan_context(context, retries=2, backoff=0.4, pool_connections=20, pool_maxsize=40):
    """Bind one process-wide scan context for legacy helpers.

    Modules execute in dedicated child processes, so process-wide binding is
    safe and intentionally visible to ThreadPoolExecutor workers spawned inside
    that module. A thread-local binding would silently let those worker threads
    bypass scope and request-budget enforcement.
    """
    global _BOUND_CONTEXT, _BOUND_TRANSPORT
    with _BINDING_LOCK:
        _BOUND_CONTEXT = context
        _BOUND_TRANSPORT = context.get_transport(
            retries=retries,
            backoff=backoff,
            verify_tls=True,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
        )


def unbind_scan_context():
    global _BOUND_CONTEXT, _BOUND_TRANSPORT
    with _BINDING_LOCK:
        _BOUND_CONTEXT = None
        _BOUND_TRANSPORT = None


@contextmanager
def scan_context_binding(context, **transport_options):
    bind_scan_context(context, **transport_options)
    try:
        yield
    finally:
        unbind_scan_context()


def _cache_key(url, method, allow_redirects, verify, headers, params):
    header_items = tuple(sorted((str(k).lower(), str(v)) for k, v in (headers or {}).items()))
    return (url, method.upper(), allow_redirects, verify, header_items, repr(params))


def _is_external_intelligence_url(url):
    return (urlparse(url).hostname or "").lower() in EXTERNAL_INTELLIGENCE_HOSTS


def safe_request(
    url,
    timeout=10,
    method="GET",
    allow_redirects=True,
    verify=DEFAULT_VERIFY_TLS,
    session=None,
    headers=None,
    data=None,
    params=None,
    json=None,
    cache=True,
    external_request=False,
):
    """Bounded HTTP helper with v2 enforcement when a ScanContext is bound.

    Target requests inherit scope, verified TLS, bounded redirects, target HTTP
    budget, retries, and cache semantics. Out-of-scope URLs fail closed except
    for the built-in external-intelligence allowlist or explicit opt-out.

    ``None`` means no HTTP response was obtained. Any actual HTTP response,
    including 4xx/5xx, is returned as a truthy SafeResponse.
    """
    method_upper = method.upper()
    merged_headers = _get_headers()
    if headers:
        merged_headers.update(headers)

    with _BINDING_LOCK:
        context = _BOUND_CONTEXT
        transport = _BOUND_TRANSPORT

    if context is not None and transport is not None and not external_request:
        decision = context.scope.check_url(url)
        if decision.allowed:
            outcome = transport.request(
                method_upper,
                url,
                timeout=timeout,
                allow_redirects=allow_redirects,
                headers=merged_headers,
                data=data,
                params=params,
                json_body=json,
                cache=cache,
                enforce_scope=True,
            )
            return _truthy_response(outcome.response)
        if not _is_external_intelligence_url(url):
            return None

    cacheable = cache and method_upper == "GET" and data is None and json is None
    key = _cache_key(url, method_upper, allow_redirects, verify, merged_headers, params)
    if cacheable:
        with _CACHE_LOCK:
            cached = _REQUEST_CACHE.get(key)
        if cached is not None:
            return _truthy_response(cached)

    client = session or _SESSION
    try:
        response = client.request(
            method_upper,
            url,
            headers=merged_headers,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            data=data,
            params=params,
            json=json,
        )
        if cacheable:
            with _CACHE_LOCK:
                _REQUEST_CACHE[key] = response
        return _truthy_response(response)
    except requests.RequestException:
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
    normalized = urlunparse(
        (parsed.scheme.lower(), netloc, parsed.path or "", "", parsed.query or "", "")
    )
    return normalized, parsed.hostname.lower()


def get_domain(url):
    return urlparse(url).hostname


def get_base_url(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else url


def append_query_param(url, param, value):
    return f"{url}{'&' if urlparse(url).query else '?'}{param}={value}"


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
    with _CACHE_LOCK:
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


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    return round(entropy, 3)


def get_soft404_profile(base_url: str, timeout: int = 8) -> dict:
    profiles = []
    for path in (
        "/dedsec_nonexistent_8f3a91",
        "/dedsec_404_test_992b1c",
        "/random_not_found_773x01",
    ):
        response = safe_request(urljoin(base_url, path), timeout=timeout, allow_redirects=True)
        if response is not None:
            profiles.append(
                {
                    "status_code": response.status_code,
                    "length": len(response.text),
                    "text_snippet": response.text[:1500],
                }
            )
    if not profiles:
        return {}
    statuses = [item["status_code"] for item in profiles]
    lengths = [item["length"] for item in profiles]
    return {
        "status_code": max(set(statuses), key=statuses.count),
        "avg_length": sum(lengths) // len(lengths),
        "sample_text": profiles[0]["text_snippet"],
    }


def is_soft_404(response, soft404_profile: dict) -> bool:
    if response is None or not soft404_profile:
        return False
    base_status = soft404_profile.get("status_code")
    base_len = soft404_profile.get("avg_length", 0)
    base_sample = soft404_profile.get("sample_text", "")
    if response.status_code == base_status and base_sample and base_len > 0:
        if abs(len(response.text) - base_len) / base_len < 0.10:
            return SequenceMatcher(None, base_sample, response.text[:1500]).quick_ratio() > 0.88
    return False


def get_wildcard_ips(domain: str) -> set:
    wildcard_ips = set()
    for subdomain in (
        f"dedsec-random-wildcard-1a2b3c.{domain}",
        f"nonexistent-test-subdomain-8877.{domain}",
        f"check-wildcard-dns-9911.{domain}",
    ):
        ip = cached_resolve_ipv4(subdomain)
        if ip:
            wildcard_ips.add(ip)
    return wildcard_ips


def is_wildcard_ip(ip: str, wildcard_ips: set) -> bool:
    return bool(ip and ip in wildcard_ips)
