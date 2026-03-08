import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib.parse import urljoin, urlparse
from dedsec.core.colors import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "DEDSEC-Recon/1.0"}
DEFAULT_VERIFY_TLS = True
RETRY = urllib3.util.Retry(
    total=1,
    connect=1,
    read=1,
    status=1,
    backoff_factor=0.1,
    status_forcelist={429, 500, 502, 503, 504},
    allowed_methods={"GET", "HEAD"},
    raise_on_status=False,
)
_SESSION = requests.Session()
_ADAPTER = HTTPAdapter(max_retries=RETRY, pool_connections=20, pool_maxsize=40)
_SESSION.mount("http://", _ADAPTER)
_SESSION.mount("https://", _ADAPTER)

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
