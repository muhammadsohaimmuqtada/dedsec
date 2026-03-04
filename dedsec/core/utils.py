import requests
import urllib3
from urllib.parse import urlparse
from dedsec.core.colors import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "DEDSEC-Recon/1.0"}

def safe_request(url, timeout=10):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        return resp
    except requests.exceptions.SSLError:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=True)
            return resp
        except Exception:
            return None
    except Exception:
        return None

def get_domain(url):
    return urlparse(url).hostname

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
