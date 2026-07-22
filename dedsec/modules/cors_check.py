from urllib.parse import urlparse
from dedsec.core.colors import Colors
from dedsec.core.utils import safe_request, section, info, warn, error
import requests

def run(url, domain, timeout=10):
    section("CORS Misconfiguration Check", "🌐")
    results = {"findings": [], "tested_origins": [], "vulnerable": False}

    attacker_origins = [
        "https://evil.example.com",
        f"https://{domain}.evil.com",
        "null",
        f"https://evil{domain}",
        f"http://{domain}",
    ]

    print(f"  Testing CORS configurations with {len(attacker_origins)} origins...")

    for origin in attacker_origins:
        results["tested_origins"].append(origin)
        try:
            # We construct a custom request with the Origin header
            headers = {
                "Origin": origin,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DEDSEC-Recon/1.0"
            }
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
            
            acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

            if not acao:
                continue

            finding = {
                "origin": origin,
                "access_control_allow_origin": acao,
                "access_control_allow_credentials": acac,
                "severity": None,
                "issue": None
            }

            # Case 1: Reflecting arbitrary attacker origin with Credentials=True (CRITICAL)
            if acao == origin and acac == "true":
                finding["severity"] = "CRITICAL"
                finding["issue"] = "Reflected Origin with Credentials enabled (Full CORS Hijacking risk)"
                
            # Case 2: Wildcard ACAO with Credentials=True (HIGH - browser rejects but indicates misconfig)
            elif acao == "*" and acac == "true":
                finding["severity"] = "HIGH"
                finding["issue"] = "Wildcard ACAO '*' combined with Allow-Credentials (Invalid config, but dangerous)"

            # Case 3: Reflecting arbitrary origin without credentials (MEDIUM)
            elif acao == origin:
                finding["severity"] = "MEDIUM"
                finding["issue"] = "Reflected Origin without credentials (potential data exposure if resource is public/unauthenticated)"

            # Case 4: Wildcard ACAO without credentials (LOW/INFO - typical for public APIs)
            elif acao == "*":
                finding["severity"] = "LOW"
                finding["issue"] = "Wildcard Access-Control-Allow-Origin (Acceptable for public resources/APIs)"

            if finding["severity"]:
                results["findings"].append(finding)
                results["vulnerable"] = True

        except Exception as e:
            pass

    if results["findings"]:
        for f in results["findings"]:
            sev_color = {
                "CRITICAL": Colors.RED,
                "HIGH": Colors.RED,
                "MEDIUM": Colors.YELLOW,
                "LOW": Colors.DIM
            }.get(f["severity"], Colors.RESET)
            
            warn(f"CORS {sev_color}{f['severity']}{Colors.RESET}: {f['issue']} on origin '{f['origin']}'")
    else:
        info("CORS Result", f"{Colors.GREEN}CORS configuration appears secure or restricted.{Colors.RESET}")

    return results
