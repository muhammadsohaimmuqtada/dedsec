from dedsec.core.colors import Colors
from dedsec.core.utils import info, safe_request, section, warn


def run(url, domain, timeout=10):
    section("CORS Configuration Check", "🌐")
    results = {
        "findings": [],
        "observations": [],
        "tested_origins": [],
        "transport_failures": 0,
        "vulnerable": False,
    }

    attacker_origins = [
        "https://attacker.invalid",
        f"https://{domain}.attacker.invalid",
        "null",
        f"https://evil-{domain.replace('.', '-')}.invalid",
        f"http://{domain}",
    ]

    print(f"  Testing CORS behavior with {len(attacker_origins)} controlled Origin values...")

    for origin in attacker_origins:
        results["tested_origins"].append(origin)
        resp = safe_request(
            url,
            headers={"Origin": origin, "User-Agent": "DEDSEC-Recon/1.3"},
            timeout=timeout,
            cache=False,
        )
        if resp is None:
            results["transport_failures"] += 1
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()
        vary = resp.headers.get("Vary", "")
        if not acao:
            continue

        base = {
            "origin": origin,
            "status": resp.status_code,
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "vary": vary,
        }

        if acao == origin and acac == "true":
            results["findings"].append(
                dict(
                    base,
                    severity="MEDIUM",
                    issue="Arbitrary Origin reflection with credentials",
                    candidate=True,
                    confirmed=False,
                    impact=None,
                    note="Potentially dangerous configuration; sensitive cross-origin readability was not demonstrated by this probe.",
                )
            )
        elif acao == origin:
            results["observations"].append(
                dict(
                    base,
                    type="reflected-origin",
                    note="Origin reflection observed without credentialed impact proof.",
                )
            )
        elif acao == "*" and acac == "true":
            results["observations"].append(
                dict(
                    base,
                    type="wildcard-with-credentials",
                    note="Browsers do not allow credentialed CORS reads with ACAO '*'; configuration should still be reviewed.",
                )
            )
        elif acao == "*":
            results["observations"].append(
                dict(
                    base,
                    type="wildcard-origin",
                    note="Wildcard CORS is commonly intentional for public resources and is not a vulnerability by itself.",
                )
            )

    results["vulnerable"] = any(item.get("confirmed") is True for item in results["findings"])

    if results["findings"]:
        for item in results["findings"]:
            warn(
                f"CORS candidate: {item['issue']} for Origin '{item['origin']}' "
                "(impact not demonstrated)"
            )
    elif results["observations"]:
        info("CORS Result", f"{len(results['observations'])} configuration observation(s); no demonstrated impact")
    else:
        info("CORS Result", f"{Colors.GREEN}No permissive CORS behavior observed.{Colors.RESET}")

    if results["transport_failures"]:
        warn(f"{results['transport_failures']} CORS probe(s) had transport failures.")
    return results
