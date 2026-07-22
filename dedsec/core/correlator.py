from typing import Any, Dict, List, Optional
from dedsec.core.contracts import ModuleResult


class FindingsCorrelator:
    """
    Correlates findings across independent modules to construct high-confidence attack surfaces and risk summaries.
    """

    def __init__(self):
        self.findings = []

    def correlate(self, module_results: List[ModuleResult]) -> Dict[str, Any]:
        result_map = {res.module: res.data for res in module_results if res.status == "success" and res.data}
        
        correlated = {
            "attack_surface_score": 0,
            "critical_vulnerabilities": [],
            "high_risks": [],
            "medium_risks": [],
            "technology_summary": [],
            "attack_vectors": []
        }

        # 1. Tech Stack Correlation
        tech_data = result_map.get("tech", {})
        frameworks = [item.get("name") for item in tech_data.get("js_frameworks", [])]
        cms = [item.get("name") for item in tech_data.get("cms", [])]
        server = tech_data.get("server")

        correlated["technology_summary"] = {
            "server": server,
            "cms": cms,
            "frameworks": frameworks
        }

        # 2. Exposure & Sensitive Path Correlation
        exposures = result_map.get("exposures", {})
        confirmed_exposures = exposures.get("confirmed", [])
        for exp in confirmed_exposures:
            correlated["critical_vulnerabilities"].append({
                "source": "exposure_checks",
                "finding": exp.get("label"),
                "url": exp.get("url"),
                "severity": exp.get("severity", "HIGH")
            })
            correlated["attack_surface_score"] += 25

        # 3. Subdomain Takeover Correlation
        subdomains = result_map.get("subdomains", {})
        takeovers = subdomains.get("takeovers", [])
        for to in takeovers:
            correlated["critical_vulnerabilities"].append({
                "source": "subdomain_enum",
                "finding": f"Subdomain Takeover on {to.get('url')} ({to.get('provider')})",
                "severity": "HIGH"
            })
            correlated["attack_surface_score"] += 30

        # 4. CORS Hijacking Risk Correlation
        cors = result_map.get("cors", {})
        if cors.get("vulnerable"):
            for f in cors.get("findings", []):
                if f.get("severity") in ("CRITICAL", "HIGH"):
                    correlated["critical_vulnerabilities"].append({
                        "source": "cors_check",
                        "finding": f.get("issue"),
                        "severity": f.get("severity")
                    })
                    correlated["attack_surface_score"] += 20

        # 5. Open Redirect & Chain Risk Correlation
        redirects = result_map.get("redirect", {})
        confirmed_redirects = redirects.get("confirmed", [])
        for red in confirmed_redirects:
            correlated["high_risks"].append({
                "source": "open_redirect",
                "finding": f"Open Redirect via parameter '{red.get('param')}'",
                "severity": "HIGH"
            })
            correlated["attack_surface_score"] += 15

        # Cap attack surface score at 100
        correlated["attack_surface_score"] = min(correlated["attack_surface_score"], 100)

        return correlated
