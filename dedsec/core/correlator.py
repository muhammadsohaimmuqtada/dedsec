from typing import Any, Dict, List

from dedsec.core.contracts import ModuleResult


class FindingsCorrelator:
    """Evidence-first correlation: observations -> hypotheses -> verified findings."""

    _SEVERITY_WEIGHT = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 0}

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    @staticmethod
    def _evidence_ids(result: ModuleResult) -> List[str]:
        return list(result.evidence_ids or [])

    def _verified(
        self,
        result: ModuleResult,
        finding: str,
        severity: str,
        details: Dict[str, Any],
        verification: str,
    ) -> Dict[str, Any]:
        return {
            "source": result.module,
            "finding": finding,
            "severity": severity.upper(),
            "verification": verification,
            "evidence_ids": self._evidence_ids(result),
            "details": details,
        }

    def _hypothesis(
        self,
        result: ModuleResult,
        finding: str,
        details: Dict[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        return {
            "source": result.module,
            "finding": finding,
            "reason": reason,
            "evidence_ids": self._evidence_ids(result),
            "details": details,
        }

    @staticmethod
    def _positive_exposure_candidate(item: Dict[str, Any]) -> bool:
        evidence = str(item.get("evidence", "")).lower()
        # A 200/401/403 without the defining content signature is not a positive
        # security signal; it is a rejected validation attempt.
        negative_markers = {
            "content signature mismatch",
            "binary magic bytes missing",
            "json validation failed",
            "soft 404 response match",
        }
        return bool(evidence and evidence not in negative_markers)

    def correlate(self, module_results: List[ModuleResult]) -> Dict[str, Any]:
        result_map = {
            res.module: res
            for res in module_results
            if res.status == "success" and isinstance(res.data, dict)
        }
        observations: List[Dict[str, Any]] = []
        hypotheses: List[Dict[str, Any]] = []
        verified: List[Dict[str, Any]] = []
        rejected_or_unverified: List[Dict[str, Any]] = []

        for result in module_results:
            observations.append(
                {
                    "source": result.module,
                    "status": result.status,
                    "evidence_ids": self._evidence_ids(result),
                    "data_keys": sorted(result.data.keys()) if isinstance(result.data, dict) else [],
                }
            )
            if result.status != "success":
                rejected_or_unverified.append(
                    {
                        "source": result.module,
                        "reason": result.error or result.status,
                        "evidence_ids": self._evidence_ids(result),
                    }
                )

        exposures = result_map.get("exposures")
        if exposures:
            for item in exposures.data.get("confirmed", []):
                if exposures.evidence_ids:
                    verified.append(
                        self._verified(
                            exposures,
                            item.get("label", "Confirmed exposure"),
                            item.get("severity", "HIGH"),
                            item,
                            item.get("evidence", "module confirmation rule matched"),
                        )
                    )
            for item in exposures.data.get("candidates", []):
                if self._positive_exposure_candidate(item):
                    hypotheses.append(
                        self._hypothesis(
                            exposures,
                            item.get("label", "Exposure candidate"),
                            item,
                            "positive response requires manual validation",
                        )
                    )
                else:
                    rejected_or_unverified.append(
                        {
                            "source": "exposures",
                            "finding": item.get("label", "Exposure candidate"),
                            "reason": item.get("evidence", "validation signal did not match"),
                            "evidence_ids": self._evidence_ids(exposures),
                            "details": item,
                        }
                    )

        redirect = result_map.get("redirect")
        if redirect:
            for item in redirect.data.get("confirmed", []):
                if redirect.evidence_ids:
                    verified.append(
                        self._verified(
                            redirect,
                            "Open redirect via parameter '%s'" % item.get("param", "unknown"),
                            "HIGH",
                            item,
                            "external redirect reproduced while control remained internal",
                        )
                    )
            for item in redirect.data.get("candidates", []):
                hypotheses.append(
                    self._hypothesis(
                        redirect,
                        "Possible open redirect via '%s'" % item.get("param", "unknown"),
                        item,
                        "control behavior did not isolate attacker-controlled redirect",
                    )
                )

        subdomains = result_map.get("subdomains")
        if subdomains:
            for item in subdomains.data.get("takeovers", []):
                if item.get("verified") is True and item.get("proof") and subdomains.evidence_ids:
                    verified.append(
                        self._verified(
                            subdomains,
                            "Verified subdomain takeover on %s" % item.get("url", "unknown"),
                            "HIGH",
                            item,
                            str(item.get("proof")),
                        )
                    )
                else:
                    hypotheses.append(
                        self._hypothesis(
                            subdomains,
                            "Potential subdomain takeover on %s" % item.get("url", "unknown"),
                            item,
                            "provider/DNS fingerprint is not proof of claimability",
                        )
                    )

        cors = result_map.get("cors")
        if cors:
            for item in cors.data.get("findings", []):
                if item.get("confirmed") is True and item.get("impact") and cors.evidence_ids:
                    verified.append(
                        self._verified(
                            cors,
                            item.get("issue", "Confirmed CORS issue"),
                            item.get("severity", "HIGH"),
                            item,
                            str(item.get("impact")),
                        )
                    )
                elif item.get("candidate") is True:
                    hypotheses.append(
                        self._hypothesis(
                            cors,
                            item.get("issue", "CORS behavior requiring validation"),
                            item,
                            "configuration signal alone is not demonstrated impact",
                        )
                    )

        js = result_map.get("js")
        if js:
            for item in js.data.get("secrets", []):
                if item.get("confidence") == "high" and item.get("validated") is True:
                    hypotheses.append(
                        self._hypothesis(
                            js,
                            "Potential exposed secret: %s" % item.get("type", "unknown"),
                            item,
                            "secret-shaped value requires owner-side revocation/validity confirmation",
                        )
                    )

        score = min(
            sum(self._SEVERITY_WEIGHT.get(item["severity"], 0) for item in verified),
            100,
        )
        technology_summary: Dict[str, Any] = {"server": None, "cms": [], "frameworks": []}
        tech = result_map.get("tech")
        if tech:
            server = tech.data.get("server") or tech.data.get("server_header")
            if not server:
                servers = tech.data.get("servers", [])
                if servers and isinstance(servers[0], dict):
                    server = servers[0].get("name")
            technology_summary = {
                "server": server,
                "cms": [
                    item.get("name")
                    for item in tech.data.get("cms", [])
                    if isinstance(item, dict)
                ],
                "frameworks": [
                    item.get("name")
                    for item in tech.data.get("js_frameworks", [])
                    if isinstance(item, dict)
                ],
            }

        correlated = {
            "attack_surface_score": score,
            "technology_summary": technology_summary,
            "observations": observations,
            "hypotheses": hypotheses,
            "verified_findings": verified,
            "rejected_or_unverified": rejected_or_unverified,
            "critical_vulnerabilities": [
                item for item in verified if item.get("severity") in ("CRITICAL", "HIGH")
            ],
            "high_risks": [item for item in verified if item.get("severity") == "HIGH"],
            "medium_risks": [item for item in verified if item.get("severity") == "MEDIUM"],
            "attack_vectors": [],
        }
        self.findings = verified
        return correlated
