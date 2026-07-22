# DeepSeek Codebase Analysis & Refactoring Guide for DEDSEC

## Objective
Analyze the DEDSEC codebase structure and recommend logic, architectural, and pattern improvements to transform it into an elite, modular, production-ready web reconnaissance framework.

---

## 1. Codebase Overview & Architecture Map

### Core Architecture
- **Entry point**: `dedsec/cli.py` built on `typer` and `rich`.
- **Contracts**: `dedsec/core/contracts.py` defines `ScanConfig`, `ModuleResult`, `ModuleSummary`, `TargetInfo`, and `PerModuleConfig`.
- **Orchestrator**: `dedsec/core/orchestrator.py` manages concurrent module execution using `ThreadPoolExecutor` with optional per-module and global timeouts, stdout capturing, and execution telemetry.
- **HTTP Session**: `dedsec/core/utils.py` configures a global `requests.Session` with `urllib3.util.Retry` exponential backoff and connection pooling.
- **Reporting**: `dedsec/core/report.py` outputs rich console summary and optional JSON report artifacts.

### Current Modules (15 Total)
1. `waf_detect.py` — WAF signature scoring & trigger payload probing.
2. `tech_fingerprint.py` — Weighted header, cookie, and body pattern matching for tech stacks.
3. `dns_recon.py` — DNS record lookup, SPF/DMARC evaluation, zone transfer testing.
4. `ip_geo.py` — IP geolocation and AS intel via ip-api.com.
5. `ssl_analysis.py` — TLS protocol probing, cipher analysis, SAN enumeration, expiry check.
6. `header_audit.py` — Security header presence validation and information disclosure checks.
7. `open_redirect.py` — Parameter-based open redirect testing with control validation.
8. `robots_sitemap.py` — Parse robots.txt and sitemap.xml for hidden endpoints.
9. `cookie_audit.py` — Cookie security attributes audit (Secure, HttpOnly, SameSite, domain scope).
10. `port_scan.py` — Multi-threaded top-25 TCP port scanner.
11. `whois_lookup.py` — WHOIS record lookup via python-whois.
12. `subdomain_enum.py` — Certificate Transparency log parsing (crt.sh).
13. `js_extraction.py` — JS file URL extraction and API endpoint pattern extraction.
14. `hosting_intel.py` — Cloud provider IP range matching (AWS, GCP, Azure, Cloudflare).
15. `exposure_checks.py` — Common sensitive path exposure probes (.env, phpinfo, git, actuator).

---

## 2. Weaknesses & Improvement Opportunities

### Architecture & Concurrency
- `ThreadPoolExecutor` per-module stdout capture using thread-local redirection is functional, but lacks structured logging/events.
- Global HTTP `requests.Session` is reused across threads, but individual modules don't customize headers, user-agents, or proxies per module.
- Retries on GET/HEAD can cause slow scans on rate-limited targets without adaptive backoff per domain.

### Module Logic Improvements

#### 1. WAF Detection (`waf_detect.py`)
- **Current**: 11 signatures, 5 trigger payloads.
- **Improvement**:
  - Add 14 additional WAF signatures (Azure Front Door, Fastly, CloudFront, Radware, Wallarm, StackPath, DataDome, Kasada, PerimeterX, HAProxy, Reblaze, DenyAll, Kona SiteDefender, SiteLock).
  - Add response-diff scoring: compare base response length/status vs payload trigger response length/status to increase detection confidence.
  - Distinguish CDN headers (e.g. `cf-ray`, `x-amz-cf-pop`) from actual WAF blocking behavior to avoid CDN-only false positives.

#### 2. Subdomain Enumeration (`subdomain_enum.py`)
- **Current**: crt.sh only, capped at 300 entries, resolves up to 50.
- **Improvement**:
  - Add multi-source CT logs (CertSpotter API, HackerTarget, AlienVault OTX).
  - Add DNS brute-forcing with common subdomain wordlists (`COMMON_SUBDOMAINS`).
  - Add domain permutation generation (`dev-{domain}`, `{domain}-staging`, etc.).
  - Increase resolution cap to 200 validated alive subdomains.

#### 3. JavaScript & Endpoint Extraction (`js_extraction.py`)
- **Current**: Basic endpoint regex, simple email regex.
- **Improvement**:
  - Add hardcoded secret detection patterns (AWS keys, Google API keys, Stripe, Slack, JWT tokens, private keys, generic API tokens, hardcoded passwords, internal IPs).
  - Fetch and scan extracted JS files recursively (up to depth 2) for secrets and hidden API routes.
  - Add Next.js `__NEXT_DATA__` JSON blob parsing to extract page routes and props.

#### 4. Port Scan (`port_scan.py`)
- **Current**: 25 top ports, TCP connect only.
- **Improvement**:
  - Expand to top 65 ports including critical database, management, and cloud ports (MongoDB, Redis, Elasticsearch, Docker API, Kubernetes API, Java RMI, NFS, Memcached, ActiveMQ).
  - Add lightweight banner grabbing on open ports to identify running service versions.

#### 5. Open Redirect (`open_redirect.py`)
- **Current**: 15 parameters tested.
- **Improvement**:
  - Expand parameter list to 35 common parameters (`to`, `link`, `location`, `from`, `page`, `ref`, `referrer`, `forward`, `jump`, etc.).
  - Add HTML `<meta http-equiv="refresh">` and JavaScript `window.location` assignment detection in responses.
  - Add multi-hop redirect chain following up to 5 hops.

#### 6. Exposure Checks (`exposure_checks.py`)
- **Current**: 6 basic paths.
- **Improvement**:
  - Expand path list to 25+ sensitive paths (.env.local, .env.production, .git/HEAD, .git/index, .svn/entries, config.json, config.yml, backup.zip, db.sql, swagger-ui.html, openapi.json, security.txt, crossdomain.xml, admin panels).
  - Implement strict content fingerprint validation (checking for JSON structure, binary magic bytes like `DIRC`, or specific string signatures) to eliminate false positives from custom 200 OK error pages.

#### 7. DNS Recon (`dns_recon.py`)
- **Current**: Basic record lookup, simple SPF/DMARC presence check.
- **Improvement**:
  - Add DKIM selector checking (`default._domainkey`, `google._domainkey`, etc.).
  - Add DNSSEC validation check.
  - Add SPF policy strength evaluation (`+all` vs `-all` vs `~all`).
  - Add dangling CNAME takeover detection.

#### 8. Header Audit (`header_audit.py`)
- **Current**: Basic header presence table.
- **Improvement**:
  - Deep CSP directive analysis (`unsafe-inline`, `unsafe-eval`, wildcard sources, missing `default-src` / `script-src`).
  - HSTS `preload` parameter validation.

#### 9. SSL Analysis (`ssl_analysis.py`)
- **Current**: Protocol probing and SAN listing.
- **Improvement**:
  - Detect self-signed certificates (`subject == issuer`).
  - Detect deprecated signature algorithms (SHA-1, MD5).
  - Check Signed Certificate Timestamps (SCT) for Certificate Transparency compliance.

---

## 3. New Dedicated Modules Proposed

1. `cors_check.py` — Audit CORS misconfigurations (wildcard ACAO, reflected Origin, `Access-Control-Allow-Credentials: true`, null origin, HTTP downgrade).
2. `csp_analyzer.py` — Standalone deep CSP analysis module evaluating directive weaknesses and bypass vectors.
3. `rate_limit_check.py` — Safely test rate limiting presence on login/sensitive endpoints using rapid sequential requests.
4. `clickjacking_check.py` — Dedicated framing protection auditor evaluating X-Frame-Options and CSP `frame-ancestors`.
5. `email_security.py` — Comprehensive email security audit module (SPF, DMARC, DKIM, MX banner disclosure, open relay detection).

---

## 4. Architectural Enhancements Proposed

1. **User-Agent Rotation**: Rotate standard browser User-Agents across requests in `safe_request()` to reduce basic WAF blocking.
2. **Request Caching**: In-memory LRU cache for identical GET requests to avoid duplicate target load.
3. **Scan Profile Presets**: Add `--market` profile for fast curated scans and `--thorough` profile for full audit.
