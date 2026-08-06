# DEDSEC — Evidence-Driven Web Reconnaissance Framework

[![Version](https://img.shields.io/badge/version-1.3.0-4c8bf5?style=flat-square)](https://github.com/muhammadsohaimmuqtada/dedsec)
[![Python](https://img.shields.io/badge/Python-3.8--3.13-blue?style=flat-square&logo=python)](https://www.python.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/muhammadsohaimmuqtada/dedsec/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/muhammadsohaimmuqtada/dedsec/actions)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

DEDSEC is a modular reconnaissance framework for **authorized web security testing**. It combines attack-surface discovery, service profiling, web-configuration analysis, endpoint extraction, evidence capture, and structured reporting in a single CLI.

The 1.3 release is benchmark-driven. It hardens execution deadlines and cancellation, routes legacy target HTTP traffic through the scoped v2 transport, and tightens detector semantics so observations are not promoted into vulnerabilities without evidence.

## Project status

| Component | Current state |
| --- | --- |
| Package version | `1.3.0` |
| Built-in modules | `24` |
| Report schema | `2.0` |
| Supported Python | `3.8`–`3.13` |
| Execution | Process-isolated concurrent modules with hard deadlines |
| Target HTTP | Scoped, verified TLS, bounded redirects, shared request budget |
| Evidence | Scan IDs, SHA-256 evidence references, redaction, ANSI-clean artifacts |
| Finding model | Observation → candidate/hypothesis → verified finding |
| Legacy compatibility | `safe_request()` transparently inherits the v2 HTTP runtime inside module processes |
| CI | Ruff + compile + unittest/package/CLI matrix |

## Highlights

- 24 built-in reconnaissance and security-posture modules
- process-isolated module execution: a stuck module can be terminated instead of holding the scanner indefinitely
- hard per-module and global scan deadlines
- live module start/completion/timeout progress
- centralized target HTTP scope and request budgeting
- TLS verification enabled by default with no automatic insecure fallback
- redirect scope enforcement: automatic redirects are not followed outside target scope
- exact target HTTP retry-attempt accounting in the v2 transport
- cache keys vary by headers, request body, parameters, and redirect behavior
- evidence IDs, sensitive-value redaction, ANSI-clean evidence, and optional atomic artifacts
- conservative observation → candidate → verified-finding correlation
- versioned JSON report schema with runtime metadata
- Python 3.8–3.13 CI matrix

## Architecture

```text
CLI
 │
 ▼
ScanContext
 ├── ScopePolicy
 ├── target HTTP request budget
 ├── evidence identity
 └── TransportEngine
        │
        ▼
Process Supervisor
 ├── hard module deadline
 ├── hard global deadline
 ├── Ctrl+C / abort termination
 └── bounded concurrency
        │
   ┌────┴───────────────────────────┐
   ▼                                ▼
run_with_context(context)     legacy run(url, ...)
   │                                │
   └──────────────┬─────────────────┘
                  ▼
       scoped target HTTP bridge
                  │
                  ▼
            Module results
                  │
                  ▼
       Evidence + correlation
                  │
                  ▼
Observation → hypothesis → verified finding
                  │
                  ▼
           JSON schema 2.0
```

Each selected module executes in its own child process. The parent supervisor owns deadlines and can terminate a blocked child. Legacy modules remain compatible, but their `safe_request()` target HTTP calls are automatically bound to the scan context inside that process—including calls made from module worker threads.

## Enforcement boundaries

DEDSEC distinguishes **target HTTP traffic** from other network operations.

For target HTTP requests made through the DEDSEC HTTP helper/runtime, 1.3 enforces:

- target host/subdomain scope policy;
- optional root-only policy;
- TLS verification;
- bounded redirect following with scope checks on each hop;
- shared target HTTP request budget;
- bounded retries/backoff;
- request timeout;
- cache isolation for header/body-varying requests.

The `--max-requests` value is specifically a **target HTTP request budget**. DNS queries, WHOIS lookups, raw TCP port connections, TLS protocol probes, and approved external-intelligence lookups are not represented as target HTTP requests and are not counted in that number. They remain bounded by their own operation timeouts and, critically, by the process-level module/global deadlines.

Built-in external HTTP intelligence sources are narrowly allowlisted for the modules that use them. Unknown out-of-scope HTTP destinations fail closed while a scan context is active.

## Modules

| Key | Module | Purpose |
| --- | --- | --- |
| `waf` | WAF Detection | Bounded vendor-signature and response-behavior fingerprinting |
| `tech` | Technology Fingerprinting | Server, framework, CMS, CDN, and stack signals |
| `dns` | DNS Reconnaissance | DNS records, authentication posture, DNSSEC, and explicitly labeled AXFR check |
| `geo` | IP & GeoLocation | IP, ASN, network, and geographic context |
| `ssl` | SSL/TLS Analysis | Verified certificate and protocol analysis |
| `headers` | HTTP Header Audit | Weighted header-coverage and disclosure posture |
| `redirect` | Open Redirect Check | Controlled redirect analysis with negative controls and no external-follow behavior |
| `robots` | Robots & Sitemap | robots.txt and sitemap discovery |
| `cookies` | Cookie Audit | Cookie security attributes and scope |
| `ports` | Port Exposure Scan | Bounded TCP service discovery; open ports are observations, not vulnerabilities by number alone |
| `whois` | WHOIS Lookup | Registration metadata |
| `subdomains` | Subdomain Enumeration | Multi-source discovery, provenance, unresolved-candidate preservation, and validation |
| `js` | JS & Endpoint Extraction | In-scope JS assets, typed routes, API candidates, and conservative secret-shape detection |
| `hosting` | Hosting Intelligence | Hosting and network-provider context |
| `exposures` | Common Exposure Checks | Signature-validated sensitive exposures plus rejected/unverified outcomes |
| `cors` | CORS Check | Cross-origin configuration candidates without impact overclaiming |
| `csp` | CSP Analyzer | CSP hardening observations and directive analysis |
| `ratelimit` | Rate-Limit Observation | Small bounded throttling sample; absence of 429 is not declared a vulnerability |
| `clickjacking` | Framing Posture | Framing restrictions and potential frameability observations |
| `email` | Email Security | DNS-only SPF, DMARC, DKIM-selector discovery, and MX posture by default |
| `vhost` | Virtual Host Finder | In-scope Host-header response-difference candidates |
| `api_schema` | API & OpenAPI Scanner | Public schema discovery and deduplicated endpoint extraction |
| `http_methods` | HTTP Methods Audit | Method declarations and bounded TRACE validation without PUT/DELETE writes |
| `security_policy` | Security Policy Audit | security.txt and disclosure-policy discovery |

## Installation

```bash
git clone https://github.com/muhammadsohaimmuqtada/dedsec.git
cd dedsec
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

For development:

```bash
python -m pip install -e '.[dev]'
```

## Usage

Run the complete module set:

```bash
dedsec https://example.com
```

Run selected modules:

```bash
dedsec https://example.com --modules tech,dns,ssl,headers
```

Use explicit execution boundaries:

```bash
dedsec https://example.com \
  --concurrency 4 \
  --timeout 10 \
  --module-timeout 120 \
  --global-timeout 600 \
  --module-retries 0 \
  --max-requests 1000
```

Restrict target HTTP to the root host:

```bash
dedsec https://example.com --root-only
```

Persist redacted evidence and the report:

```bash
dedsec https://example.com \
  --evidence-dir ./dedsec-evidence \
  --output report.json
```

Print the machine-readable report:

```bash
dedsec https://example.com --json
```

Run through Python:

```bash
python -m dedsec https://example.com
```

### Curated profile

```bash
dedsec https://example.com --market
```

`--market` is a **mixed-impact authorized-testing profile**, not a passive-only mode. Review the target's written scope and testing rules before using it.

## Timeout semantics

DEDSEC 1.3 separates three concepts:

- `--timeout`: per-request / per-operation timeout passed into modules;
- `--module-timeout`: hard wall-clock deadline for each module process, default `120s`;
- `--global-timeout`: hard wall-clock deadline for the complete scan, default `600s`.

If a module blocks inside a library or socket call beyond its module deadline, the parent process terminates it and records a terminal timeout result. A global timeout terminates active modules and marks work that never started as timed out. Ctrl+C uses the same termination path rather than waiting indefinitely for worker threads.

## Evidence and reporting

DEDSEC separates collection from security conclusions. A report may contain:

- **observations** — facts collected from the target or supporting intelligence;
- **candidates / hypotheses** — positive security signals that still require verification;
- **verified findings** — findings promoted only when module verification semantics and evidence references support the claim;
- **rejected or unverified outcomes** — negative controls, signature mismatches, transport failures, or deliberately unpromoted signals.

Evidence records contain scan identity, module provenance, timestamps, SHA-256 digests, redacted structured data, and optional atomic JSON artifacts. Terminal ANSI styling is removed before evidence persistence.

Report runtime metadata records target HTTP request use and explicitly distinguishes traffic classes that are not part of the target HTTP budget.

## Detector precision principles

DEDSEC deliberately avoids several common scanner shortcuts:

- an HTTP `403` or `404` is a real response, not a network failure;
- an exposed-looking path is not confirmed without the expected content/format signature;
- a WordPress/admin route is a surface observation, not automatically a vulnerability;
- no `429` in a small sample does not prove missing rate limiting;
- missing CSP or framing headers are hardening/frameability observations, not proof of XSS/clickjacking;
- reflected CORS headers are not a verified vulnerability without demonstrated cross-origin impact;
- a DKIM search across common selectors cannot prove DKIM is absent;
- an open port is an exposure observation; severity depends on the service and access context;
- WAF/CDN fingerprinting reports uncertainty when vendor-specific evidence is insufficient.

## Development and contribution

Install development dependencies and run:

```bash
ruff check .
python -m unittest discover -s tests -v
python -m compileall -q dedsec tests
```

CI runs the package/test/CLI matrix on Python 3.8, 3.11, 3.12, and 3.13.

Contributions must keep network behavior bounded, protect sensitive data, respect target scope, and distinguish heuristic candidates from verified findings. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before proposing scanner or architecture changes.

## Repository standards

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — engineering, testing, evidence, runtime, and pull-request standards
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — professional community and security-research conduct
- [`SECURITY.md`](SECURITY.md) — supported versions and coordinated vulnerability disclosure
- [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) — code-change quality review
- [`.github/ISSUE_TEMPLATE/bug_report.md`](.github/ISSUE_TEMPLATE/bug_report.md) — structured bug reporting

## Security

Security issues **in DEDSEC itself** should be handled according to [`SECURITY.md`](SECURITY.md), not through a public issue containing exploit details or sensitive evidence.

Findings discovered against third-party systems should be disclosed through the target owner's authorized vulnerability-disclosure or bug-bounty process.

## Legal and authorized use

DEDSEC is intended for systems you own or have explicit authorization to test. You are responsible for the written scope, testing rules, rate limits, and disclosure requirements of the system or bug-bounty program you assess.

## License

MIT — see [`LICENSE`](LICENSE).

## Author

Sohaim Muqtada
