# DEDSEC — Web Reconnaissance Framework

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/muhammadsohaimmuqtada/dedsec/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/muhammadsohaimmuqtada/dedsec/actions)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

DEDSEC is a modular reconnaissance framework for authorized web security testing. It combines discovery, service profiling, web-configuration analysis, endpoint extraction, evidence capture, and structured reporting in a single CLI.

The v2 architecture is moving DEDSEC toward an evidence-driven runtime: scanner output is preserved as evidence, heuristic signals remain candidates until they satisfy verification rules, and machine-readable reports distinguish observations from verified findings.

## Highlights

- 24 built-in reconnaissance and security-posture modules
- bounded concurrent module execution
- HTTP connection pooling and retry controls
- per-module and global timeout controls
- evidence IDs, sensitive-value redaction, and optional evidence artifacts
- versioned JSON report schema
- observation → candidate → verified-finding correlation model
- runtime scope and request-budget foundation for migrated modules
- Rich terminal summaries
- CI with Ruff and unit tests

## Modules

| Key | Module | Purpose |
| --- | --- | --- |
| `waf` | WAF Detection | Signature and response-behavior fingerprinting |
| `tech` | Technology Fingerprinting | Server, framework, CMS, CDN, and application-stack signals |
| `dns` | DNS Reconnaissance | DNS records and related security posture |
| `geo` | IP & GeoLocation | IP, ASN, network, and geographic context |
| `ssl` | SSL/TLS Analysis | Certificate and protocol analysis |
| `headers` | HTTP Header Audit | Security headers and information-disclosure posture |
| `redirect` | Open Redirect Check | Redirect-parameter and redirect-chain analysis |
| `robots` | Robots & Sitemap | robots.txt and sitemap discovery |
| `cookies` | Cookie Audit | Cookie security attributes and scope |
| `ports` | Port Scan | Bounded TCP service discovery and lightweight fingerprints |
| `whois` | WHOIS Lookup | Registration metadata |
| `subdomains` | Subdomain Enumeration | Multi-source subdomain discovery and validation |
| `js` | JS & Endpoint Extraction | JavaScript assets, routes, endpoint and secret candidates |
| `hosting` | Hosting Intelligence | Hosting and network-provider context |
| `exposures` | Common Exposure Checks | Sensitive-file and service-exposure candidates with content validation |
| `cors` | CORS Check | Cross-origin configuration behavior |
| `csp` | CSP Analyzer | Content-Security-Policy analysis |
| `ratelimit` | Rate-Limit Check | Rate-limit behavior observations |
| `clickjacking` | Framing Protection | X-Frame-Options and CSP frame-ancestors posture |
| `email` | Email Security | SPF, DMARC, DKIM, MX, and related email posture |
| `vhost` | Virtual Host Finder | Virtual-host discovery signals |
| `api_schema` | API & OpenAPI Scanner | Public schema discovery and endpoint extraction |
| `http_methods` | HTTP Methods Audit | HTTP method exposure analysis |
| `security_policy` | Security Policy Audit | security.txt and disclosure-policy discovery |

## Installation

```bash
git clone https://github.com/muhammadsohaimmuqtada/dedsec.git
cd dedsec
python -m pip install -e .
```

For development:

```bash
python -m pip install -e '.[dev]'
```

## Usage

Run the full module set:

```bash
dedsec https://example.com
```

Run selected modules:

```bash
dedsec https://example.com --modules waf,ssl,headers,dns
```

Run the curated profile:

```bash
dedsec https://example.com --market
```

Tune bounded execution:

```bash
dedsec https://example.com \
  --concurrency 6 \
  --timeout 12 \
  --module-timeout 20 \
  --global-timeout 90 \
  --retries 3 \
  --module-retries 1 \
  --backoff 0.5
```

Use the v2 runtime guardrails for runtime-aware modules:

```bash
dedsec https://example.com --max-requests 750 --root-only
```

Persist redacted evidence artifacts and save the report:

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

## Evidence and reporting

DEDSEC's report schema separates module execution from security conclusions. A scan can contain:

- **observations** — facts collected by modules
- **hypotheses / candidates** — security-relevant signals that still require verification
- **verified findings** — findings promoted only when the detector provides verification semantics and evidence references
- **rejected or unverified outcomes** — failed modules and signals that were not promoted

Evidence records include a scan ID, module provenance, timestamp, SHA-256 digest, redacted structured data, and an optional atomic JSON artifact. Sensitive-looking values are redacted before report/evidence output.

See [the v2 evidence model](docs/v2-evidence-model.md) and [the core runtime plan](docs/CORE_RUNTIME_PLAN.md).

## Runtime direction

The current CLI remains compatible with the existing `run(url, domain, timeout)` module contract. Runtime-aware modules can opt into a shared scan context containing target scope, request budget, evidence state, and centralized transport. This lets DEDSEC migrate its built-in modules incrementally without a risky all-at-once rewrite.

The next runtime stages are request-level evidence, normalized asset/endpoint stores, and dependency-aware scheduling so discoveries can be reused across modules instead of rediscovered independently.

## Development

Run lint and tests before opening a pull request:

```bash
ruff check .
python -m unittest discover -s tests -v
```

Project contributions should keep network behavior bounded, avoid sensitive data in fixtures and output, and distinguish heuristic candidates from verified findings. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Security issues in DEDSEC itself should be reported according to [SECURITY.md](SECURITY.md). Findings discovered against third-party systems should be disclosed through the target owner's authorized process.

## Legal

DEDSEC is intended for systems you own or have explicit authorization to test. You are responsible for complying with the scope and rules of any security-testing or bug-bounty program you participate in.

## License

MIT — see [LICENSE](LICENSE).

## Author

Sohaim Muqtada
