# DEDSEC — Evidence-Driven Web Reconnaissance Framework

[![Version](https://img.shields.io/badge/version-1.2.0-4c8bf5?style=flat-square)](https://github.com/muhammadsohaimmuqtada/dedsec)
[![Python](https://img.shields.io/badge/Python-3.8--3.12-blue?style=flat-square&logo=python)](https://www.python.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/muhammadsohaimmuqtada/dedsec/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/muhammadsohaimmuqtada/dedsec/actions)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

DEDSEC is a modular reconnaissance framework for **authorized web security testing**. It combines attack-surface discovery, service profiling, web-configuration analysis, endpoint extraction, evidence capture, and structured reporting in a single CLI.

The 1.2 release line establishes the v2 runtime foundation: bounded execution, explicit scope policy, shared request budgeting, evidence-aware findings, and a migration path from independent scanner modules toward a coordinated reconnaissance engine.

## Project status

| Component | Current state |
| --- | --- |
| Package version | `1.2.0` |
| Built-in modules | `24` |
| Report schema | `2.0` |
| Supported Python | `3.8`–`3.12` |
| Execution | Bounded concurrent orchestration |
| Evidence | Scan IDs, SHA-256 evidence references, redaction, optional artifacts |
| Finding model | Observation → candidate/hypothesis → verified finding |
| Runtime migration | Foundation merged; bundled modules migrating incrementally |
| CI | Ruff + unittest matrix + package/CLI checks |

## Highlights

- 24 built-in reconnaissance and security-posture modules
- bounded concurrent module execution
- per-module and global timeout controls
- centralized v2 scope and request-budget foundation
- HTTP connection pooling and retry controls
- evidence IDs, sensitive-value redaction, and optional evidence artifacts
- versioned JSON report schema
- observation → candidate → verified-finding correlation model
- Rich terminal summaries
- supported-Python CI matrix and repository quality gates

## Architecture

```text
Target
  │
  ▼
ScanContext
  ├── ScopePolicy
  ├── request budget
  ├── evidence identity
  └── shared transport
          │
          ▼
     Orchestrator
          │
     ┌────┼──────────────┐
     ▼    ▼              ▼
  legacy runtime-aware  future
  modules modules        schedulers
     │       │
     └───┬───┘
         ▼
   Module results
         │
         ▼
Evidence + correlation
         │
         ▼
Observation → candidate → verified finding
         │
         ▼
JSON report schema 2.0
```

Existing modules remain compatible with `run(url, domain, timeout)`. New and migrated modules can use `run_with_context(context)` to consume shared scope, request-budget, evidence, and transport state.

See [`docs/CORE_RUNTIME_PLAN.md`](docs/CORE_RUNTIME_PLAN.md), [`docs/MODULE_AUTHORING.md`](docs/MODULE_AUTHORING.md), and [`docs/v2-evidence-model.md`](docs/v2-evidence-model.md).

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

Run the complete module set:

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

DEDSEC separates collection from security conclusions. A scan may contain:

- **observations** — facts collected by modules;
- **candidates / hypotheses** — security-relevant signals that still require verification;
- **verified findings** — findings promoted only when verification semantics and evidence references exist;
- **rejected or unverified outcomes** — failed, inconclusive, or deliberately unpromoted results.

Evidence records include scan identity, module provenance, timestamps, SHA-256 digests, redacted structured data, and optional atomic JSON artifacts. Sensitive-looking values are redacted before report/evidence output.

## Runtime direction

DEDSEC 1.2 is a compatibility foundation rather than a cosmetic version bump. The core runtime now supports explicit scope decisions and shared request budgets while the existing 24 modules continue to run.

The planned migration sequence is:

1. migrate noisy/high-value detectors to shared transport and candidate semantics;
2. add request-level evidence;
3. normalize discovered assets and API endpoints;
4. introduce dependency-aware scheduling so discoveries can be reused across modules;
5. add persistent scan workspaces and attack-surface diffing.

## Development and contribution

Install development dependencies and run:

```bash
ruff check .
python -m unittest discover -s tests -v
python -m compileall -q dedsec tests
```

Contributions must keep network behavior bounded, protect sensitive data, respect runtime scope, and distinguish heuristic candidates from verified findings. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before proposing scanner or architecture changes.

## Repository standards

DEDSEC maintains explicit project policies for technical and security collaboration:

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — engineering, testing, evidence, runtime, and pull-request standards
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — professional community and security-research conduct
- [`SECURITY.md`](SECURITY.md) — supported versions and coordinated vulnerability disclosure
- [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) — required quality review for code changes
- [`.github/ISSUE_TEMPLATE/bug_report.md`](.github/ISSUE_TEMPLATE/bug_report.md) — structured bug reporting

## Security

Security issues **in DEDSEC itself** should be handled according to [`SECURITY.md`](SECURITY.md), not through a public issue containing exploit details or sensitive evidence.

Findings discovered against third-party systems should be disclosed through the target owner's authorized vulnerability-disclosure or bug-bounty process.

## Legal and authorized use

DEDSEC is intended for systems you own or have explicit authorization to test. You are responsible for complying with the written scope, testing rules, request limits, and disclosure requirements of any organization or bug-bounty program you assess.

## License

MIT — see [`LICENSE`](LICENSE).

## Author

Sohaim Muqtada
