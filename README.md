# DEDSEC — Evidence-Driven Reconnaissance & Application-Surface Research

[![Version](https://img.shields.io/badge/version-2.0.0-4c8bf5?style=flat-square)](https://github.com/muhammadsohaimmuqtada/dedsec)
[![Python](https://img.shields.io/badge/Python-3.8--3.13-blue?style=flat-square&logo=python)](https://www.python.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/muhammadsohaimmuqtada/dedsec/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/muhammadsohaimmuqtada/dedsec/actions)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

DEDSEC is a modular reconnaissance and application-surface research framework for **authorized security testing**. Version 2.0 keeps the original 24 reconnaissance/security-posture modules, but adds the stateful layers needed for deeper research: a canonical asset graph, endpoint/request corpus, insertion-point model, bounded crawler, explicit authentication contexts, OpenAPI import, project history/diff, passive analysis, declarative checks, coverage telemetry, and multi-format reporting.

DEDSEC is intentionally conservative. A successful request, a template match, a missing header, a reflected input, or an open port is not automatically a vulnerability. The framework separates observations, candidates/hypotheses, verified findings, transport failures, and incomplete coverage.

> **Authorization required.** Use DEDSEC only against systems you own or are explicitly authorized to test. The project does not provide an anti-WAF/IDS evasion mode, automatic account creation, destructive exploit automation, or automatic state-changing template execution.

## Project status

| Component | DEDSEC 2.0 |
| --- | --- |
| Package | `2.0.0` |
| Built-in modules | `24` |
| Report schema | `3.0` |
| Python | `3.8`–`3.13` |
| Runtime | Process-isolated modules with hard module/global deadlines |
| HTTP | Scoped, verified TLS, bounded redirects, exact request budget, total logical deadlines |
| Reachability | Bounded preflight + shared target-health circuit + multi-address IPv4/IPv6 telemetry |
| Application model | Asset graph + endpoint graph + request corpus + insertion points + identities |
| Discovery | Static bounded crawler; optional bounded Playwright SPA observation |
| Authentication | Explicit researcher-supplied header/basic/bearer/API-key/cookie/workflow profiles |
| API input | OpenAPI 3 / Swagger 2 request-corpus import |
| Persistent research | Redacted SQLite project history, checkpoints, resume, and cross-scan diff |
| Extensibility | Validated Python entry-point plugins + declarative checks |
| Output | JSON, JSONL, SARIF, CSV, HTML |
| Finding model | Observation → candidate/hypothesis → verified finding |

The package remains **Beta**. CI and regression tests establish tested behavior; they do not prove the absence of every defect or false positive.

## Architecture

```text
Target + Scan Policy
        │
        ├── host / port / path scope
        ├── impact ceiling
        ├── request budget / deadlines
        └── optional identity
        │
        ▼
Reachability + Discovery
        │
        ├── DNS / TLS / ports / WHOIS / OSINT
        ├── bounded HTTP crawler
        ├── optional browser observation
        ├── JavaScript candidates
        └── OpenAPI / Swagger input
        │
        ▼
ResearchWorkspace
        │
        ├── AssetGraph
        ├── EndpointGraph
        ├── RequestCorpus
        ├── InsertionPoints
        ├── IdentityContexts
        ├── Response metadata
        └── CoverageTracker
        │
        ├──────────────┐
        ▼              ▼
PassivePipeline   Bounded Audit / Templates
        │              │
        └──────┬───────┘
               ▼
      Evidence + Correlation
               │
        observation / candidate
               │
          verified finding
               │
               ▼
   Report schema 3.0 + Project DB
     history / diff / resume / export
```

The original modules remain useful producers of evidence. They are no longer the only source of knowledge: DEDSEC 2.0 correlates discovered hosts, IPs, services, certificates, URLs, endpoints, request shapes, identities, and scan coverage inside one research workspace.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

Development install:

```bash
pip install -e '.[dev]'
```

Optional browser discovery:

```bash
pip install -e '.[browser]'
playwright install chromium
```

Browser support is optional. Static crawling, API import, project history, templates, and the built-in modules do not require Playwright.

## Basic scan

The familiar scan path remains available:

```bash
dedsec https://example.com
```

Select modules:

```bash
dedsec https://example.com \
  --modules dns,ssl,headers,subdomains,js,ports
```

The 24 built-ins are:

```text
waf, tech, dns, geo, ssl, headers, redirect, robots,
cookies, ports, whois, subdomains, js, hosting, exposures,
cors, csp, ratelimit, clickjacking, email, vhost,
api_schema, http_methods, security_policy
```

## Deep application discovery

```bash
dedsec https://example.com \
  --deep \
  --crawl-depth 3 \
  --crawl-pages 200 \
  --project .dedsec/example.db \
  --output report.json
```

The static crawler:

- follows only URLs allowed by central scope policy;
- uses bounded depth/page/body limits;
- records HTML forms but **does not submit them**;
- records JavaScript request candidates;
- feeds observed responses into passive analyzers;
- records request shapes and insertion points;
- does not keep response bodies in persistent workspace snapshots.

## Input-surface coverage

`--audit-inputs` currently enables a deliberately narrow built-in active audit: a harmless deterministic marker is substituted into one **GET/HEAD query parameter at a time**, with a negative baseline control. Reflection is recorded as an `INFO` surface observation only.

```bash
dedsec https://example.com \
  --deep \
  --audit-inputs \
  --audit-max-requests 100 \
  --audit-max-points 250
```

This audit does **not** automatically send script payloads, SQL syntax, command syntax, path traversal payloads, or state-changing methods.

## Authentication contexts

Authentication is explicit. DEDSEC never attempts to register an account on its own.

```bash
dedsec https://example.com \
  --auth examples/auth-profile.example.yml \
  --deep
```

Supported profile kinds:

- `headers`
- `basic`
- `bearer`
- `api_key` (header)
- `cookie`
- bounded `workflow` using explicit `GET`, `HEAD`, or `POST` steps

Credentials are runtime material. Persistent workspace/report/project serialization redacts sensitive headers, cookies, body keys, and sensitive insertion-point values. Authentication material is bound to the exact configured target origin; DEDSEC strips `Authorization`, `Proxy-Authorization`, and `Cookie` when its manual HTTP redirect crosses to a different scheme/host/effective-port, even if the destination host is otherwise in scope.

A configured credential is **not** reported as a verified authenticated identity unless the profile contains an explicit verification rule and that rule succeeds.

See [`docs/AUTHENTICATION.md`](docs/AUTHENTICATION.md).

## OpenAPI / Swagger request corpus

```bash
dedsec https://example.com \
  --api-spec ./openapi.yaml \
  --project .dedsec/example.db
```

OpenAPI/Swagger import records:

- method + path/template;
- path/query/header parameters;
- JSON/body shapes and insertion points;
- operation IDs and summaries;
- declared authentication schemes;
- state-changing methods.

Importing a schema does **not** execute its `POST`, `PUT`, `PATCH`, or `DELETE` operations. They are tagged as recorded/not-executed surfaces.

## Reproducible scan plans

```bash
dedsec --plan examples/scan-plan.example.yml
```

Plans can define target, modules, host/port/path scope, discovery limits, traffic budgets, maximum impact, project storage, templates, authentication profile, API schemas, and exports.

Impact classes are ordered:

```text
passive < normal < active-safe < state-changing < high-impact
```

A module/check whose declared impact exceeds the configured ceiling is blocked before execution.

See [`docs/SCAN_PLANS.md`](docs/SCAN_PLANS.md).

## Project history, resume, and diff

```bash
dedsec https://example.com \
  --deep \
  --project .dedsec/example.db
```

Resume from the latest crawler checkpoint:

```bash
dedsec https://example.com \
  --deep \
  --project .dedsec/example.db \
  --resume
```

The SQLite project store keeps redacted snapshots of assets, edges, requests, observations, and reports. Cross-scan diffs report new, removed, and changed entities.

A removed observation in a later scan is **not by itself proof of remediation**: coverage or reachability may have changed. Use the coverage and runtime sections when interpreting project diffs.

## Declarative checks

```bash
dedsec https://example.com \
  --template-dir examples/templates
```

Declarative checks support:

- explicit impact class;
- request or passive mode;
- status/header/word/regex request matchers;
- negative matchers;
- header/regex request extractors;
- optional SHA-256 file-integrity verification;
- candidate/observation classification.

Important boundaries:

- templates cannot self-declare `verified-finding`;
- state-changing template methods are recorded but not auto-executed;
- passive templates send zero traffic;
- passive templates cannot use body matchers because DEDSEC intentionally does not retain response bodies in the workspace;
- SHA-256 proves content integrity against a declared digest, **not author authenticity**.

See [`docs/TEMPLATES.md`](docs/TEMPLATES.md).

## Optional browser discovery

```bash
dedsec https://example.com --deep --browser
```

The browser adapter observes SPA/browser requests and navigable links. It does not auto-submit forms or click mutation controls. Sensitive browser headers are restricted to the exact configured target origin; cookie profiles are installed for that target URL rather than copied as a global browser header.

## Scope

Root + subdomains is the default target-HTTP scope. `--root-only` limits target HTTP to the root host.

Scan plans additionally support:

- explicit allowed/denied hosts;
- allowed ports;
- path include globs/regexes;
- path exclude globs/regexes.

Path exclusions are applied before path inclusions. Redirects are manually followed only while the destination remains in scope.

## Reachability and adaptive resilience

DEDSEC separates target availability from findings.

The root service receives a bounded TCP preflight. Repeated target transport failures open a shared temporary health circuit, allowing HTTP-dependent modules to terminate as `INCONCLUSIVE` instead of spending their full deadlines reproving the same outage. DNS, WHOIS, raw TCP and other independent work can continue.

DEDSEC also records all DNS-resolved IPv4/IPv6 paths and classifies bounded connection state as reachable, refused, filtered/timeout, unreachable, or error. HTTP retries stay inside one logical request deadline and `Retry-After` is honored for relevant retryable responses.

This is resilience and load reduction—not firewall/WAF evasion.

## Coverage

Schema 3.0 reports include research coverage such as:

- requests discovered;
- responses observed;
- requests audited/skipped;
- insertion points discovered/audited/skipped;
- skipped-reason counts;
- assets/endpoints observed.

`0 findings` must be interpreted together with coverage. DEDSEC does not equate a clean partial scan with proof that an application is vulnerability-free.

## Exports

```bash
dedsec https://example.com \
  --deep \
  --export json,jsonl,sarif,csv,html \
  --export-dir ./reports
```

The canonical report schema is JSON `3.0`. Other formats are derived from that report.

## Runtime guarantees and boundaries

For target HTTP sent through the DEDSEC runtime:

- TLS verification is enabled by default;
- no automatic insecure TLS fallback;
- root/subdomain/port/path scope enforcement;
- cross-scope redirects are not followed;
- target HTTP requests share one budget;
- retries consume budget per on-wire attempt;
- retries/backoff do not multiply `--timeout`;
- module processes have killable hard deadlines;
- global scan deadline terminates active children;
- Ctrl+C terminates active module processes.

`--max-requests` counts **target HTTP** requests. It does not claim to meter DNS, WHOIS, raw TCP sockets, TLS handshakes, or external-intelligence traffic.

## Finding semantics

DEDSEC distinguishes:

```text
observation
    ↓
candidate / hypothesis
    ↓
verified finding
```

Examples:

- open TCP port → service observation;
- missing security header → posture/hardening observation;
- arbitrary CORS reflection → candidate until readable sensitive impact is demonstrated;
- frameability → observation, not automatic clickjacking vulnerability;
- declarative template match → observation/candidate, never self-verified;
- content-signature-backed sensitive exposure + evidence → eligible for verified correlation.

## Development gates

```bash
ruff check .
python -m unittest discover -s tests -v
python -m compileall -q dedsec tests
```

CI runs lint/compile plus package/unit/CLI smoke tests across Python 3.8, 3.11, 3.12 and 3.13.

## Documentation

- [`docs/DEDSEC_2_ARCHITECTURE.md`](docs/DEDSEC_2_ARCHITECTURE.md)
- [`docs/SCAN_PLANS.md`](docs/SCAN_PLANS.md)
- [`docs/AUTHENTICATION.md`](docs/AUTHENTICATION.md)
- [`docs/TEMPLATES.md`](docs/TEMPLATES.md)
- [`SECURITY.md`](SECURITY.md)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)

## License

MIT. See [`LICENSE`](LICENSE).
