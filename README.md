# DEDSEC — Evidence-Driven Reconnaissance & Application-Surface Research

[![Version](https://img.shields.io/badge/version-2.0.1-4c8bf5?style=flat-square)](https://github.com/muhammadsohaimmuqtada/dedsec)
[![Python](https://img.shields.io/badge/Python-3.8--3.13-blue?style=flat-square&logo=python)](https://www.python.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/muhammadsohaimmuqtada/dedsec/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/muhammadsohaimmuqtada/dedsec/actions)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

DEDSEC is a modular reconnaissance and application-surface research framework for **authorized security testing**. Version 2 keeps the hardened 24-module recon runtime from the 1.3 line and adds a cross-cutting application knowledge layer: asset/request modeling, bounded crawling, authentication contexts, API-spec ingestion, passive analysis, controlled insertion-point auditing, scan plans, project history/diff/resume, declarative checks, optional browser discovery, multi-address network telemetry, coverage accounting, and structured exports.

DEDSEC is intentionally conservative: transport failure is not a vulnerability, a template match is not automatically a verified finding, forms and state-changing API operations are recorded rather than submitted by discovery, and scope/impact policy is enforced centrally.

> **Project status:** Beta. CI and benchmark-driven regression testing reduce known defects; they do not justify a claim that the scanner is bug-free or that zero findings prove an application is secure.

## Current platform

| Component | Current state |
| --- | --- |
| Package version | `2.0.1` |
| Built-in modules | `24` |
| Report schema | `3.0` |
| Supported Python | `3.8`–`3.13` |
| Module execution | Process-isolated concurrent workers with hard module/global deadlines |
| HTTP runtime | Scope-enforced, verified TLS, bounded redirects/retries, shared target-HTTP budget |
| Reachability | Root preflight + target-health circuit + multi-address IPv4/IPv6 telemetry |
| Knowledge model | Asset graph + request corpus + insertion points + identities + observations |
| Application discovery | Bounded static crawler; optional bounded Playwright SPA discovery |
| API ingestion | OpenAPI 3 / Swagger 2 request modeling; local `$ref` resolution; no remote-ref fetching |
| Authentication | Explicit researcher-supplied header/basic/bearer/API-key/cookie/workflow profiles |
| Audit | Controlled query-reflection coverage probes; observation only |
| Persistence | Redacted SQLite project history, checkpoints, resume, and cross-scan diff |
| Extensibility | Impact-controlled declarative templates + explicitly enabled Python plugins |
| Exports | JSON, JSONL, SARIF, CSV, HTML |
| Finding model | Observation → candidate/hypothesis → evidence-backed verified finding |

## Architecture

```text
                              DEDSEC 2
                                 │
                     Scan Plan / CLI Policy
                  scope · impact · budgets · auth
                                 │
          ┌──────────────────────┴──────────────────────┐
          │                                             │
   Recon Module Runtime                         Research Pipeline
  24 bounded built-ins                               │
          │                              ┌────────────┼─────────────┐
          │                              │            │             │
          │                           Crawler      API import    Browser*
          │                              │            │             │
          └──────────────┬───────────────┴────────────┴─────────────┘
                         ▼
                 ResearchWorkspace
        ┌────────────────┼─────────────────┐
        │                │                 │
     AssetGraph      RequestCorpus      Identities
        │                │                 │
        └──────────┬─────┴──────┬──────────┘
                   │            │
             Passive analysis   Controlled audit
                   │            │
                   └──────┬─────┘
                          ▼
                    Observations
                          │
                correlation/evidence
                          │
                          ▼
                    Report schema 3.0
                          │
            SQLite history / diff / resume
                          │
             JSON · JSONL · SARIF · CSV · HTML

* optional Playwright dependency
```

### Core invariants

- Scope is checked centrally for target HTTP and research-pipeline requests.
- Path scope is decoded and dot-segment normalized before include/exclude matching.
- `--timeout` is one logical HTTP deadline including retries/backoff, not a per-attempt multiplier.
- Hard module and global process deadlines remain independent last-resort boundaries.
- `--max-requests` counts target HTTP attempts; DNS/WHOIS/raw TCP are separate bounded operations.
- TLS verification is enabled; there is no automatic insecure fallback.
- Automatic redirects are not followed outside configured scope.
- HTTP 4xx/5xx responses remain valid transport responses.
- Authentication secrets are used in memory when configured but redacted at evidence/report/project persistence boundaries.
- External Python plugins are **not imported by default**.
- Browser discovery aborts out-of-scope requests before send and blocks non-idempotent browser requests by default.
- API imports model state-changing methods but do not execute them.
- Declarative templates cannot self-label a match as a verified finding.
- A partial, inconclusive, failed, timed-out, or aborted module is not evidence that a vulnerability is absent.

## Installation

```bash
git clone https://github.com/muhammadsohaimmuqtada/dedsec.git
cd dedsec
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Development/test dependencies:

```bash
python -m pip install -e '.[dev]'
```

Optional browser discovery:

```bash
python -m pip install -e '.[browser]'
playwright install chromium
```

## Basic usage

Legacy usage remains valid:

```bash
dedsec https://example.com
```

Selected modules:

```bash
dedsec https://example.com --modules tech,dns,ssl,headers
```

Explicit runtime boundaries:

```bash
dedsec https://example.com \
  --concurrency 4 \
  --timeout 10 \
  --module-timeout 120 \
  --global-timeout 600 \
  --module-retries 0 \
  --max-requests 1000
```

Persist evidence/report:

```bash
dedsec https://example.com \
  --evidence-dir ./dedsec-evidence \
  --output report.json
```

## Deep application discovery

Deep discovery is opt-in:

```bash
dedsec https://example.com \
  --deep \
  --crawl-depth 3 \
  --crawl-pages 200
```

The static crawler records links, responses, forms, JavaScript request candidates and input surfaces. Forms are **not submitted**. Non-GET form methods are recorded and tagged as potentially state-changing surfaces.

Optional SPA/browser discovery:

```bash
dedsec https://example.com --deep --browser
```

Browser mode does not click controls or submit forms. Out-of-scope browser traffic is aborted before send. Non-idempotent browser requests generated by page scripts are recorded but blocked by default.

## Authentication contexts

Use an explicit local authentication profile:

```bash
dedsec https://example.com --deep --auth ./auth.yml
```

Example bearer profile:

```yaml
label: researcher
kind: bearer
token: replace-me-at-runtime
verification:
  url: /api/me
  expect_status: 200
  body_regex: researcher
```

Example bounded login workflow:

```yaml
label: researcher
kind: workflow
workflow:
  - method: POST
    url: /login
    form:
      username: test-user
      password: test-password
    expect_status: [200, 302]
verification:
  url: /account
  expect_status: 200
```

Authentication profiles are validated before workflow traffic begins. Workflow targets remain subject to scan scope. Profile secrets, Authorization values, cookies, semantic password/token insertion points and captured values are redacted before persistence.

## OpenAPI / Swagger request corpus

Import one or more local API specifications:

```bash
dedsec https://example.com \
  --api-spec ./openapi.yml \
  --api-spec ./legacy-swagger.json
```

DEDSEC converts operations into non-executed request records containing methods, path/query/header/form/body inputs, content types, auth metadata and state-changing tags. Local JSON-Pointer `$ref` values are resolved with bounded recursion. Remote/file `$ref` values are **not fetched automatically** and remain explicit unresolved coverage metadata.

If an authenticated identity is configured, its prepared headers/session context are attached to in-memory imported requests; persistence redaction still removes credentials.

## Controlled input audit

```bash
dedsec https://example.com --deep --audit-inputs
```

The built-in audit currently performs only a bounded differential query-reflection probe with a harmless deterministic marker. It skips non-idempotent methods, out-of-scope URLs, mutation-like paths such as logout/reset/delete flows, sensitive token/password-like query inputs and unsupported body/header locations. Reflection is an **INFO surface observation**, not an XSS claim.

## Impact policy

```bash
dedsec https://example.com --max-impact normal
```

Supported classes:

```text
passive < normal < active-safe < state-changing < high-impact
```

The effective ceiling governs built-in modules, deep/browser/auth discovery, controlled auditing and declarative templates. DEDSEC does not include a stealth/evasion mode and does not automatically execute destructive/state-changing declarative checks.

## Reproducible scan plans

```bash
dedsec --plan ./dedsec-plan.yml
```

Example:

```yaml
target: https://example.com
modules: [dns, ssl, headers, tech]

scope:
  include_subdomains: true
  allowed_ports: [80, 443]
  include_paths: ['/*']
  exclude_paths:
    - '/logout*'
    - '/delete*'

discovery:
  enabled: true
  crawl_depth: 3
  crawl_pages: 150
  api_specs: [specs/openapi.yml]

traffic:
  timeout: 10
  concurrency: 4
  module_timeout: 120
  global_timeout: 600
  max_requests: 1000
  maximum_impact: active-safe

project:
  database: state/project.db
  resume: false
  diff: true

templates:
  directories: [templates]
  maximum_impact: active-safe

exports:
  formats: [json, jsonl, sarif, csv, html]
  directory: reports
```

Unknown plan keys are rejected instead of silently ignored. Relative artifact paths resolve relative to the plan file.

## Project history, checkpoint, resume and diff

```bash
dedsec https://example.com --project ./project.db --deep
```

Resume from the most recent crash/research checkpoint:

```bash
dedsec https://example.com --project ./project.db --resume --deep
```

Checkpoints are used for resume. Longitudinal diffs compare against the latest **completed** scan, not an arbitrary crash checkpoint. Persistent snapshots are redacted and the project DB is created with owner-only permissions on POSIX systems where supported.

## Declarative templates

Load a researcher-controlled directory:

```bash
dedsec https://example.com --template-dir ./templates
```

Templates declare impact, request/passive mode, matchers, negative matchers and optional extractors. Loader validation rejects malformed regular expressions, invalid status codes, unsupported impact/severity/classification values and duplicate IDs. Optional SHA-256 integrity metadata can verify a template definition. A template match can produce an observation/candidate/hypothesis only; it cannot declare itself a verified finding.

State-changing template methods are modeled but automatic execution is disabled.

## External Python plugins

Third-party Python entry points execute code when imported, so DEDSEC does not discover them during an ordinary scan. Explicitly opt in for an environment you control:

```bash
DEDSEC_ENABLE_PLUGINS=1 dedsec https://example.com
```

Plugin metadata includes protocol/impact/capability information and plugin loading errors are retained as diagnostics. Built-in modules do not require this opt-in.

## Multi-address network telemetry

The research pipeline resolves the supplied target hostname across available IPv4/IPv6 addresses and preserves per-address reachability state:

```text
reachable
refused
filtered_or_timeout
unreachable
error
```

This is operational telemetry, not a bypass mechanism. DEDSEC does not silently switch to third-party proxy infrastructure or attempt to evade filtering.

## Reporting and coverage

Schema 3.0 can include:

- module terminal states;
- verified findings and hypotheses;
- asset graph nodes/edges;
- request corpus and insertion points;
- identity metadata without persisted secrets;
- passive/audit observations;
- request and insertion-point coverage;
- target health/network paths;
- project diff metadata.

Additional exports:

```bash
dedsec https://example.com \
  --export json,jsonl,sarif,csv,html \
  --export-dir ./reports
```

CSV output neutralizes spreadsheet-formula cells. HTML output escapes untrusted text. Export basenames are constrained to the selected directory.

Coverage matters: `0 findings` is not equivalent to `fully tested`. DEDSEC records discovered/audited/skipped request and insertion-point counts so incomplete coverage remains visible.

## Module outcome model

- **SUCCESS** — intended evidence collection completed without a material limitation.
- **PARTIAL** — useful evidence exists, but part of intended collection was unavailable.
- **INCONCLUSIVE** — insufficient evidence for a positive or negative conclusion.
- **FAILED** — non-timeout execution failure.
- **TIMEOUT** — hard module/global deadline terminated the work.
- **ABORTED** — intentional cancellation.

## Built-in modules

| Key | Purpose |
| --- | --- |
| `waf` | Bounded WAF/vendor and filtering-behavior fingerprinting |
| `tech` | Technology/server/framework/CMS/CDN signals |
| `dns` | DNS records, security posture and bounded DNS checks |
| `geo` | IP/ASN/network/geographic context |
| `ssl` | Verified certificate/protocol analysis |
| `headers` | Weighted HTTP security-header posture |
| `redirect` | Controlled redirect analysis with negative controls |
| `robots` | robots.txt and sitemap discovery |
| `cookies` | Cookie security attributes/scope |
| `ports` | Bounded TCP service discovery with explicit network-state semantics |
| `whois` | Registration metadata |
| `subdomains` | Multi-source discovery with provenance/unresolved preservation |
| `js` | JavaScript assets, API/navigation candidates and conservative secret-shape detection |
| `hosting` | Hosting/network-provider context |
| `exposures` | Signature-validated common sensitive exposure checks |
| `cors` | CORS configuration candidates without impact overclaiming |
| `csp` | CSP hardening/directive observations |
| `ratelimit` | Small bounded throttling observation |
| `clickjacking` | Framing posture/potential frameability |
| `email` | DNS-only SPF/DMARC/DKIM-selector/MX posture |
| `vhost` | Bounded Host-header response-difference candidates |
| `api_schema` | Public API/OpenAPI surface discovery |
| `http_methods` | Method declarations and bounded TRACE echo validation |
| `security_policy` | security.txt/disclosure-policy discovery |

## Reliability validation

Before release/merge, DEDSEC changes are expected to pass:

```bash
ruff check .
python -m unittest discover -s tests -v
python -m compileall -q dedsec tests
dedsec --version
dedsec --help
```

CI runs the package/test/CLI matrix on Python 3.8, 3.11, 3.12 and 3.13.

## Responsible use

Use DEDSEC only where you own the systems or have explicit authorization to test. Respect the program's scope, excluded endpoints, request-rate limits, authentication/account rules and disclosure terms. DEDSEC's policy controls reduce accidental overreach but do not replace the researcher's authorization obligations.

See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md) for project policies.
