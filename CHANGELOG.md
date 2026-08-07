# Changelog

All notable DEDSEC changes are documented here. The project is pre-1.0-semver-strict in maturity despite the 2.0 architecture label; compatibility is maintained where practical and breaking report-schema changes are explicitly versioned.

## 2.0.1 — Release-gate and trust-boundary hardening

### Release reliability

- Fixed the post-2.0 merge CI blockers across the supported Python matrix.
- Restored deterministic browser endpoint/cookie helpers required by the optional browser layer.
- Preserved canonical URL-encoded redaction markers through repeated persistence redaction passes.
- Made scope rejection diagnostics explicit for excluded hosts and disallowed ports.
- Kept Ruff, compile, package installation, dependency checks, and CLI smoke tests as release gates.

### Browser and scope safety

- Browser requests are intercepted before send and fail closed outside configured scope.
- Non-idempotent browser requests are recorded as discovered surfaces but are not executed by default.
- Researcher-supplied browser authentication headers are bound to the exact target origin; cookies are installed as target-scoped browser cookies.
- Browser request-corpus records retain identity references without persisting credential-bearing headers or bodies.
- Scope path matching now performs conservative repeated URL decoding, slash normalization, and dot-segment normalization before include/exclude evaluation.
- Scope scheme and port configuration is validated before execution.

### Reproducibility and extensibility

- Scan plans now reject unknown keys, validate impact relationships, and resolve file/directory paths relative to the plan file.
- The shipped scan-plan example follows the same plan-relative path contract.
- Installed third-party Python entry-point plugins are no longer enumerated/imported during ordinary scans; discovery requires explicit opt-in.

### Reporting/export hardening

- CSV export neutralizes spreadsheet-formula cells.
- Export basenames cannot traverse outside the selected output directory.
- Semantic insertion-point secret redaction is applied at shared persistence/report boundaries.

## 2.0.0 — Research-platform architecture

### Application knowledge

- Added canonical `ResearchWorkspace` with asset graph, endpoint graph, request corpus, insertion points, identity contexts, response metadata, observations, and coverage accounting.
- Added method-aware endpoint identity and request-shape identity to avoid query-value/secret-driven duplication.
- Added module-result ingestion for DNS, subdomains, ports/services, technologies, hosting context, and TLS certificates.

### Discovery

- Added bounded same-scope static crawler.
- HTML forms are modeled but never automatically submitted by the crawler.
- Added JavaScript request-candidate discovery.
- Added optional bounded Playwright browser observation.
- Added multi-address IPv4/IPv6 reachability telemetry.

### Authentication

- Added explicit local authentication profiles: headers, Basic, Bearer, header API key, cookie, and bounded configured login workflows.
- Added authentication verification semantics; supplying credentials alone does not mark an identity verified.
- Authentication context propagates into module child processes.
- Sensitive credentials are exact-origin scoped and stripped on endpoint-changing redirects.

### API and input surface

- Added OpenAPI 3 / Swagger 2 import into a non-executed request corpus.
- State-changing API methods are recorded but not automatically executed.
- Added bounded controlled query-reflection audit with a negative baseline control; reflection is an informational surface observation only.

### Policy and reproducibility

- Added YAML/JSON scan plans.
- Added host/port/path scope rules.
- Added impact classes: passive, normal, active-safe, state-changing, high-impact.
- Added validated module metadata/registry and plugin diagnostics.

### Persistence and coverage

- Added redacted SQLite project history, checkpoints, resume, and cross-scan workspace diff.
- Added request/insertion-point coverage counters and skipped-reason accounting.
- Persistent serialization redacts sensitive headers, cookies, bodies, and insertion-point values.

### Declarative checks

- Added request/passive templates with matchers, negative controls, extractors, impact policy, and optional SHA-256 integrity checking.
- Templates cannot self-declare verified findings.
- Passive templates send zero additional traffic.
- State-changing template requests are not automatically executed.

### Reporting

- Report schema upgraded to `3.0`.
- Added workspace, coverage, research metadata, and project diff to canonical reports.
- Added JSONL, SARIF, CSV, and HTML derived exports.

### Reliability retained from 1.3.x

- Process-isolated killable modules.
- Hard module/global deadlines.
- Shared target HTTP request budget.
- Total logical HTTP deadlines including retries/backoff.
- TLS verification with no automatic insecure fallback.
- Redirect scope enforcement.
- Target-health circuit and inconclusive semantics for unreachable HTTP surfaces.
- Accurate TCP open/closed/filtered/unreachable/error classification.

## 1.3.1

- Added target-reachability preflight and shared health circuit.
- Eliminated retry-timeout multiplication.
- Added PARTIAL/INCONCLUSIVE module states.
- Corrected TCP timeout/filtering state semantics.
- Report schema 2.1.

## 1.3.0

- Added process-level module supervision and hard deadlines.
- Centralized target HTTP scope/budget/TLS behavior.
- Hardened detector precision and evidence persistence.
- Report schema 2.0.
