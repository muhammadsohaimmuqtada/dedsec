# DEDSEC 2.0 Architecture

DEDSEC 2.0 turns the original module-oriented reconnaissance CLI into a stateful, evidence-driven application-surface research framework while preserving the 24 built-in modules and the existing `dedsec <url>` workflow.

## Design goals

1. **Truthful results.** Transport failure, incomplete coverage, a candidate signal, and a verified finding are different states.
2. **One canonical target model.** Modules, crawlers, API importers, passive analyzers, and future checks should contribute to the same asset/request knowledge model.
3. **Bounded execution.** Target HTTP uses central scope, TLS verification, deadlines, request budgets, redirect enforcement, and process-level module kill boundaries.
4. **Reproducibility.** Scan plans, project history, coverage accounting, and stable request/asset identities make research repeatable.
5. **Explicit authorization boundaries.** DEDSEC does not silently expand scope, auto-register accounts, auto-execute state-changing templates, or implement anti-WAF/IDS evasion.
6. **Secret minimization.** Credentials are runtime material. Persistent reports/workspaces/project snapshots redact sensitive fields and insertion-point values.

## High-level pipeline

```text
Target + ScanPlan
       │
       ├─ ScopePolicy
       ├─ impact ceiling
       ├─ request budget / deadlines
       └─ optional IdentityContext
       │
       ▼
Reachability / discovery
       │
       ├─ built-in recon modules
       ├─ bounded static crawler
       ├─ optional browser observer
       ├─ JavaScript candidates
       └─ OpenAPI / Swagger import
       │
       ▼
ResearchWorkspace
       ├─ AssetGraph
       ├─ EndpointGraph
       ├─ RequestCorpus
       ├─ InsertionPoints
       ├─ IdentityContexts
       ├─ Response metadata
       └─ CoverageTracker
       │
       ├───────────────┐
       ▼               ▼
PassivePipeline   Audit / Templates
       │               │
       └───────┬───────┘
               ▼
Evidence + FindingsCorrelator
               │
 observation → candidate/hypothesis → verified finding
               │
               ▼
Report schema 3.0 + ProjectStore
```

## Canonical data model

### Assets

`AssetNode` represents durable entities such as:

- domain
- host
- IP address
- service
- certificate
- URL
- endpoint
- technology
- identity

`AssetEdge` describes relationships, for example:

- `resolves_to`
- `has_subdomain`
- `serves`
- `exposes_service`
- `uses_technology`
- `presents_certificate`
- `certificate_for`
- `links_to`
- `contains_form`
- `exposes_api`

Asset IDs are deterministic hashes of normalized type/key pairs. The same observed asset can therefore receive multiple provenance sources without being duplicated.

### Endpoints

Endpoint identity is method-aware and ignores incidental query values:

```text
GET https://example.com/users
POST https://example.com/users
```

These are separate endpoints. `GET /users?id=1` and `GET /users?id=2` contribute to the same method/path endpoint while preserving their request/input surfaces separately.

OpenAPI paths can retain path templates such as `/users/{id}`.

### Request corpus

`RequestRecord` stores a request *shape*:

- method
- canonical URL
- non-secret headers needed for modeling
- content type
- identity reference
- source/provenance
- insertion points
- tags and metadata

Request identity is based on method + URL/input shape + content type + identity, not secret values. Changing a password/token therefore does not create misleading project-diff churn.

State-changing API/form requests can be recorded as `not-executed` surfaces without being sent.

### Insertion points

`InsertionPoint` represents a controllable/input-bearing location:

- query parameter
- path parameter
- body/form parameter
- JSON field
- cookie
- selected custom headers

Each point records name, type, required state, provenance, and structural metadata. Sensitive values are redacted in public serialization.

### Identities

`IdentityContext` references the role/tenant/session used to observe a request. Credential material itself belongs to runtime authentication handling and is not intended to become persistent workspace state.

`authenticated=true` means an explicit verification rule succeeded. Supplying a bearer token/basic credential alone is not considered verification.

## Crawling

The static crawler is bounded by depth, page count, link count, body bytes, request budget, central scope, and HTTP deadlines.

It:

- follows in-scope links;
- records forms without submitting them;
- records JavaScript request candidates;
- captures response metadata/body hashes;
- feeds responses into `PassivePipeline`;
- creates endpoint/request/insertion-point records.

The optional browser crawler observes SPA/browser traffic and navigable links. It is intentionally observational: no form auto-submit, mutation-click automation, anti-bot bypass, or browser exploit behavior.

## Authentication and process isolation

`AuthManager` prepares explicit researcher-provided authentication. Runtime authentication headers propagate into module child `ScanContext` objects so legacy and runtime-aware modules can share the same identity.

Sensitive authentication material is origin-bound. Manual HTTP redirects do not forward `Authorization`, `Proxy-Authorization`, or `Cookie` to a different scheme/host/effective-port. Browser credentials follow the same exact-origin principle.

## Passive analysis

`PassivePipeline` analyzes already-observed response metadata without generating additional target requests. Current passive observations include security-header coverage, cookie attributes, CSP metadata, server header/technology hints, content type, and password-form surface signals.

Passive observations are not promoted directly to verified vulnerabilities.

## Input audit

The first 2.0 insertion-point audit is deliberately conservative. It mutates one GET/HEAD query parameter with a harmless deterministic marker, verifies that the marker was absent from the baseline response, and records reflection as an `INFO` surface observation.

It does not send script, SQL, command, traversal, destructive, or authorization-bypass payloads.

## Declarative checks

Declarative templates are data-driven checks separate from Python core code. They declare impact, request/passive mode, matchers, negative matchers, extractors, classification, severity, and references.

Trust boundaries:

- templates cannot self-classify as `verified-finding`;
- passive templates send zero traffic;
- state-changing template requests are not auto-executed;
- SHA-256 verifies declared file integrity only, not author identity;
- Python plugins remain trusted executable code and are not sandboxed.

## Project persistence

`ProjectStore` uses SQLite/WAL and persists redacted workspace/report snapshots. It supports:

- checkpoints;
- resume;
- asset/request/observation history;
- cross-scan new/removed/changed diff.

A removed entity/observation is only “not seen in the newer scan.” It is not automatically labeled remediated because reachability or coverage may have changed.

## Coverage

`CoverageTracker` records:

- requests discovered/observed/audited/skipped;
- insertion points discovered/audited/skipped;
- skipped reasons;
- request and insertion-point audit ratios.

Coverage is part of finding interpretation. `0 findings` with partial coverage is not evidence that no vulnerability exists.

## Built-in module compatibility

The 24 legacy modules continue to run in killable child processes. Child contexts inherit:

- scan identity;
- target/domain;
- ScopePolicy including path rules;
- shared target HTTP budget;
- shared TargetHealth;
- request deadline/retry configuration;
- default authentication headers and identity reference.

The parent remains authoritative for module/global deadlines and can terminate blocked children.

## Failure semantics

Module terminal states are:

- `SUCCESS`
- `PARTIAL`
- `INCONCLUSIVE`
- `FAILED`
- `TIMEOUT`
- `ABORTED`

An unavailable target is an operational condition, not a vulnerability. An HTTP response including 4xx/5xx is a real transport response, not automatically a transport failure.

## Report schema 3.0

Schema 3.0 extends module/evidence reporting with:

- workspace snapshot;
- coverage;
- research-pipeline metadata;
- project diff;
- runtime reachability/identity/impact metadata.

Derived export formats are JSONL, SARIF, CSV, and HTML. The canonical representation remains JSON.

## Explicit non-goals

DEDSEC 2.0 does not claim:

- zero defects or zero false positives;
- complete browser-auth parity with commercial DAST suites;
- anti-WAF/IDS stealth/evasion;
- automatic exploitation;
- automatic destructive/state-changing workflows;
- that a clean or partial scan proves a target is secure.

Those boundaries are part of the reliability model, not missing marketing claims.
