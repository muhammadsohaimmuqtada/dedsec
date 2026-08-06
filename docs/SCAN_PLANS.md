# DEDSEC Scan Plans

Scan plans make DEDSEC behavior reproducible. They are local YAML or JSON files loaded with `--plan`.

```bash
dedsec --plan examples/scan-plan.example.yml
```

A plan can define target, modules, scope, discovery limits, traffic policy, project storage, templates, authentication, API specifications, and exports.

## Example

```yaml
target: https://example.com
modules:
  - dns
  - ssl
  - headers
  - subdomains
  - js
  - ports

scope:
  include_subdomains: true
  allowed_ports: [80, 443, 8443]
  include_paths:
    - "/app/*"
    - "re:^/api/(v1|v2)/"
  exclude_paths:
    - "/logout"
    - "/delete-account"
    - "re:^/api/admin/destructive(?:/|$)"

discovery:
  enabled: true
  crawl_depth: 3
  crawl_pages: 200
  crawl_body_bytes: 2097152
  javascript_candidates: true
  browser: false
  api_specs:
    - ./openapi.yaml

traffic:
  timeout: 10
  concurrency: 4
  module_timeout: 120
  global_timeout: 600
  retries: 2
  module_retries: 0
  backoff: 0.5
  max_requests: 1500
  maximum_impact: active-safe

project:
  database: .dedsec/example.db
  resume: false
  diff: true

templates:
  directories:
    - ./examples/templates
  maximum_impact: active-safe
  max_templates: 500

auth:
  file: ./auth-profile.yml

exports:
  formats: [json, sarif, html]
  directory: ./reports

metadata:
  purpose: authorized-research
```

## Target and modules

`target` may replace the positional URL. If both are supplied, an explicit CLI URL takes precedence.

`modules` accepts built-in or discovered plugin module keys. `all` means all available modules.

## Impact classes

DEDSEC orders impact as:

```text
passive < normal < active-safe < state-changing < high-impact
```

The scan-wide `traffic.maximum_impact` is the ceiling. Modules/templates whose declared impact is above the ceiling are blocked before execution.

This is an authorization/load-control mechanism. It does not make an operation safe merely because it is below a chosen ceiling; the researcher remains responsible for program rules and target authorization.

## Scope

### Hosts

When `allowed_hosts` is empty, DEDSEC allows the root host and, when `include_subdomains: true`, its subdomains.

When `allowed_hosts` is set, it becomes an explicit host allow-list. `denied_hosts` wins over allow rules.

Host rules may use shell-style `*` matching.

### Ports

`allowed_ports` constrains URL/service ports that pass central URL scope checks.

### Paths

`include_paths` and `exclude_paths` apply to decoded URL paths. Query strings do not change path authorization.

Rules are shell-style globs unless prefixed with `re:`.

```yaml
include_paths:
  - "/api/*"
  - "re:^/app/[a-z0-9-]+/"

exclude_paths:
  - "/logout"
  - "/account/delete"
```

Exclusions take precedence.

Path rules govern HTTP URL requests. Raw DNS/TCP/TLS reachability telemetry has no URL path and should be interpreted separately.

## Discovery

`discovery.enabled` activates the static application crawler.

- `crawl_depth`: maximum link depth.
- `crawl_pages`: maximum successfully observed pages.
- `crawl_body_bytes`: maximum response bytes used for crawler parsing/passive analysis.
- `javascript_candidates`: extract bounded fetch/axios/XHR URL candidates.
- `browser`: enable optional Playwright observation.
- `api_specs`: local OpenAPI/Swagger files imported into the request corpus.

Forms are recorded but not submitted by the crawler.

## Traffic

`timeout` is a total logical HTTP request deadline including retries/backoff, not a timeout multiplied by every retry.

`max_requests` meters target HTTP requests made through the DEDSEC runtime. It does not claim to meter DNS, WHOIS, raw TCP sockets, TLS handshakes, or external-intelligence traffic.

`module_timeout` and `global_timeout` are hard parent-process execution boundaries.

## Project

`project.database` enables SQLite project history.

`resume: true` restores knowledge from the latest saved checkpoint for the same domain before continuing discovery. Runtime coverage counters for the new run begin fresh.

`diff: true` compares the current workspace with the previous saved workspace. A removed observation/entity means “not seen this time,” not automatic remediation.

## Authentication

Use:

```yaml
auth:
  file: ./auth-profile.yml
```

or top-level:

```yaml
auth_file: ./auth-profile.yml
```

Authentication details are described in `docs/AUTHENTICATION.md`.

## Templates

`templates.maximum_impact` cannot exceed the scan-wide traffic maximum. State-changing template methods are not automatically executed even when the ceiling allows that impact class.

## Exports

Supported formats:

```text
json
jsonl
sarif
csv
html
```

The canonical schema is JSON 3.0; other formats are derived views.

## CLI precedence

DEDSEC currently applies a plan value when the corresponding CLI option remains at its normal default. An explicit non-default CLI option overrides the plan.

Because CLI parsers cannot distinguish “user explicitly typed the default value” from “option was untouched” for these options, explicitly repeating a default may still allow the plan value to win. For strict reproducibility, keep execution policy in the plan instead of redundantly restating defaults on the command line.

## Validation

Invalid impact classes, unsupported export formats, contradictory template/traffic impact ceilings, and malformed plan structures fail before scanning.
