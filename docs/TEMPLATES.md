# DEDSEC Declarative Checks

DEDSEC 2.0 supports local declarative checks so researchers can add deterministic observations/candidates without editing scanner core code.

```bash
dedsec https://example.com --template-dir ./examples/templates
```

Templates are YAML/JSON data. Python plugins are a separate mechanism and remain trusted executable code.

## Minimal request template

```yaml
id: security-txt-surface
name: security.txt surface
impact: normal
mode: request
severity: INFO
classification: surface-observation
request:
  method: GET
  path: /.well-known/security.txt
matchers:
  - type: status
    value: 200
  - type: word
    value: "Contact:"
negative_matchers:
  - type: word
    value: "<html"
extractors:
  - type: regex
    name: contact
    pattern: '(?im)^Contact:\s*(.+)$'
references:
  - https://www.rfc-editor.org/rfc/rfc9116
```

A match becomes an observation/candidate according to the declared classification. It is not automatically a verified vulnerability.

## Required fields

- `id`: stable 3–120 character identifier using letters, numbers, `_ . : -`.
- `name`: display name; defaults to the ID.
- `impact`: one DEDSEC impact class.
- `mode`: `request` or `passive`.
- `matchers`: at least one matcher.

## Impact

Allowed values:

```text
passive
normal
active-safe
state-changing
high-impact
```

The template impact must be at or below the configured scan/template ceiling.

A non-idempotent method such as POST/PUT/PATCH/DELETE must declare `state-changing` or `high-impact`, but DEDSEC 2.0 still refuses to automatically execute state-changing template requests. They remain recorded/skipped surfaces until a future explicit state-change policy is designed and tested.

## Classification

Templates may declare only conservative classifications:

```text
observation
surface-observation
configuration-observation
hardening-observation
candidate
```

Templates cannot self-declare `verified-finding`. Verification requires framework-level evidence/correlation semantics outside an untrusted template file.

## Severity

Allowed severity labels:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Severity does not override classification. A `HIGH` candidate remains a candidate.

## Request mode

Request mode currently auto-executes only:

```text
GET
HEAD
OPTIONS
```

Request fields:

```yaml
request:
  method: GET
  path: /path
  headers:
    Accept: application/json
  query:
    view: public
```

Central scope, TLS, request budgets, logical deadlines, target-health behavior, and credential isolation still apply.

## Matchers

### Status

```yaml
- type: status
  value: 200
```

or:

```yaml
- type: status
  values: [200, 204]
```

### Header

```yaml
- type: header
  name: Content-Type
  value: application/json
```

Without `value`, the matcher checks header presence.

### Word

Request templates may match response body text:

```yaml
- type: word
  value: "Contact:"
```

### Regex

```yaml
- type: regex
  pattern: '(?im)^Contact:'
```

Python regular expressions are used. Templates are local researcher-controlled input; they are not sandboxed against pathological regular expressions.

### Negative matchers

`negative_matchers` are evaluated as controls. A positive group is rejected when the negative group matches.

Use negative controls to reduce false positives instead of relying on status codes alone.

## Matcher conditions

Matchers default to `and`. A matcher with:

```yaml
condition: or
```

joins the optional OR group. All required/AND matchers must pass, and when OR matchers exist at least one OR matcher must pass.

## Extractors

### Header extractor

```yaml
extractors:
  - type: header
    name: server
    header: Server
```

### Regex extractor

Request mode may extract a regex group:

```yaml
extractors:
  - type: regex
    name: version
    pattern: 'Version:\s*([0-9.]+)'
    group: 1
```

Extracted values are evidence metadata, not vulnerability proof.

## Passive mode

Passive templates analyze already-observed response metadata and send **zero additional network requests**.

Because DEDSEC intentionally does not retain response bodies in `ResearchWorkspace`, passive templates support only:

- status matchers;
- header matchers;
- header extractors.

Body word/regex matchers or regex body extractors are rejected at template load time instead of silently operating on missing data.

Example:

```yaml
id: passive-server-header
name: Server header observed
mode: passive
impact: passive
severity: INFO
classification: configuration-observation
matchers:
  - type: header
    name: Server
extractors:
  - type: header
    name: server
    header: Server
```

## Integrity field

A template may include `sha256`. DEDSEC canonicalizes the template excluding the `sha256` field and compares the declared digest.

This is an **integrity check only**. It proves that the loaded file matches a declared digest. It does not prove who authored or approved the template and is not a digital-signature system.

## Repository behavior

`TemplateRepository` loads `.yaml`, `.yml`, and `.json` recursively from configured directories, rejects duplicate IDs, and enforces a configurable maximum template count.

## Python plugins

Python plugin discovery uses the `dedsec.modules` entry-point group and requires a valid module entrypoint plus `ModuleMetadata` for entry-point plugins.

Python plugins execute code in the DEDSEC process/module environment. They are **trusted executable extensions and are not sandboxed**. Only install plugins from sources you trust and review.

## Authoring guidance

For low-false-positive checks:

1. Prefer structural evidence over generic strings.
2. Use negative controls for generic 200/HTML fallback pages.
3. Avoid assigning vulnerability language to configuration/posture observations.
4. Keep impact declarations accurate.
5. Keep state-changing requests out of auto-executed templates.
6. Record references and evidence needed for manual validation.
7. Do not use a template match as the sole basis for `verified` claims.
