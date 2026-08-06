# DEDSEC Authentication Contexts

DEDSEC authentication is explicit and researcher-supplied. The framework does not register accounts, guess credentials, bypass access controls, or automatically discover privileged sessions.

Use a local YAML/JSON profile:

```bash
dedsec https://example.com --auth ./auth-profile.yml --deep
```

## Supported kinds

### Static headers

```yaml
label: researcher
kind: headers
headers:
  X-Research-Header: authorized
verification:
  url: /account
  expect_status: 200
```

### Basic authentication

```yaml
label: researcher
kind: basic
username: researcher@example.com
password: ${PLACEHOLDER}
verification:
  url: /account
  expect_status: 200
  body_regex: "Account"
  logged_out_regex: "Sign in"
```

### Bearer token

```yaml
label: researcher
kind: bearer
token: ${PLACEHOLDER}
role: customer
verification:
  url: /api/me
  expect_status: 200
```

### Header API key

```yaml
label: api-researcher
kind: api_key
api_key_name: X-API-Key
api_key_value: ${PLACEHOLDER}
api_key_location: header
verification:
  url: /api/me
  expect_status: 200
```

### Cookie context

```yaml
label: researcher
kind: cookie
cookies:
  session: ${PLACEHOLDER}
verification:
  url: /account
  expect_status: 200
```

### Explicit login workflow

```yaml
label: customer-a
kind: workflow
role: customer
tenant: tenant-a
workflow:
  - method: GET
    url: /login
    expect_status: 200

  - method: POST
    url: /login
    form:
      username: researcher@example.com
      password: ${PLACEHOLDER}
    expect_status: [200, 302]
    follow_redirects: true

verification:
  url: /account
  expect_status: 200
  body_regex: "Welcome"
  logged_out_regex: "Sign in"
```

Workflow methods are restricted to explicitly configured `GET`, `HEAD`, and `POST`. DEDSEC does not invent login steps.

## Verification semantics

A configured credential is not the same as a verified authenticated session.

If no `verification` block exists, DEDSEC records the identity as configured but `authenticated=false` with reason `verification-not-configured`.

Verification can check:

- one in-scope URL;
- expected status code(s);
- optional positive body regex;
- optional logged-out/negative body regex.

Only a successful verification marks the identity authenticated.

## Credential propagation

Authentication material is bound to the exact configured target origin:

```text
scheme + host + effective port
```

For a target of `https://example.com`, DEDSEC does not automatically send the same `Authorization`, `Proxy-Authorization`, or `Cookie` values to `https://api.example.com`, `http://example.com`, or a different port merely because that destination is otherwise within hostname scope.

Manual redirects strip sensitive explicit headers when the endpoint changes.

The optional browser adapter follows the same principle. Cookies are installed for the configured target URL; Authorization/Proxy-Authorization are injected only for requests whose endpoint matches the exact target origin.

This is intentionally conservative. If an application legitimately uses separate authenticated origins, define/test those identities deliberately instead of relying on implicit credential propagation.

## Child-process modules

DEDSEC modules execute in isolated child processes. The runtime specification carries the identity reference and default runtime headers into each child `ScanContext`, so runtime-aware and bridged legacy target HTTP calls can use the same authentication context.

## Secret persistence

Credentials are runtime material. Public workspace/report/project serialization redacts:

- Authorization/Proxy-Authorization;
- Cookie/Set-Cookie;
- API-key/auth-token style headers;
- password/token/secret/session/CSRF-like body keys;
- sensitive insertion-point values;
- Bearer/Basic-like inline credential strings.

Project snapshots are redacted before SQLite persistence.

The crawler intentionally stores an `identity_id` reference while removing sensitive auth/cookie headers from its request corpus.

Do not treat this as a general-purpose secret vault. Protect auth profile files with normal filesystem controls and avoid committing real credentials to source control.

## Workflow capture

A workflow step may capture a value from a response header or a regular-expression group for substitution into later configured workflow steps.

Example:

```yaml
workflow:
  - method: GET
    url: /login
    capture:
      csrf:
        regex: 'name="csrf" value="([^"]+)"'
        group: 1

  - method: POST
    url: /login
    form:
      username: researcher@example.com
      password: ${PASSWORD}
      csrf: ${csrf}
```

Captured values are runtime workflow variables. Avoid writing secrets into metadata fields intended for reports.

## Current limitations

DEDSEC 2.0 authentication does not claim parity with Burp/ZAP browser-auth ecosystems. In particular, core authentication does not automatically implement:

- account registration;
- credential guessing;
- TOTP generation;
- WebAuthn ceremonies;
- arbitrary client-script login automation;
- identity/role discovery;
- cross-user authorization comparison logic.

Those require explicit, testable designs rather than being silently approximated.
