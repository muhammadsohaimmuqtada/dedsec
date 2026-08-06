# Module authoring

Bundled and third-party modules should be conservative, bounded, and evidence-friendly.

## Compatibility entry points

Existing modules expose:

```python
def run(url: str, domain: str, timeout: int = 10) -> dict:
    ...
```

Runtime-aware modules may expose:

```python
def run_with_context(context) -> dict:
    ...
```

The orchestrator prefers the runtime-aware entry point when a scan context is available and otherwise uses the legacy contract.

## Result semantics

Use structured results. When applicable, distinguish observations, candidates, and confirmed results instead of collapsing them into a generic `vulnerable` flag.

A heuristic fingerprint, missing header, unusual port, or permissive configuration signal is not by itself a verified vulnerability. Verified findings need an explicit verification condition and supporting evidence.

## Network behavior

New active HTTP modules should use the shared runtime transport rather than creating ad-hoc `requests` sessions. Keep request counts finite, use explicit timeouts, and avoid unbounded concurrency or retry loops.

## Sensitive values

Do not print or persist raw credentials, authorization headers, session cookies, API keys, private keys, or other secrets. Return only the minimum redacted context required to explain a result.

## Tests

A detector should normally include deterministic fixtures for a positive case, a negative case, an ambiguous/candidate case, and malformed or unavailable input. CI tests should not depend on live third-party services.
