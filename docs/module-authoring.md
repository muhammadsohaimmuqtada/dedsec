# Module authoring guide

Bundled and third-party modules should be predictable, conservative, and evidence-friendly.

## Current compatibility contract

Existing modules expose:

```python
def run(url: str, domain: str, timeout: int = 10) -> dict:
    ...
```

During the v2 runtime migration this API remains supported.

## Output rules

- Return structured data; do not return terminal-formatted strings as the primary result.
- Use explicit keys for `confirmed`, `candidates`, `observations`, and `error` when those concepts apply.
- Do not label a heuristic, missing header, fingerprint, or configuration signal as a verified vulnerability without a defined verification condition.
- Preserve enough context for the evidence layer to explain why a result was produced.
- Never place credentials, session cookies, authorization headers, API keys, private keys, or other sensitive values into findings or console output.

## Network rules

Modules should use the shared DEDSEC transport/runtime as they are migrated. New modules should not introduce direct ad-hoc HTTP sessions unless the protocol cannot be represented by the shared transport.

Network behavior must remain bounded: finite request counts, explicit timeouts, conservative concurrency, and predictable retry behavior.

## Error handling

Avoid broad exception suppression that turns materially different failures into the same result. Errors should preserve a useful classification such as timeout, DNS failure, TLS failure, connection failure, invalid response, or parser failure while keeping sensitive content out of error strings.

## Testing

Each detector should have tests covering:

- a positive fixture
- a negative fixture
- at least one ambiguous/candidate fixture
- malformed or unavailable upstream data
- redaction when sensitive-looking values can appear

Tests should not depend on live third-party services.
