# DEDSEC v2 evidence model

DEDSEC v2 separates scanner output into four levels:

1. **Raw module result** — structured data returned by a module.
2. **Evidence record** — immutable scan evidence with a SHA-256 digest, provenance, secret redaction, and an optional atomic JSON artifact.
3. **Hypothesis** — a security-relevant signal that still needs proof or impact validation.
4. **Verified finding** — a structured module confirmation backed by a persisted evidence ID.

A module's prose or a heuristic fingerprint is never sufficient by itself to create a verified finding. Candidate endpoints, CORS configuration signals, and subdomain-takeover fingerprints remain hypotheses until the module provides explicit verification semantics and evidence.

## Reliability rules

- Module-level retries are bounded and restricted to transient/timeout failures.
- Exponential backoff is capped.
- Repeated failures open a per-module circuit breaker.
- Parallel stdout capture is thread-local to avoid cross-module output corruption.
- Global and per-module timeouts are recorded as explicit terminal states.
- Failed and negative module outcomes are preserved in the final report rather than silently dropped.

## Reporting

The JSON report schema is versioned as `2.0` and includes scan metadata, module execution status, attempts, failure classification, evidence IDs, redacted raw results, observations, hypotheses, verified findings, and rejected/unverified outcomes.

Use `--evidence-dir PATH` to persist per-module evidence artifacts when running from the CLI.
