# Testing

DEDSEC tests should be deterministic and should not depend on live third-party services.

Core coverage should include target normalization, scope decisions, transport failure classification, request budgets, caching, evidence redaction, finding-promotion rules, concurrency isolation, timeout behavior, and report-schema stability.

Detector tests should cover positive, negative, ambiguous, and malformed-response cases.

Run the project checks with:

```bash
ruff check .
python -m unittest discover -s tests -v
```
