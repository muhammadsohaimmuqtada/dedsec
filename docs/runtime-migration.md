# Runtime migration plan

The migration is intentionally incremental.

1. Land `ScopePolicy`, `ScanContext`, request budgeting, typed finding models, and the centralized transport.
2. Add compatibility helpers so current modules continue to run.
3. Migrate HTTP-heavy modules first and remove direct `requests.*` calls.
4. Add request-level evidence capture to the transport.
5. Introduce dependency-aware scheduling and shared asset discovery.
6. Remove legacy executors and transport paths after bundled modules no longer depend on them.

This ordering avoids a large rewrite that would make detector regressions difficult to isolate.
