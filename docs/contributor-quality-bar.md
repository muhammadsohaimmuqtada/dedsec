# Contributor quality bar

DEDSEC favors precise, reviewable security engineering over feature count.

A change is ready for review when it has a clear purpose, bounded behavior, deterministic tests where practical, and no ambiguous vulnerability claims.

For scanner logic, reviewers should be able to answer four questions from the code and tests: what was observed, why it matters, what evidence supports it, and what condition promotes it from a candidate to a verified finding.

Changes that introduce network activity should document request count, concurrency, timeout, retry, caching, scope, and sensitive-data behavior.

Large architectural work should be split into migration-safe stages so the CLI remains usable and reports remain interpretable between releases.
