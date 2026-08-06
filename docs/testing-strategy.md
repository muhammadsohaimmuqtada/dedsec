# Testing strategy

DEDSEC tests should prefer deterministic fixtures over live network dependencies.

The core suite should cover target normalization, scope decisions, transport failure classification, request-budget enforcement, evidence redaction, report-schema stability, finding promotion rules, concurrency isolation, and timeout behavior.

Detector suites should cover positive, negative, ambiguous, and malformed-response cases. Integration tests should use local fixture servers or mocked transports so CI results do not depend on third-party uptime or rate limits.
