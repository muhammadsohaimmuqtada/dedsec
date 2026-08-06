# Quality gates

A DEDSEC pull request should pass the following gates before merge:

1. Static linting succeeds.
2. The full unit-test suite succeeds.
3. New detector behavior includes deterministic fixtures.
4. Network changes remain bounded and scope-aware.
5. Verified findings require evidence references.
6. Sensitive values are redacted from reports, logs, tests, and examples.
7. CLI/report compatibility changes are documented.
8. README and module inventory match shipped behavior.

These gates are intended to keep reliability and evidence quality from regressing as coverage expands.
