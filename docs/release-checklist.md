# Release checklist

Use this checklist before tagging a DEDSEC release.

- [ ] `main` is green in CI
- [ ] version metadata is synchronized
- [ ] report-schema changes are documented
- [ ] CLI help and README examples match current behavior
- [ ] module inventory is current
- [ ] new detectors have positive, negative, and ambiguous fixtures
- [ ] sensitive-value redaction tests pass
- [ ] dependency changes have been reviewed
- [ ] SECURITY.md and disclosure instructions are current
- [ ] changelog/release notes explain user-visible compatibility changes
- [ ] a clean install smoke test succeeds in a fresh environment
