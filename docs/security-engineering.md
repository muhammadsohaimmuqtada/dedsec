# Security engineering expectations

DEDSEC itself should be developed with the same rigor expected from the systems it inspects.

Defaults should verify TLS, respect explicit scope, bound concurrency and request counts, redact secrets, and avoid silently converting errors into successful or negative scan results.

Security-sensitive changes should include tests that demonstrate the intended safe failure mode.
