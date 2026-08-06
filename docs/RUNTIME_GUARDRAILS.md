# Runtime guardrails

Runtime-aware target requests are expected to use explicit scope checks, TLS verification by default, bounded retries, a shared request budget, connection pooling, and classified failures. These guardrails are infrastructure, not a substitute for the authorization rules of the target program.
