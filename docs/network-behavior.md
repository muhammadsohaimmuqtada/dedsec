# Network behavior

All active network behavior should eventually be routed through the shared runtime so connection pooling, TLS verification, retry policy, request budgets, scope checks, caching, and error classification are consistent across modules.
