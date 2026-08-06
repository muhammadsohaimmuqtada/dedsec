# Runtime lifecycle

A scan creates one context, one evidence store, one scope policy, one request budget, and one shared transport. The orchestrator passes the context to runtime-aware modules and closes runtime-owned resources when the scan completes.
