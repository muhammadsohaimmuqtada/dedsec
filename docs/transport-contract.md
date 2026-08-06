# Transport contract

The v2 transport is responsible for centralizing target HTTP behavior.

A request outcome must distinguish a response from a transport failure. Failures are classified instead of collapsed into `None`, allowing callers to tell scope rejection, request-budget exhaustion, TLS failures, connection failures, and timeouts apart.

The transport owns connection pooling, bounded retry behavior for idempotent requests, response caching, TLS verification defaults, request accounting, and scope checks.

During migration, legacy modules may still use existing helpers. New runtime-aware modules should use the transport directly so their request behavior is auditable and consistent.
