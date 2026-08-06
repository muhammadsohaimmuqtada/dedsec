# Transport notes

Response caching is intended for simple idempotent target requests. Requests with custom headers or request bodies should not share the default cache entry because detector inputs such as `Origin` can change response semantics.
