# Scope and safety model

DEDSEC should fail closed when deciding whether active target traffic is permitted.

The v2 runtime models scope independently from detector logic. A scope policy can allow the root domain, optionally include its subdomains, restrict schemes, restrict ports, add explicit host allow-lists, and add explicit host deny-lists.

Passive intelligence providers are conceptually separate from target scope. Modules that query external data providers should identify those requests as provider traffic rather than silently bypassing target-scope checks.

The current migration keeps the legacy module API available while runtime-aware modules move to the centralized transport. New active modules should be written against the runtime instead of creating ad-hoc HTTP sessions.
