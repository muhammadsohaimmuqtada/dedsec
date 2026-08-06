# Runtime-aware module contract

During migration DEDSEC supports two module entry points.

Legacy modules expose `run(url, domain, timeout)`.

Runtime-aware modules expose `run_with_context(context)` and receive the shared scan context, including target scope, request budget, evidence store, and runtime metadata. The orchestrator should prefer the runtime entry point when present and fall back to the legacy entry point otherwise.

This allows modules to be migrated without a flag day or a repository-wide rewrite.
