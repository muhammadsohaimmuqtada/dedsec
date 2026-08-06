# Implementation notes

The v2 orchestrator now supports a runtime-aware module entry point while preserving the existing `run(url, domain, timeout)` contract. Runtime-aware modules can receive shared scope, budget, and evidence state without breaking legacy modules.
