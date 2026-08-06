# DEDSEC v2 architecture

DEDSEC v2 is evolving from a collection of independent checks into an evidence-driven reconnaissance runtime.

## Design principles

1. Network activity should be centralized, bounded, observable, and reusable.
2. Scope decisions should be explicit and fail closed.
3. Modules should emit structured observations instead of making presentation-layer decisions.
4. Heuristic signals should remain candidates until verification criteria are satisfied.
5. Evidence should preserve provenance while redacting sensitive values.
6. Discovery results should be reusable by downstream modules rather than rediscovered independently.

## Target architecture

```text
CLI
 |
 v
ScanContext
 |-- ScopePolicy
 |-- Transport
 |-- EvidenceStore
 |-- AssetStore
 |-- RequestBudget
 |
 v
Scheduler
 |-- discovery modules
 |-- profiling modules
 |-- detector modules
 |-- verification modules
 |
 v
Correlation
 |
 v
Versioned Report
```

## Migration strategy

The existing `run(url, domain, timeout)` module API remains supported during migration. New runtime-aware modules should accept a shared context through a compatibility adapter. Once all bundled modules use the runtime, legacy transport helpers and stale executor implementations can be removed.
