# DEDSEC v2 core runtime plan

The next runtime stage moves DEDSEC from independent recon checks toward a shared, evidence-driven scan engine.

## This branch

- add a fail-closed target scope policy
- add a shared scan context and request budget
- add a centralized HTTP transport with TLS verification, pooling, caching, failure classification, and scope checks
- add typed observation, candidate, and verified-finding models
- let modules opt into the shared runtime while keeping the legacy `run(url, domain, timeout)` entry point working
- add deterministic runtime tests
- tighten contributor/review documentation without rewriting user-added community files unnecessarily

## Follow-up migration

HTTP-heavy bundled modules will be migrated to the shared transport in focused changes. After that, request-level evidence, asset/endpoint stores, and dependency-aware scheduling can become authoritative across the full scan.
