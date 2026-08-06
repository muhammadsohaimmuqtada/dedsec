# DEDSEC Professionalization Roadmap

This document tracks the engineering work required to make DEDSEC consistent, auditable, maintainable, and release-ready.

## Current baseline

DEDSEC already has a central CLI, bounded module orchestration, versioned JSON reporting, evidence identifiers, redaction, retry classification, and CI.

## Priority 1: core runtime

- one transport layer for all HTTP traffic
- explicit target scope policy
- shared scan context passed to modules
- structured request/response outcomes instead of silent `None` failures
- request-level evidence references
- host-aware budgets, retries, and backoff

## Priority 2: detector contract

- separate observations, candidates, and verified findings
- remove vulnerability claims based only on missing headers or heuristic fingerprints
- standardize module metadata and capabilities
- make modules independent from terminal rendering

## Priority 3: asset intelligence

- normalize domains, IPs, services, URLs, scripts, API routes, and schemas
- record discovery relationships and provenance
- allow downstream modules to consume upstream discoveries
- avoid repeated discovery and duplicate network requests

## Priority 4: quality and releases

- deterministic network fixtures
- report-schema compatibility tests
- supported-Python CI matrix
- release notes and semantic versioning
- maintained module and plugin authoring documentation

This roadmap favors reliability and evidence quality over adding large numbers of shallow checks.
