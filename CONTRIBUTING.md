# Contributing to DEDSEC

Thank you for contributing to DEDSEC. The project is building toward a reliable, evidence-driven reconnaissance framework for **authorized** security testing. Contributions are evaluated not only for feature value, but also for signal quality, bounded network behavior, reproducibility, compatibility, and maintainability.

## Before you start

Small fixes can go directly to a pull request. For larger work—new active probes, architecture changes, report-schema changes, major dependencies, or behavior that materially increases request volume—open an issue first so the design and safety boundaries can be reviewed.

DEDSEC is not intended for destructive testing, persistence, credential abuse, unauthorized access, or evasion designed to defeat controls on systems you are not authorized to assess.

## Development setup

```bash
git clone https://github.com/muhammadsohaimmuqtada/dedsec.git
cd dedsec
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[dev]'
```

Run the local quality checks before opening a pull request:

```bash
ruff check .
python -m unittest discover -s tests -v
python -m compileall -q dedsec tests
```

CI additionally validates the supported Python versions and CLI smoke behavior.

## Engineering principles

### Prefer evidence over claims

DEDSEC distinguishes collected facts from security conclusions:

- **Observation** — a fact collected from a target or runtime.
- **Candidate / hypothesis** — a security-relevant signal that still requires validation.
- **Verified finding** — a finding supported by explicit verification semantics and evidence references.

Do not label a target `vulnerable` solely because a header is absent, a fingerprint matches, a status code appears, or a configuration looks unusual. Where impact has not been demonstrated, emit an observation or candidate instead.

### Keep network behavior bounded

New and migrated modules should use the shared scan runtime and transport rather than creating independent network stacks.

Contributions must:

- respect `ScopePolicy` decisions;
- respect request budgets, timeouts, and bounded concurrency;
- keep TLS verification enabled by default;
- avoid unbounded recursion, brute-force loops, or hidden background traffic;
- document the expected request volume of new active checks;
- preserve timeout, failure, and inconclusive states instead of silently discarding them.

### Use the runtime-aware module contract

Legacy modules remain supported through:

```python
def run(url, domain, timeout=10):
    ...
```

New or migrated modules should prefer:

```python
def run_with_context(context):
    ...
```

The context provides shared target scope, request budgeting, evidence identity, and transport ownership. See [`docs/MODULE_AUTHORING.md`](docs/MODULE_AUTHORING.md) and [`docs/CORE_RUNTIME_PLAN.md`](docs/CORE_RUNTIME_PLAN.md).

### Reuse core contracts

Before inventing a module-specific structure, check the core package for an existing contract. Shared findings, evidence, status, scope, and runtime types are preferred because they keep reporting and correlation predictable.

## Evidence and sensitive data

- Never commit live credentials, session tokens, API keys, private keys, or private customer data.
- Tests must use synthetic fixtures and fake credentials.
- Do not print or persist complete discovered secrets when a redacted representation is sufficient.
- Persisted evidence must pass through DEDSEC's redaction layer.
- A verified finding must retain enough evidence provenance to be independently reviewed.

## Tests

Behavior changes should include regression coverage where practical. High-value cases include:

- parsing and normalization edge cases;
- scope allow/deny behavior;
- request-budget enforcement;
- timeout and retry behavior;
- false-positive controls and negative controls;
- evidence redaction;
- candidate-to-verified promotion rules;
- report-schema compatibility.

Tests should be deterministic and should not depend on live third-party services unless a maintainer explicitly approves an integration-test workflow.

## Documentation requirements

Update the README or relevant docs whenever a contribution changes:

- CLI flags or defaults;
- module inventory;
- supported Python versions;
- report fields or schema behavior;
- runtime/scope semantics;
- installation requirements;
- network side effects;
- user-visible finding terminology.

Code, package metadata, and repository documentation should always describe the same current behavior.

## Pull-request expectations

Keep pull requests focused and explain:

1. what changed;
2. why it changed;
3. network or target impact;
4. compatibility impact;
5. how it was tested;
6. remaining limitations or migration work.

Use the repository pull-request template and complete the scanner-quality, scope, evidence, and sensitive-data checks honestly.

## Security issues

Do not open a public issue for a vulnerability in DEDSEC itself. Follow [`SECURITY.md`](SECURITY.md) for coordinated disclosure.

## Community conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Technical disagreement is welcome; harassment, doxxing, intimidation, or disclosure of private target/researcher data is not.

By contributing, you agree that your contribution may be distributed under the repository's MIT License.
