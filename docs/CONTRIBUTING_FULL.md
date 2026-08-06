# Contributing to DEDSEC

Thank you for improving DEDSEC. Changes should keep the framework precise, bounded, and useful for authorized security work.

## Development setup

```bash
git clone https://github.com/muhammadsohaimmuqtada/dedsec.git
cd dedsec
python -m pip install -e '.[dev]'
```

Run the checks before submitting changes:

```bash
ruff check .
python -m unittest discover -s tests -v
```

## Pull requests

Keep pull requests focused. Explain what changed, why it changed, compatibility impact, and how it was tested. Include or update tests for logic changes.

For network-facing changes, document timeout, retry, concurrency, request-count, scope, caching, and TLS behavior where relevant.

For detector changes, distinguish observations and candidates from verified findings. A missing hardening header, fingerprint, permissive configuration signal, or unusual service is not automatically a vulnerability.

## Module changes

Existing modules use `run(url, domain, timeout)`. Runtime-aware modules may use `run_with_context(context)` to access shared scope, evidence, request budget, and transport state. New active HTTP modules should prefer the shared runtime.

See `docs/MODULE_AUTHORING.md` for the module-quality contract.

## Sensitive data

Do not commit real credentials, cookies, tokens, private keys, target reports, or unredacted evidence. Use synthetic fixtures in tests and examples.

## Security issues

Do not open a public issue for a vulnerability in DEDSEC itself when disclosure could put users at risk. Follow `SECURITY.md`.

## Conduct

Participation in the project is governed by `CODE_OF_CONDUCT.md`.
