---
name: Bug report
about: Report a reproducible DEDSEC defect or incorrect scanner behavior
title: "[bug] "
labels: "bug"
assignees: ""
---

## Summary

Describe the problem clearly. If this is a security vulnerability in DEDSEC itself, **do not continue with a public issue**—follow `SECURITY.md` instead.

## DEDSEC environment

- DEDSEC version/commit:
- Python version:
- Operating system:
- Installation method (`pip -e`, clone, other):

## Command

```bash
# Paste the minimal command that reproduces the issue.
# Remove credentials, cookies, tokens, private hosts, and customer data.
```

## Modules and runtime options

- Module(s):
- `--timeout` / `--module-timeout` / `--global-timeout`:
- `--concurrency`:
- `--retries` / `--module-retries`:
- `--max-requests` (if used):
- `--root-only` (if used):
- Evidence output enabled? yes/no

## Expected behavior

What should DEDSEC have done?

## Actual behavior

What happened instead? Include the exact status, finding classification, or error when useful.

## Reproduction

Provide the smallest reproducible sequence using a system you own, a local fixture, or another explicitly authorized target.

1.
2.
3.

## Signal-quality details

If reporting a false positive or false negative, include:

- the module and finding/candidate name;
- why the result is incorrect;
- the relevant **redacted** response characteristics or synthetic fixture;
- whether a negative/control request produced different behavior.

Do not post live secrets or private vulnerability evidence.

## Logs / report excerpt

```text
Paste only the relevant redacted output here.
```

## Additional context

Include anything else needed to reproduce the issue, such as proxy use, unusual DNS/TLS behavior, or whether it appears only under concurrency.

### Checklist

- [ ] I reproduced this on the latest release or current `main` when practical.
- [ ] I removed credentials, cookies, tokens, private customer data, and unrelated target information.
- [ ] This is an ordinary bug/false-positive report, not a private security vulnerability in DEDSEC itself.
- [ ] The reproduction uses infrastructure I own or am authorized to test.
