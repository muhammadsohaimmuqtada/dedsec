# Security Policy

DEDSEC is security tooling. Vulnerabilities in the tool itself can affect scan scope, confidentiality, evidence integrity, or the safety of authorized testing. Please report those issues responsibly.

## Supported Versions

| Version | Supported |
| --- | --- |
| `1.3.x` | ✅ Current |
| `1.2.x` | ⚠️ Upgrade recommended |
| `<= 1.1.x` | ❌ No longer supported |

Security fixes are prioritized for the current release line. Users should reproduce issues against the latest release or current `main` when practical.

## What Counts as a DEDSEC Security Issue

Examples include:

- target-scope or redirect-scope bypass;
- failure of hard scan/module cancellation that can leave unintended network activity running;
- secret or credential leakage in reports, evidence, logs, or artifacts;
- unsafe TLS behavior or automatic certificate-verification bypass;
- command, path, template, or other injection in DEDSEC itself;
- request-budget or network-boundary enforcement failures;
- evidence tampering, report-integrity failures, or unsafe artifact handling;
- dependency vulnerabilities that materially affect DEDSEC's security behavior.

A vulnerability found **with DEDSEC against somebody else's system** is not a DEDSEC vulnerability. Report that issue through the affected system owner's authorized disclosure or bug-bounty process.

## Reporting a Vulnerability

Please do not publish sensitive exploit details, credentials, private target data, or zero-day information in a public GitHub issue.

Use GitHub's private security-reporting mechanism when it is available for this repository. If private reporting is unavailable, contact the maintainer through an established private channel before publishing technical details.

A useful report should include:

- affected DEDSEC version and commit;
- operating system and Python version;
- exact command/configuration needed to reproduce the issue;
- expected vs. observed behavior;
- minimal proof of impact using synthetic or owned test data;
- relevant stack trace or logs with secrets removed;
- whether the issue affects scope, request budgets, TLS, evidence, reporting, or execution boundaries.

## Response Targets

These are project targets, not contractual SLAs:

| Stage | Target |
| --- | --- |
| Acknowledge report | 3 business days |
| Initial severity / reproducibility review | 7 business days |
| Remediation plan for confirmed high-impact issues | 14 business days |
| Coordinated disclosure | Agreed with reporter based on fix availability |

## Safe Research Expectations

When testing DEDSEC itself:

- use systems you own or are explicitly authorized to test;
- prefer local fixtures and synthetic credentials;
- keep request volume bounded;
- do not use destructive payloads, denial-of-service techniques, social engineering, or persistence;
- do not access or retain third-party data;
- stop testing if behavior escapes the intended scope.

DEDSEC's built-in guardrails reduce accidental unsafe behavior, but they do not replace authorization or operator judgment. The target HTTP request budget does not represent DNS queries, WHOIS, or raw TCP operations; those operations are bounded separately by module/global execution deadlines and module-specific controls.

## Disclosure and Credit

We aim to coordinate fixes and disclosure with good-faith reporters. With the reporter's permission, meaningful security contributions may be credited in release notes or advisories.
