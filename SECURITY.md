# Security Policy

DEDSEC is security software, so vulnerabilities in the tool itself should be handled through coordinated disclosure. Please do **not** publish exploit details, credentials, private scan artifacts, or sensitive target data in a public issue.

## Supported versions

Security fixes are provided for the current release line.

| Version | Supported |
| --- | --- |
| `1.2.x` | Yes |
| `<= 1.1.x` | No |

Users should reproduce security issues against the latest available release or the current `main` branch when practical.

## What should be reported privately

Examples include:

- command or argument handling that can cause unintended code execution;
- scope-policy or transport behavior that can send requests outside the intended target boundary;
- secret-redaction failures that expose credentials or sensitive evidence;
- unsafe temporary-file or report-writing behavior;
- dependency or packaging behavior that creates a concrete security impact;
- denial-of-service conditions that can be triggered through normal DEDSEC usage;
- CI/release weaknesses that could compromise distributed project artifacts.

A false positive in a detector, feature request, documentation issue, or ordinary scanner bug can normally be reported through the public issue tracker unless it contains sensitive target information.

## How to report a vulnerability

**Preferred:** use GitHub's private vulnerability reporting / Security Advisory flow for this repository when the **Report a vulnerability** option is available under the repository's Security tab.

If private vulnerability reporting is unavailable, contact the repository maintainer through a private contact method listed on the maintainer's GitHub profile before sending technical details. Do not fall back to a public issue containing proof-of-concept code or sensitive evidence.

Please include, when available:

- affected DEDSEC version or commit;
- operating system and Python version;
- affected component/module;
- concise impact description;
- reproduction steps using a local, synthetic, or otherwise authorized target;
- minimal proof of concept;
- suggested mitigation, if known.

Redact credentials, access tokens, cookies, private hostnames, and unrelated customer data.

## Response targets

For a well-formed private report, the project aims to:

- acknowledge receipt within **3 business days**;
- provide an initial triage decision within **7 business days**;
- coordinate remediation and disclosure timing based on severity and complexity.

These are response targets, not contractual service-level guarantees. Complex issues may require additional time.

## Coordinated disclosure

Please allow maintainers reasonable time to reproduce, fix, test, and release a remediation before public disclosure. When a report is confirmed, the project may publish a GitHub Security Advisory describing affected versions, impact, remediation, and reporter credit if the reporter wishes to be named.

DEDSEC does not currently promise monetary bug bounties or rewards.

## Security research expectations

Testing DEDSEC itself should use infrastructure you own or are authorized to use. A project vulnerability report does not grant permission to test unrelated third-party systems.

When demonstrating scanner issues:

- prefer local fixtures, mock services, or disposable lab targets;
- keep request volume bounded;
- avoid destructive payloads;
- do not include third-party credentials or production data.

## Vulnerabilities discovered by DEDSEC

This policy covers vulnerabilities **in DEDSEC**. Security findings discovered against another organization should be reported through that organization's authorized disclosure or bug-bounty process and handled according to its scope and rules.
