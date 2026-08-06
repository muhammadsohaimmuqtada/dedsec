# Community standards

DEDSEC's repository policies are part of the product quality bar. Scanner code, public documentation, contribution workflow, and security handling should describe the same current behavior.

## Canonical project policies

| Area | Canonical file | Purpose |
| --- | --- | --- |
| Contribution workflow | [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Engineering, testing, evidence, runtime, and PR expectations |
| Community behavior | [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) | Professional conduct and security-research collaboration |
| Vulnerability disclosure | [`SECURITY.md`](../SECURITY.md) | Supported versions and coordinated disclosure process |
| License | [`LICENSE`](../LICENSE) | MIT licensing terms |
| Pull requests | [`.github/PULL_REQUEST_TEMPLATE.md`](../.github/PULL_REQUEST_TEMPLATE.md) | Required quality and safety review checklist |
| Bug reports | [`.github/ISSUE_TEMPLATE/bug_report.md`](../.github/ISSUE_TEMPLATE/bug_report.md) | Reproducible runtime/scanner bug template |

## Reporting boundaries

Use a public issue for ordinary bugs, regressions, false positives, documentation problems, and feature requests that do not expose sensitive third-party information.

Use the private process in `SECURITY.md` for vulnerabilities in DEDSEC itself when public disclosure could put users at risk.

Third-party vulnerabilities discovered with DEDSEC belong in the affected organization's authorized disclosure or bug-bounty process, not in this repository's issue tracker.

## Maintenance rule

When a release changes supported versions, CLI controls, module contracts, report semantics, security behavior, or contribution requirements, update the relevant policy/documentation in the same pull request. Placeholder templates and contradictory version information should not remain in the default branch.
