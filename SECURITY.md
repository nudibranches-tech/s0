# Security Policy

s0 sits directly on the authorization path for S3 traffic and holds the
per-tenant backend credentials it re-signs with, so we take security reports
seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately to:

- **Email:** roch@nudibranches.tech
- Optionally use GitHub's
  [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  ("Report a vulnerability" under the repository's **Security** tab).

Please include, as far as you can:

- A description of the issue and its impact.
- Steps to reproduce or a proof of concept.
- Affected version(s) / git SHA.
- Any suggested remediation.

Encrypt sensitive details if possible, and never include third-party
credentials or customer data in a report.

## Response process

- **Acknowledgement:** within **3 business days**.
- **Initial assessment:** within **7 business days**, including severity triage.
- **Fix & disclosure:** we aim to ship a fix and coordinate a public advisory
  within **90 days** of the report, sooner for actively exploited issues.

We will keep you informed throughout and credit you in the advisory unless you
prefer to remain anonymous.

## Supported versions

s0 is pre-1.0; only the latest released minor series receives security
fixes.

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

Once 1.0 ships this table will be updated to reflect the supported release
window.

## Disclosure policy

We follow **coordinated disclosure**: please give us a reasonable window to
release a fix before any public discussion. We will publish a GitHub Security
Advisory and release notes when the fix is available.
