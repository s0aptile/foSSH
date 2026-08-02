# Security policy

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/s0aptile/foSSH/security/advisories/new) on this repository. Do not open a public issue for a security report.

There is no email address, no postal address, no phone number for this project — GitHub private vulnerability reporting and public GitHub issues are the only contact surface, and that's intentional (see `tos.md`).

## What to expect

- **No bug bounty.** This project does not pay for reports.
- **No response-time SLA.** This is maintained by one person, in whatever time is available.
- **No guarantee of a fix**, or of a timeline for one. Best-effort, stated plainly rather than implied.

If a report turns into a fix, credit is given in the release notes unless the reporter asks not to be named.

## Scope

foSSH's own security invariants are documented in `THREAT_MODEL.md` — a report that foSSH violates one of those is exactly the kind of thing this process is for. A report about a deployment-specific misconfiguration (wrong file permissions, an operator disabling a documented safeguard) is a support question, not a vulnerability in foSSH itself, though it's still fine to report it.

## Supported versions

This is Open Alpha (`0.1.0-alpha.1`). There is no long-term-support branch and no guarantee that a fix lands anywhere but the current alpha line — see `tos.md` §5.
