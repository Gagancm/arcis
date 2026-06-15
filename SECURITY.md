# Security Policy

Arcis is security software, so we hold its own security to a high bar. Thank you
for helping keep it and its users safe.

## Reporting a vulnerability

Please report security issues privately, not in public issues or pull requests.

- Preferred: GitHub's private vulnerability reporting on this repository
  (the "Report a vulnerability" button under the Security tab). This opens a
  private advisory only the maintainers can see.

Please include:

- The affected package and version (`@arcis/node`, `arcis`, `arcis-go`,
  `@arcis/cli`, or `@arcis/mcp`).
- A description of the issue and its impact (for example, a bypass that lets a
  payload reach the application, or a false negative in a detector).
- A minimal reproduction: the input, the configuration, and the observed versus
  expected behavior.

## What to expect

- We aim to acknowledge a report within 3 business days.
- We will confirm the issue, assess severity, and share a remediation timeline.
- Detection bypasses are treated as security issues across all SDKs at once,
  since a bypass that works in one SDK is a bug in all of them.
- With your consent, we credit reporters in the release notes for the fix.

We do not run a paid bug-bounty program at this time. Responsible disclosure is
genuinely appreciated regardless.

## Scope

In scope: the Arcis SDKs (Node, Python, Go), the CLI scanner, the MCP server,
and the shared detection patterns. A detector that misses a real attack in a
realistic shape, or a sanitizer that can be bypassed, is in scope.

Out of scope: vulnerabilities in your own application that Arcis is not designed
to cover (see "What Arcis Cannot Replace" in the documentation), denial of
service via deliberately pathological input far above the configured size
limits, and issues in third-party dependencies that have no impact through
Arcis.

## Supported versions

Security fixes target the latest released minor of each package. Please upgrade
to the current version before reporting, in case the issue is already fixed.
