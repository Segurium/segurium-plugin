# Security Policy

Segurium is security software. We hold our own code to the standard we sell.

## Reporting a vulnerability

**Do not open a public issue.** A public report exposes every live install
before a fix exists.

Use either private channel. Both reach the same people:

1. **GitHub private reporting.** Open the
   [Security tab](https://github.com/Segurium/segurium-plugin/security)
   of this repository and press **Report a vulnerability**.
2. **Email** security@segurium.com. A human reads it.

The full disclosure policy lives at
[segurium.com/security](https://segurium.com/security/). It covers what to
include in a report, what we do after we receive one, the testing ground
rules, what falls out of scope, and how we credit reporters. Read it before
you send anything.

A report is easiest to act on when it names what the issue lets an attacker
do, the version you tested, and the steps to reproduce it.

## Supported versions

| Version | Security fixes |
|---|---|
| The release currently published on [WordPress.org](https://wordpress.org/plugins/segurium/) | Yes |
| Anything older | No. Update first, then re-test |

Fixes ship as a new release on WordPress.org. WordPress auto-updates carry
them to sites that have auto-updates enabled.

## Scope

This repository mirrors the WordPress plugin. Findings in the plugin code
belong here.

Findings in our cloud service, our website, or our infrastructure belong to
the same team through the same two channels, and are governed by the policy
at [segurium.com/security](https://segurium.com/security/).

Out of scope, and covered in full by that policy: denial of service,
social engineering, physical attacks, and scanner output with no
demonstrated impact.

## Rewards

Segurium runs no paid bug bounty. We credit reporters publicly at
[segurium.com/security](https://segurium.com/security/) once the reported
issue is fixed and the reporter has told us how they want to be named.

## Not a security issue?

Bug reports and missed detections go to the
[WordPress.org support forum](https://wordpress.org/support/plugin/segurium/),
or to the contact form on [segurium.com](https://segurium.com/). Both get
triaged faster than a security mailbox.
