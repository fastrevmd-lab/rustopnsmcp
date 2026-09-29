# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository:

https://github.com/mechubsec/rustopnsmcp/security/advisories/new

Include what you'd include in a bug report — affected version, reproduction steps, and impact — but keep it in the private report, not a public issue, PR, or discussion.

## Scope

`rustopnsmcp` is an MCP server that authenticates to one or more OPNsense devices and exposes a curated, scoped set of tools over MCP, with authentication, transport, audit, and (from phase 2) change-control behavior supplied by the shared [`mecmcp`](https://github.com/mechubsec/mecmcp) crates. Phase 1 exposes read tools only. Vulnerability classes we especially want to hear about:

- Anything that lets a caller exceed the scope granted to its token without going through the intended auth/scope checks
- TLS or certificate-handling issues in the server's listener, or in its outbound connection to an OPNsense device
- Injection or path-traversal issues via the device inventory file or the token store
- Parsing issues where a malicious or malformed device response could affect the server beyond the intended request
- Anything that would let a read tool's output leak a credential the redaction layer should have scrubbed

If the issue is actually in shared `mecmcp` code rather than something specific to this repo's OPNsense integration, it's still fine to report it here — it will get routed to the right repository.

## Response

This is a community-maintained project. There's no guaranteed SLA. A human maintainer is responsible for triaging every report and for all disclosure and fix decisions.
