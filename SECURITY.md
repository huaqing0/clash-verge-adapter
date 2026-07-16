# Security Policy

## Supported version

The Clash Control Adapter is currently pinned to Clash Verge Rev `2.5.1`,
macOS Apple Silicon, and Adapter protocol `v1`. Other application versions,
architectures, or repackaged binaries are unsupported.

## Reporting a vulnerability

Use this repository's private vulnerability reporting form under the GitHub
Security tab. Do not open a public issue containing Controller secrets,
Adapter tokens, subscription URLs, Profile contents, or local configuration.

## Runtime boundary

- Adapter traffic is accepted only on loopback.
- Requests require a per-installation bearer token.
- Credentials are stored in an owner-only file and are not returned by the API.
- Writes are allowlisted, state-bound, verified, and rollback-aware.
- Unverified side effects are reported as `UNVERIFIED`, never as committed.
