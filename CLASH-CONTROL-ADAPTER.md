# Clash Control Adapter for Clash Verge Rev 2.5.1

This repository contains the GPL-3.0 source for the native companion Adapter
used by [Clash Control MCP](https://github.com/huaqing0/clash-control-mcp).
It is a focused fork of
[Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) at
`v2.5.1`; it is not a new Clash client.

## Supported scope

The Adapter exposes Clash Verge's own Profile and preference operations through
an authenticated server bound to `127.0.0.1`:

- inspect, activate, and refresh Profiles;
- inspect and update supported Verge basic, theme, and layout preferences;
- update hotkeys through Clash Verge's native shortcut manager;
- return explicit memory, persisted, runtime, and side-effect evidence.

The HTTP routes call existing Clash Verge Rust functions so that configuration
regeneration, persistence, runtime updates, GUI refresh requests, hotkey
registration, and rollback follow the application's native paths.

## Security boundary

- The server is loopback-only.
- Every Adapter request requires a per-installation bearer token of at least
  32 characters.
- The token is stored in an owner-only credentials file and is never returned
  by the API.
- Request DTOs reject unknown fields and validate values before mutation.
- Writes use optimistic state fingerprints and fail on drift.
- Failed or unverifiable rollback is reported as `RECOVERY_REQUIRED`; the
  Adapter never fabricates a successful GUI acknowledgement.

## Compatibility

The current patch and installer path is pinned to:

- Clash Verge Rev `2.5.1`;
- macOS Apple Silicon;
- Adapter protocol `v1`;
- bundle ID `io.github.clash-verge-rev.clash-verge-rev`.

The MCP installer refuses unsupported versions, architectures, bundle IDs, or
binary/content hashes. See the
[unsigned patch installation guide](https://github.com/huaqing0/clash-control-mcp/blob/main/ADAPTER-PATCH-INSTALLATION.md)
for the user-facing workflow.

## Validation status

The source has passed Rust checks and unit tests, MCP integration tests, and
real-desktop acceptance on Clash Verge Rev 2.5.1. GUI-visible operations remain
explicitly `UNVERIFIED` whenever the application cannot supply a direct
acknowledgement; hotkeys are committed only after native registration evidence.

## Build

Use the upstream Clash Verge Rev prerequisites and build commands. A local
source build is for development and validation; this repository deliberately
does not run scheduled full-platform AutoBuild jobs or publish a replacement
Clash Verge application.

The supported end-user distribution is the version-pinned unsigned Adapter
patch produced and transactionally installed by Clash Control MCP.

## Licenses and attribution

This fork remains licensed under GNU GPL v3.0. Upstream notices and third-party
licenses remain intact. Clash Control MCP and its patch installer are
separately licensed under MIT.
