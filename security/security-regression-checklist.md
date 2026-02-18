# Security Regression Checklist

Use this checklist on every security-sensitive release.

## Identity & Auth

- [ ] Connection fails by default if host-key callback is missing.
- [ ] Host-key rejection path is tested and blocks session establishment.
- [ ] Insecure host-key mode (if retained) requires explicit opt-in and is visibly documented.

## Transport & Parser Bounds

- [ ] WebSocket receive path enforces a max frame size.
- [ ] Oversized frame tests verify deterministic connection close/failure behavior.
- [ ] Binary frame parser rejects invalid ID lengths and malformed payloads.
- [ ] HTTP tunnel request parser rejects CR/LF and invalid request-line tokens.
- [ ] Hop-by-hop header filtering is case-insensitive.

## Resource Safety

- [ ] Non-streaming upload has a hard max size guard.
- [ ] Streaming cancel paths close resources and remove state entries.
- [ ] Concurrent close/cancel paths remain idempotent under race tests.
- [ ] Backpressure behavior under saturated channels is explicitly tested.

## SFTP Safety

- [ ] Path policy behavior (pass-through vs strict mode) is documented and tested.
- [ ] Recursive removal behavior for symlinks remains non-following (`Lstat`-based).
- [ ] Large download path enforces explicit size limits with clear error.

## Browser Boundary

- [ ] Service Worker stream pull/cancel routing is validated in multi-tab scenarios.
- [ ] Internal stream APIs are not broadly exposed, or are protected and documented.
- [ ] Fallback download path has explicit size warning/guard behavior.

## Supply Chain & Tooling

- [ ] `go mod verify` passes.
- [ ] `govulncheck` passes for default and wasm target env.
- [ ] wasm-target tests pass: `GOOS=js GOARCH=wasm ... go test`.
- [ ] Fuzz targets run on host CI for parser helpers.
- [ ] Compose/container image tags are pinned (no floating latest in release paths).
- [ ] `go mod tidy -diff` has no diff.
- [ ] Security disclosure policy (`SECURITY.md`) is present and current.

## Release Gate

- [ ] No open Critical findings.
- [ ] No open High findings without explicit, signed risk acceptance.
- [ ] Medium findings have owner + target milestone.
- [ ] Audit artifacts are updated and linked in release notes.

