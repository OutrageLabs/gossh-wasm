# Full Security Audit Report: gossh-wasm (2026-02-18)

## Executive Summary

This audit reviewed architecture, code, browser boundary, runtime behavior, and supply-chain posture for `gossh-wasm`.

Top conclusion:
- The library has strong foundational controls (timeouts, parser bounds in key spots, CRLF guard, symlink-safe recursive delete, cleanup idempotence),
- but contains one **Critical** security-default issue and several **High** availability/integrity hardening gaps that should be addressed before high-trust production rollout.

## Severity Summary

- Critical: 1
- High: 5
- Medium: 9
- Low: 4

## Most Important Findings

1. **Critical**: Host-key verification defaults to insecure trust-all behavior when callback is missing (`ssh.InsecureIgnoreHostKey` path in `ssh.go`).
2. **High**: Transport receive path has no explicit max frame limit before allocation (`transport.go`).
3. **High**: Forwarded HTTP request-line values are not strictly validated under tunnel input trust-compromise scenarios (`portforward.go`).
4. **High**: Non-streaming upload path can fully copy unbounded payloads into WASM memory (`sftp_transfer.go`).
5. **High (process)**: No CI security gate currently enforces tests/scanners on changes.

## What Was Performed

- Threat model and trust-boundary analysis.
- Deep static audit of core modules.
- Browser boundary review of Service Worker/message bridge.
- Dependency and supply-chain verification (`go mod verify`, `govulncheck`, `gosec`, compose/security posture review).
- Dynamic adversarial test expansion and execution for wasm target.
- Coverage-guided fuzz execution on parser mirrors due `-fuzz` limitation on `js/wasm`.

## Evidence Artifacts

- Threat model: `security/threat-model.md`
- Core static findings: `security/static-audit-core.md`
- Browser boundary findings: `security/browser-boundary-audit.md`
- Supply-chain findings: `security/supply-chain-audit.md`
- Dynamic test evidence: `security/dynamic-test-results.md`
- Fuzzing evidence: `security/fuzzing-results.md`
- Triage/backlog: `security/findings-triage.md`
- Added runtime tests: `security_runtime_test.go`
- Added host fuzz harness: `parser_fuzz_host_test.go`

## Commands Executed (Key)

- `go mod verify`
- `govulncheck ./...`
- `GOOS=js GOARCH=wasm govulncheck ./...`
- `GOOS=js GOARCH=wasm go test -exec="$(go env GOROOT)/lib/wasm/go_js_wasm_exec" ./...`
- `go test -run=^$ -fuzz=FuzzParseBinaryFrame -fuzztime=5s .`
- `go test -run=^$ -fuzz=FuzzContainsCRLF -fuzztime=5s .`
- `go test -run=^$ -fuzz=FuzzFindHeaderEnd -fuzztime=5s .`

## Residual Risk Statement

If no remediation is applied:
- MITM risk remains significant in integration-misconfiguration scenarios.
- Memory/availability risk remains elevated under malicious or compromised tunnel/proxy input.
- Security quality may regress over time due missing automated CI security gates.

## Recommended Release Decision

- **Not recommended for hardened production release until C-01 and High findings (H-01/H-02/H-03/S-01) are addressed.**
- Acceptable for controlled/internal environments with strict integrator controls and explicit risk acceptance.

