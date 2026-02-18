# Release Security Gate Recommendations

## Blocking Conditions (Must Pass)

1. **Identity Safety**
   - Host-key verification is fail-closed by default.
2. **Memory/DoS Hardening**
   - WS frame max enforced.
   - Non-streaming upload max enforced.
3. **Tunnel Input Hardening**
   - Request-line token/path validation added.
   - Header filtering normalized (case-insensitive).
4. **Automation**
   - CI runs wasm tests + vuln scans + module hygiene checks on all PRs.

## Required CI Job Matrix

- `wasm-tests`:
  - `GOOS=js GOARCH=wasm go test -exec="$(go env GOROOT)/lib/wasm/go_js_wasm_exec" ./...`
- `static-security`:
  - `go vet ./...`
  - `govulncheck ./...`
  - `GOOS=js GOARCH=wasm govulncheck ./...`
- `module-hygiene`:
  - `go mod tidy -diff`
  - `go mod verify`
- `parser-fuzz-smoke`:
  - `go test -run=^$ -fuzz=FuzzParseBinaryFrame -fuzztime=10s .`

## Exception Process

- Critical findings: no exceptions.
- High findings: require documented business justification, expiration date, and named owner.
- Medium/Low findings: can ship with tracked backlog item and milestone.

## Sign-off Checklist

- Security owner signs off triage state in `security/findings-triage.md`.
- Engineering owner signs off gate checks and CI evidence.
- Release notes include security deltas and known residual risks.

