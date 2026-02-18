# Supply Chain & Dependency Security Audit (2026-02-18)

## Scope

- `go.mod`
- `go.sum`
- `Makefile`
- `docker-compose.test.yml`
- Repository automation posture (CI/security gates)

## Evidence Collected

### Toolchain and module integrity
- `go version` -> `go1.26.0 darwin/arm64`
- `go mod verify` -> `all modules verified`
- `go env GOSUMDB` -> `sum.golang.org`
- `go env GOPROXY` -> `https://proxy.golang.org,direct`

### Vulnerability scanning
- `govulncheck ./...` -> no known vulnerabilities reported.
- `GOOS=js GOARCH=wasm govulncheck ./...` -> no known vulnerabilities reported.
- `gosec` executed and produced findings; most are hardening/false-positive style, with one materially relevant issue:
  - `ssh.InsecureIgnoreHostKey` path in `ssh.go` (already captured as core critical issue).

### Dependency graph observed
- Direct/transitive module graph includes:
  - `golang.org/x/crypto v0.48.0`
  - `github.com/pkg/sftp v1.13.10`
  - `github.com/kr/fs v0.1.0`
  - plus test/tool transitive packages (`testify`, `x/net`, `x/text`, `x/term`, etc.)

## Findings

### High

#### S-01: No CI-based security gate or automation
- **Evidence**: No `.github/workflows` or equivalent CI config in repository.
- **Impact**: Security checks are not guaranteed on PRs/releases.
- **Recommendation**: Add CI pipeline with mandatory `go test`, `go vet`, `govulncheck`, and formatting/lint checks.

### Medium

#### S-02: Test/development container images use floating tags
- **Location**: `docker-compose.test.yml`
- **Evidence**:
  - `lscr.io/linuxserver/openssh-server:latest`
  - `nginx:alpine`
- **Impact**: Non-reproducible builds/tests and possible unexpected image drift.
- **Recommendation**: Pin immutable digests or specific version tags.

#### S-03: Test proxy configuration allows wildcard origins
- **Location**: `docker-compose.test.yml`
- **Evidence**: `ALLOWED_ORIGINS: "*"`
- **Impact**: Risky default if copied outside test context.
- **Recommendation**: Use explicit origins even in test templates or mark clearly as insecure-dev only.

#### S-04: Module metadata hygiene is not fully tidy
- **Evidence**: `go mod tidy -diff` reported differences:
  - direct dependencies currently marked as indirect in `go.mod`,
  - missing checksums for some test dependencies in `go.sum`.
- **Impact**: Reduces reproducibility clarity and dependency transparency.
- **Recommendation**: Run and commit `go mod tidy` under canonical Go version policy.

### Low

#### S-05: Security policy/reporting process file is absent
- **Evidence**: No `SECURITY.md`.
- **Impact**: Unclear coordinated vulnerability disclosure path.
- **Recommendation**: Add `SECURITY.md` with reporting channel and SLA expectations.

#### S-06: No dependency update automation
- **Evidence**: No Dependabot/Renovate config.
- **Impact**: Patch lag risk for future CVEs.
- **Recommendation**: Enable automated update PRs and scheduled vulnerability checks.

## Positive Controls

- Uses Go module checksum verification (`sum.golang.org`).
- No known vulnerabilities from `govulncheck` at audit time.
- `Makefile` includes `go vet` check path.

## Minimum Recommended Security Gate (CI)

1. `go test` for `GOOS=js GOARCH=wasm` target.
2. `go vet ./...` and optional `staticcheck`.
3. `govulncheck ./...` (default and js/wasm target env).
4. `go mod tidy -diff` and fail on diff.
5. Optional: `gosec` with tuned rule suppressions and triage policy.
6. Image tag linting for compose/Docker files.

