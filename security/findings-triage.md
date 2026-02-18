# Findings Triage & Remediation Backlog (2026-02-18)

## Severity Model

- **Critical**: likely compromise of core security objective (auth/identity/confidentiality).
- **High**: realistic exploitation causing major confidentiality/integrity/availability impact.
- **Medium**: meaningful hardening gap or exploit path requiring extra conditions.
- **Low**: limited impact or primarily reliability/operational concern.

Exploitability scale:
- 5 = easy/likely in real-world conditions
- 1 = difficult/specialized preconditions

## Prioritized Findings

| ID | Severity | Exploitability | Finding | Primary Files |
|---|---|---:|---|---|
| C-01 | Critical | 5 | Missing host-key callback falls back to insecure trust-all | `ssh.go` |
| H-01 | High | 4 | Unbounded WS frame allocation in transport receive path | `transport.go` |
| H-02 | High | 3 | HTTP request-line fields not strictly validated before forwarding | `portforward.go` |
| H-03 | High | 5 | In-memory SFTP upload copies full payload without hard cap | `sftp_transfer.go` |
| S-01 | High | 4 | No CI security gate for tests/vuln/lint checks | repo-level |
| M-01 | Medium | 3 | Hop-by-hop header filtering is case-sensitive | `portforward.go` |
| M-02 | Medium | 3 | Backpressure can stall transport/tunnel channels under flood | `transport.go`, `portforward.go` |
| M-03 | Medium | 2 | Secrets not explicitly zeroized after parsing/auth | `ssh.go`, `agent.go` |
| M-04 | Medium | 3 | Raw internal errors surfaced to JS callers | `ssh.go`, `portforward.go` |
| M-05 | Medium | 2 | SFTP path policy not enforced locally | `sftp.go`, `sftp_transfer.go` |
| M-06 | Medium | 3 | No strict proxy URL scheme policy (`wss` enforcement) | `ssh.go`, `portforward.go` |
| M-07 | Medium | 2 | Unsafe type assertion in key metadata helper | `agent.go` |
| S-02 | Medium | 3 | Floating container tags in test compose | `docker-compose.test.yml` |
| S-03 | Medium | 2 | Wildcard origin in test proxy config | `docker-compose.test.yml` |
| B-01 | Medium | 2 | Internal stream control methods exposed globally | `main.go` |
| L-01 | Low | 2 | Minimal HTTP response parser edge-case risk | `portforward.go` |
| L-02 | Low | 2 | Write errors dropped in tunnel response helpers | `portforward.go` |
| S-05 | Low | 1 | No `SECURITY.md` vulnerability disclosure policy | repo-level |
| S-06 | Low | 2 | No dependency update automation | repo-level |

## Remediation Tasks With Acceptance Criteria

### 1) Enforce fail-closed host key policy (C-01)

**Task**
- Replace implicit `InsecureIgnoreHostKey` default with explicit failure when `onHostKey` is missing.
- Optional: add explicit `allowInsecureHostKey` dev flag requiring deliberate opt-in.

**Acceptance Criteria**
- Connecting without `onHostKey` returns deterministic error by default.
- New tests cover missing callback rejection + explicit insecure override path.

### 2) Add transport frame-size limits (H-01)

**Task**
- Define max WS frame size constant.
- Reject/close on oversized frame before allocating large buffers.

**Acceptance Criteria**
- Oversized frame test closes connection predictably.
- Memory profile shows bounded behavior under large frame attack corpus.

### 3) Harden forwarding request construction (H-02, M-01)

**Task**
- Validate method token, path characters, and reject CTL bytes.
- Normalize header keys to lowercase before hop-by-hop filtering.

**Acceptance Criteria**
- Tests for malformed method/path/header casing pass.
- No CR/LF or invalid token can reach forwarded request string.

### 4) Enforce upload bounds in non-streaming API (H-03)

**Task**
- Add `maxUploadSize` (or shared transfer bounds policy).
- Return clear error when exceeded; recommend streaming API.

**Acceptance Criteria**
- New tests verify >max uploads are rejected before full-copy allocation.
- Documentation updated with explicit upload size limits.

### 5) Establish CI security baseline (S-01)

**Task**
- Add CI workflow running:
  - wasm tests,
  - vet/lint,
  - `govulncheck`,
  - `go mod tidy -diff`.

**Acceptance Criteria**
- PRs fail when any security gate fails.
- CI artifact/log provides scanner output for review.

### 6) Address medium hardening backlog

**Tasks**
- Add safe error classes/messages for JS surface.
- Add optional strict SFTP path policy mode.
- Enforce `wss` default scheme with explicit dev override.
- Change `keyBits` to checked assertion.
- Add backpressure fail-fast/cleanup strategy for saturated channels.
- Pin compose image versions and tighten origin defaults.

**Acceptance Criteria**
- Unit/integration tests added for each changed policy.
- Security docs reflect defaults and opt-out behavior.

## Risk Acceptance Candidates (If Deferred)

- Stream helper broad worker scope (`scope: '/'`) may be accepted temporarily if app-wide SW ownership is intentional.
- Minimal HTTP response parser can be accepted short-term if strict upstream assumptions are documented and tested.

