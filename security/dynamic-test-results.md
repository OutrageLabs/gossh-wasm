# Dynamic Security Test Results (2026-02-18)

## Execution Commands

- Baseline wasm tests:
  - `GOOS=js GOARCH=wasm go test -exec="$(go env GOROOT)/lib/wasm/go_js_wasm_exec" ./...`
- Re-run after adding adversarial tests:
  - `GOOS=js GOARCH=wasm go test -exec="$(go env GOROOT)/lib/wasm/go_js_wasm_exec" ./...`

Result: all tests passed.

## Added Adversarial Runtime Tests

File: `security_runtime_test.go`

### Host key handling

- `TestHostKeyCallback_NoCallbackAcceptsKey`
  - Verifies current behavior accepts host key when callback is missing.
  - Confirms insecure-default risk path is reachable.

- `TestHostKeyCallback_UserRejectsKey`
  - Verifies rejection callback fails connection with expected error.

- `TestAwaitPromise_TimesOut`
  - Verifies promise timeout path used by host-key verification wait logic.

### Tunnel parsing robustness

- `TestParseBinaryFrame_AdversarialCorpus_NoPanic`
  - Runs 10,000 pseudo-random payloads through parser.
  - Asserts invalid frames do not yield inconsistent payload state.

### Cleanup/race resilience

- `TestSessionClose_IdempotentUnderConcurrency`
  - Calls `session.close()` concurrently from 32 goroutines.
  - Asserts single `onClose` callback and session-store cleanup.

- `TestStreamCancel_ClosesAndRemovesState`
  - Verifies stream cancel closes file handle, closes done channel, and removes stream state.
  - Confirms repeated cancel call remains safe.

### SFTP path behavior

- `TestFileInfoToJS_PathIsNotNormalized`
  - Demonstrates path values are reflected without normalization.
  - Supports hardening recommendation for optional path-policy validation mode.

## Runtime Coverage Notes

- Existing tests in `gossh_test.go` continue to validate parser bounds and CRLF guard behavior.
- Full remote-server path traversal behavioral testing (real SFTP endpoint policy enforcement) is not covered in this repository-only harness and should be executed in integration E2E with controlled SSH/SFTP fixtures.

