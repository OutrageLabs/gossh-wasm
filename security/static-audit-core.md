# Static Security Audit: Core Modules (2026-02-18)

## Files Reviewed

- `ssh.go`
- `transport.go`
- `portforward.go`
- `sftp.go`
- `sftp_transfer.go`
- `agent.go`
- `jsutil.go`

## Method

- Manual security review of entry points, parser paths, auth boundaries, memory usage paths, and lifecycle cleanup.
- Focused on attacker-controlled inputs crossing JS -> WASM, proxy -> WASM, and remote endpoint -> WASM boundaries.

## Findings

### Critical

#### C-01: Host key verification can be bypassed by default
- **Location**: `makeHostKeyCallback()` in `ssh.go`
- **What happens**: If `onHostKey` is absent, code returns `ssh.InsecureIgnoreHostKey()`.
- **Impact**: Enables transparent MITM if the integrating app forgets or misconfigures callback wiring.
- **Exploitability**: High in real deployments with integration mistakes.
- **Recommendation**: Fail closed by default (reject connection when callback is missing), with optional explicit insecure-dev override flag.

### High

#### H-01: Unbounded WebSocket message allocation in transport receive path
- **Location**: `onMessage` handler in `DialWebSocket()` (`transport.go`)
- **What happens**: Incoming `ArrayBuffer` is copied into a new Go slice with no max frame size enforcement.
- **Impact**: Proxy or peer can trigger large allocations and OOM/instability.
- **Exploitability**: High if attacker can influence proxy traffic or if proxy is compromised.
- **Recommendation**: Enforce max WS frame size before copy; close connection on violation.

#### H-02: HTTP request-line fields are forwarded without strict validation
- **Location**: `handleHTTPRequest()` in `portforward.go`
- **What happens**: `method` and `path` are inserted into `fmt.Sprintf("%s %s HTTP/1.1\r\n...")` without explicit token/path validation.
- **Impact**: Under compromised proxy/control-channel conditions, malformed values can alter forwarded request semantics.
- **Exploitability**: High against trust-compromised tunnel input.
- **Recommendation**: Validate method token (`^[A-Z]+$`), reject CTL/CR/LF in method/path, normalize/sanitize path.

#### H-03: In-memory upload path copies full payload with no size cap
- **Location**: `sftpUpload()` in `sftp_transfer.go`
- **What happens**: Entire JS `Uint8Array` is copied to Go memory before write loop.
- **Impact**: Large uploads can exhaust WASM memory (DoS).
- **Exploitability**: High (caller-controlled payload size).
- **Recommendation**: Introduce hard max upload size for this API and steer large uploads to streaming upload API.

### Medium

#### M-01: Hop-by-hop header stripping is case-sensitive
- **Location**: `handleHTTPRequest()` header filtering in `portforward.go`
- **What happens**: Strips only exact-case header names (`Host`, `Connection`, etc.).
- **Impact**: Alternate casing can bypass filter and forward undesirable hop/proxy headers.
- **Exploitability**: Medium.
- **Recommendation**: Normalize header names to lower-case before filtering.

#### M-02: Channel backpressure can block forwarding/transport loops
- **Location**: `transport.go` (`readCh` send), `portforward.go` (`tcpChans` send path)
- **What happens**: Blocking sends can stall goroutines when buffers saturate under burst traffic.
- **Impact**: Connection stalls and DoS under load/malicious flood.
- **Exploitability**: Medium.
- **Recommendation**: Add bounded non-blocking/drop/close strategy with telemetry when buffers overflow.

#### M-03: Sensitive credential material is not explicitly zeroized
- **Location**: `parsePrivateKey()` (`ssh.go`), `agentAddKey()` (`agent.go`)
- **What happens**: Password/passphrase/key byte material remains in managed memory until GC.
- **Impact**: Longer exposure window in memory snapshots or post-compromise analysis.
- **Exploitability**: Medium (post-compromise).
- **Recommendation**: Minimize lifetime, clear temporary byte slices where practical, document residual WASM memory constraints.

#### M-04: Detailed transport errors are returned to JS callers
- **Location**: multiple `fmt.Errorf("...: %w", err)` paths in `ssh.go`, `portforward.go`
- **What happens**: Raw underlying error strings are surfaced to caller.
- **Impact**: Potential disclosure of internal network/transport details.
- **Exploitability**: Medium.
- **Recommendation**: Return user-safe error classes/messages and keep verbose details behind debug flag/log channel.

#### M-05: SFTP path policy is entirely delegated to remote server
- **Location**: path-taking APIs in `sftp.go` and `sftp_transfer.go`
- **What happens**: No local policy checks for dangerous path patterns (`..`, empty, unexpected absolute path).
- **Impact**: Integrator may assume local policy guard that does not exist.
- **Exploitability**: Medium depending on product assumptions.
- **Recommendation**: Add optional strict path-policy mode and document default behavior explicitly.

#### M-06: Proxy URL scheme is not explicitly restricted
- **Location**: URL parse/build in `ssh.go`, `portforward.go`
- **What happens**: Code parses URL but does not enforce `wss://` (or at least `ws://`/`wss://`) policy.
- **Impact**: Misconfiguration may allow insecure transport in production contexts.
- **Exploitability**: Medium via misconfiguration.
- **Recommendation**: Validate scheme, require `wss` by default with explicit dev override.

#### M-07: `keyBits()` uses unchecked type assertion
- **Location**: `keyBits()` in `agent.go`
- **What happens**: `pubKey.(ssh.CryptoPublicKey)` can panic if unexpected key implementation appears.
- **Impact**: Stability/availability issue, potential crash.
- **Exploitability**: Medium-low.
- **Recommendation**: Use checked assertion and fallback.

### Low

#### L-01: HTTP response parsing is intentionally minimal and can mis-handle edge protocols
- **Location**: `handleHTTPRequest()` in `portforward.go`
- **What happens**: Custom parser does not fully handle all HTTP framing edge cases.
- **Impact**: Reliability issues and potential response misinterpretation.
- **Exploitability**: Low security impact, higher correctness impact.
- **Recommendation**: Consider robust parser framing or tighter protocol assumptions in docs/tests.

#### L-02: Write errors from tunnel response helpers are ignored
- **Location**: `sendHTTPResponse()`, `sendTCPClose()` in `portforward.go`
- **What happens**: `Write` return values/errors are discarded.
- **Impact**: Silent failures reduce observability and recovery quality.
- **Exploitability**: Low (availability/diagnostics).
- **Recommendation**: Capture and act on write errors (metrics, cleanup, debug callbacks).

## Positive Security Controls Noted

- CRLF header injection guard (`containsCRLF`) in forwarding path.
- Size limits in key areas:
  - 1 MB cap for tunnel-ready JSON decode.
  - 10 MB cap for forwarded HTTP response body.
  - 512 MB cap for in-memory `sftpDownload`.
- Symlink-aware recursive delete (`Lstat`) to avoid following symlink targets.
- Promise wait timeout in host-key callback path (`awaitPromise` + context timeout).
- Cleanup idempotence patterns (`sync.Once`) for session/forward/stream lifecycles.

## Recommended Fix Priority

1. C-01 immediately (host key fail-closed default).
2. H-01/H-03 next (memory DoS hardening).
3. H-02 and M-01 together (forwarding input hardening).
4. M-03/M-04/M-06 for production hardening baseline.

