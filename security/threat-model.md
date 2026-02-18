# gossh-wasm Threat Model (2026-02-18)

## System Summary

`gossh-wasm` is a browser-executed SSH client runtime (Go WASM) that exposes APIs for SSH terminal access, SFTP, SSH agent forwarding, and proxy-mediated port forwarding.

Primary data path:
- Browser JS app -> `window.GoSSH` (`main.go`)
- Go WASM SSH stack (`ssh.go`, `transport.go`, `agent.go`, `sftp.go`, `sftp_transfer.go`, `portforward.go`)
- WebSocket relay/proxy (external system)
- SSH server / forwarded remote services

## Security Objectives

1. Preserve confidentiality and integrity of SSH credentials, private keys, and session traffic.
2. Prevent host impersonation (MITM) during SSH handshake.
3. Prevent command/data injection across tunnel/HTTP bridging boundaries.
4. Bound memory, CPU, and goroutine growth under malformed/untrusted inputs.
5. Ensure predictable cleanup and session teardown on disconnect/failure/cancel.

## Assets

- SSH passwords and key passphrases (`ssh.go`)
- Private key material and signers (`agent.go`, `ssh.go`)
- SSH session state and stream data (`ssh.go`, `transport.go`)
- SFTP file content and metadata (`sftp.go`, `sftp_transfer.go`)
- Port-forward tunnel data and request metadata (`portforward.go`)
- Stream IDs and download channels (`sftp_transfer.go`, `stream_worker.js`, `stream_helper.js`)

## Threat Actors

- Network adversary between browser and proxy endpoint.
- Malicious or compromised proxy endpoint.
- Malicious SSH server (banner/host key/content manipulation).
- Malicious external tunnel client (untrusted traffic entering forwarded paths).
- Malicious script running in same origin (XSS or compromised app dependency).
- Legitimate but abusive user causing resource exhaustion.

## Trust Boundaries

1. **App JS -> Go WASM API**
   - Entry point: `RegisterAPI()` in `main.go`.
   - Risk: untrusted/invalid argument types, malformed callback contracts.

2. **Go WASM -> WebSocket transport**
   - Entry point: `DialWebSocket()` in `transport.go`.
   - Risk: unbounded frame ingestion, lifecycle misuse, degraded reliability causing resource retention.

3. **Proxy tunnel control/data -> forwarding handlers**
   - Entry point: `handleTunnelMessages()` in `portforward.go`.
   - Risk: parser confusion, malformed frames, concurrent request flood, header/value injection.

4. **Service Worker <-> page message bridge**
   - Entry points: `stream_worker.js`, `stream_helper.js`, `_streamPull/_streamCancel` in `main.go` + `sftp_transfer.go`.
   - Risk: spoofed or replayed stream pulls, cancellation race behavior, client routing confusion.

5. **SSH server identity/user trust decision**
   - Entry point: `makeHostKeyCallback()` in `ssh.go`.
   - Risk: trust downgrade if host key verification callback is missing or bypassed.

## Assumptions

- Browser TLS and Web Crypto primitives are not compromised.
- Hosting application controls origin security and XSS defenses.
- Proxy enforces its own authentication/authorization and target restrictions.
- Remote SSH/SFTP endpoints may be untrusted and are treated as attacker-controlled input sources.

## Non-Goals

- Endpoint hardening of external proxy implementation (not in this repository).
- UI-level anti-phishing or credential UX (library has no UI).
- Persistent key/known-host storage policy (owned by integrating app).

## Key Abuse Cases

1. Connect without host-key callback and silently accept attacker host key.
2. Flood tunnel with control/data messages to exhaust goroutines/channels.
3. Inject CRLF or malformed headers through HTTP forwarding bridge.
4. Push large or malformed WS/tunnel frames to trigger memory growth.
5. Abuse SFTP operations for path misuse or recursive delete surprises.
6. Keep secrets in WASM memory longer than required (post-auth/post-parse exposure).
7. Trigger stream pull/cancel races to leak resources or hang operations.

## Required Security Invariants (Release Gate Candidates)

1. Host key validation must be fail-closed in production mode (no implicit `InsecureIgnoreHostKey` path).
2. All protocol parsers must enforce strict size and shape bounds.
3. Forwarding bridge must sanitize request/response metadata crossing protocols.
4. Maximum concurrency and payload limits must exist and be tested for tunnel operations.
5. Secret-bearing buffers should be minimized in lifetime and, where feasible, cleared after use.
6. Public API entry points must reject invalid argument shapes safely.
7. Session/SFTP/forward/stream state must cleanly teardown on disconnect/cancel/error.

## Security-Critical Modules

- `ssh.go`: authentication, host key verification, session lifecycle.
- `agent.go`: key parsing and in-memory keyring behavior.
- `transport.go`: browser WebSocket `net.Conn` adapter.
- `portforward.go`: tunnel control protocol, HTTP/TCP bridging, parsing.
- `sftp.go` + `sftp_transfer.go`: remote file ops, transfer bounds, stream lifecycles.
- `stream_worker.js` + `stream_helper.js`: browser messaging and streaming download bridge.
- `jsutil.go` + `main.go`: JS callback validation and API boundary behaviors.

## Security Posture Snapshot (Pre-Remediation)

Strengths:
- Bounded limits in multiple hot paths (for example 1 MB ready-message decode, 10 MB HTTP response cap, download size cap).
- CRLF header injection guard present in forwarding path.
- Symlink-safe recursive delete logic via `Lstat`.
- Timeout handling in key dial/handshake/stream operations.

High concern:
- Insecure host key fallback when no callback is provided.
- Error messages that may expose internal transport/connect details.
- Limited hard controls around input/path policy and origin/channel validation assumptions.

