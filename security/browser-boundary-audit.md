# Browser Boundary Security Audit (2026-02-18)

## Scope

- `main.go` (public JS API registration and internal stream API exposure)
- `stream_worker.js` (stream fetch interception and worker-side pull flow)
- `stream_helper.js` (page-side worker bridge and fallback path)

## Boundary Model

Security depends on same-origin integrity of the embedding app. `gossh-wasm` assumes:
- trusted first-party JS initializes and calls APIs correctly,
- no XSS or hostile same-origin third-party script can invoke exported APIs,
- Service Worker messaging is not spoofed by untrusted origins.

If those assumptions fail, confidentiality/integrity of in-browser SSH operations is also at risk.

## Findings

### Medium

#### B-01: Internal stream control methods are publicly exposed
- **Location**: `_streamPull` and `_streamCancel` in `RegisterAPI()` (`main.go`)
- **Risk**: Any same-origin script can invoke stream internals.
- **Impact**: Stream disruption (`_streamCancel`) or unauthorized chunk pulling if stream IDs are known.
- **Notes**: Stream IDs are high entropy, which reduces blind guessing risk.
- **Recommendation**: Keep methods private to internal bridge where possible, or enforce stream ownership/session token checks.

#### B-02: Service Worker fallback client selection can weaken tab isolation on older behavior paths
- **Location**: `getSourceClient()` fallback in `stream_worker.js`
- **Risk**: If `clientId` is unavailable, worker picks first window client.
- **Impact**: Potential wrong-tab routing in corner cases.
- **Recommendation**: Require `clientId` for stream pulls when available; fail closed when absent unless explicit compatibility mode is enabled.

#### B-03: Download trigger event is globally observable in page context
- **Location**: `dispatchEvent("gossh-stream-download", detail)` in `sftp_transfer.go` consumed by `stream_helper.js`
- **Risk**: Any page script can observe event metadata (`streamId`, filename, size).
- **Impact**: In compromised same-origin script contexts, active stream metadata can be abused.
- **Recommendation**: Treat as expected under XSS threat model and document clearly; optionally avoid broadcasting on `window` and use scoped callback wiring.

### Low

#### B-04: Service Worker is registered at broad scope (`/`)
- **Location**: `register('/stream_worker.js', { scope: '/' })` in `stream_helper.js`
- **Risk**: Worker controls broad URL space if application has unexpected route overlaps.
- **Impact**: Operational hardening concern, not direct exploit by itself.
- **Recommendation**: Support configurable scope and default to narrow path where possible.

#### B-05: Blob fallback reintroduces high-memory download behavior
- **Location**: fallback branch in `stream_helper.js`
- **Risk**: Large file downloads in fallback mode can consume significant browser memory.
- **Impact**: Availability degradation.
- **Recommendation**: Add configurable size guard to reject or warn for large fallback downloads.

## Positive Controls

- `stream_worker.js` sanitizes filename for `Content-Disposition` header injection defense.
- Pull requests use `MessageChannel` and explicit timeout (`30s`) in worker pull path.
- Worker uses `event.clientId` targeting when available, improving multi-tab safety.

## Abuse Test Scenarios To Include

1. Attempt forced `_streamCancel` from non-owner script context.
2. Trigger many synthetic `gossh-stream-download` events and verify no unexpected stream leakage.
3. Validate behavior when worker receives pull for nonexistent stream ID.
4. Validate fallback memory behavior with large files when Service Worker registration fails.

