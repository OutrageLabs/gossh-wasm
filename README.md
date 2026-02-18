# gossh-wasm

Go SSH client compiled to WebAssembly — full SSH, SFTP, agent forwarding, and port forwarding in the browser.

All cryptography runs in the browser via `golang.org/x/crypto/ssh`. The proxy ([wsproxy](https://github.com/OutrageLabs/wsproxy)) only relays encrypted bytes — zero-knowledge architecture.

Security defaults:
- Host key verification is fail-closed by default (`onHostKey` required unless explicitly opting into insecure mode for development).
- `wss://` proxy URLs are required by default (`ws://` allowed only with explicit development override).
- Non-streaming SFTP upload/download APIs enforce 512MB limits; use streaming APIs for larger files.

## Features

- **SSH sessions** — connect, PTY, resize, keepalive, host key verification
- **SFTP** — list, upload, download, mkdir, remove, rename, chmod, progress callbacks
- **SSH agent** — in-memory keyring, agent forwarding to remote hosts
- **Port forwarding** — SSH direct-tcpip via tunnel WebSocket
- **Streaming downloads** — Service Worker-based streaming for large files (no memory buffering)
- **Jump hosts** — ProxyJump chains with per-hop authentication
- **Key formats** — RSA, Ed25519, ECDSA, OpenSSH format, passphrase-protected

## Architecture

```
┌──────────────────────────────────────────────┐
│  Browser (WASM)                              │
│                                              │
│  JS App ←→ GoSSH API ←→ golang.org/x/crypto │
│                  ↕                           │
│          WebSocket net.Conn adapter          │
└──────────────────┬───────────────────────────┘
                   │ wss://
                   ▼
          ┌────────────────┐
          │ wsproxy (relay)│     ← zero-knowledge
          └───────┬────────┘
                  │ TCP (encrypted SSH)
                  ▼
          ┌────────────────┐
          │ SSH Server     │
          └────────────────┘
```

## Quick Start

### Build

```bash
# Requires Go 1.21+
make build        # → gossh.wasm (7.7 MB)
make optimize     # → wasm-opt -Oz (requires binaryen)
```

### Usage

```html
<script src="wasm_exec.js"></script>
<script>
  const go = new Go();
  const { instance } = await WebAssembly.instantiateStreaming(
    fetch('gossh.wasm'), go.importObject
  );
  go.run(instance);

  // GoSSH is now available globally
  const sessionId = await GoSSH.connect({
    proxyUrl: 'wss://proxy.example.com/relay',
    host: '192.168.1.100',
    port: 22,
    username: 'admin',
    authMethod: 'password',
    password: 'secret',
    onData: (data) => terminal.write(data),
    onClose: (reason) => console.log('Disconnected:', reason),
    onHostKey: async (info) => confirm(`Trust ${info.fingerprint}?`),
  });

  // Send keystrokes
  GoSSH.write(sessionId, new TextEncoder().encode('ls\r'));

  // Resize terminal
  GoSSH.resize(sessionId, 120, 40);

  // Disconnect
  GoSSH.disconnect(sessionId);
</script>
```

## API Reference

### SSH Session

| Method | Signature | Description |
|--------|-----------|-------------|
| `connect` | `(config) → Promise<sessionId>` | Establish SSH connection |
| `write` | `(sessionId, data: Uint8Array)` | Send data to stdin |
| `resize` | `(sessionId, cols, rows)` | Change PTY size |
| `disconnect` | `(sessionId)` | Close connection |

**Connect config:**

```typescript
{
  proxyUrl: string;      // WebSocket proxy URL
  host: string;          // SSH server hostname
  port: number;          // SSH server port (default: 22)
  username: string;
  authMethod: 'password' | 'key' | 'agent';
  password?: string;
  keyPEM?: string;       // PEM-encoded private key
  keyPassphrase?: string;
  agentForward?: boolean;
  allowInsecureWS?: boolean;     // Dev only: allow ws:// proxy URL
  allowInsecureHostKey?: boolean;// Dev only: disable host key verification
  strictSFTPPaths?: boolean;     // Optional: enforce absolute, non-traversal SFTP paths
  cols?: number;         // Terminal columns (default: 80)
  rows?: number;         // Terminal rows (default: 24)
  token?: string;        // JWT for proxy auth
  onData: (data: Uint8Array) => void;
  onClose: (reason: string) => void;
  onHostKey: (info: HostKeyInfo) => Promise<boolean>; // required unless allowInsecureHostKey=true
  onBanner?: (banner: string) => void;
}
```

### SFTP

| Method | Signature |
|--------|-----------|
| `sftpOpen` | `(sessionId) → Promise<sftpId>` |
| `sftpClose` | `(sftpId)` |
| `sftpListDir` | `(sftpId, path) → Promise<FileInfo[]>` |
| `sftpStat` | `(sftpId, path) → Promise<FileInfo>` |
| `sftpMkdir` | `(sftpId, path) → Promise<void>` |
| `sftpRemove` | `(sftpId, path, recursive?) → Promise<void>` |
| `sftpRename` | `(sftpId, oldPath, newPath) → Promise<void>` |
| `sftpChmod` | `(sftpId, path, mode) → Promise<void>` |
| `sftpUpload` | `(sftpId, remotePath, data, onProgress?) → Promise<void>` |
| `sftpDownload` | `(sftpId, remotePath, onProgress?) → Promise<Uint8Array>` |
| `sftpDownloadStream` | `(sftpId, remotePath, onProgress?) → Promise<void>` |

### SSH Agent

| Method | Signature |
|--------|-----------|
| `agentAddKey` | `(keyPEM, passphrase?) → Promise<fingerprint>` |
| `agentRemoveAll` | `()` |
| `agentListKeys` | `() → KeyInfo[]` |

### Port Forwarding

| Method | Signature |
|--------|-----------|
| `portForwardStart` | `(sessionId, config) → Promise<TunnelInfo>` |
| `portForwardStop` | `(tunnelId)` |
| `portForwardList` | `(sessionId) → TunnelInfo[]` |

## Binary Size

| Build | Size |
|-------|------|
| Raw WASM | 7.7 MB |
| After `wasm-opt -Oz` | ~6.5 MB |
| Brotli compressed (served) | ~2 MB |

## Dependencies

- `golang.org/x/crypto/ssh` — SSH protocol
- `github.com/pkg/sftp` — SFTP protocol
- `golang.org/x/crypto/ssh/agent` — SSH agent

All are standard, widely-used Go libraries. No CGo, no niche dependencies.

## What This Library Does NOT Do

- **No UI** — no terminal emulator, no file manager. Just raw bytes in/out.
- **No key storage** — `agentAddKey` takes a PEM string, doesn't know where it came from.
- **No known hosts** — calls your `onHostKey` callback, doesn't store the decision.
- **No auth UI** — doesn't know about Clerk, OAuth, or any auth system.
- **No tab management** — returns `sessionId`, your app manages the map.

## License

MIT
