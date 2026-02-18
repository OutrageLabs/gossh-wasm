/**
 * Type definitions for gossh-wasm.
 *
 * After loading the WASM binary, the GoSSH object is available
 * on the global window object.
 *
 * Usage:
 *   /// <reference path="./gossh.d.ts" />
 *   const sessionId = await GoSSH.connect({ ... });
 */

interface GoSSHAPI {
  // ──── SSH Session ────

  /** Establish an SSH connection through a WebSocket proxy. */
  connect(config: SSHConnectConfig): Promise<string>;

  /** Send data to the SSH session's stdin. */
  write(sessionId: string, data: Uint8Array): void;

  /** Change the PTY window size. */
  resize(sessionId: string, cols: number, rows: number): void;

  /** Gracefully close an SSH session. */
  disconnect(sessionId: string): void;

  // ──── SSH Agent ────

  /** Add a PEM-encoded private key to the in-memory agent. Returns fingerprint. */
  agentAddKey(keyPEM: string, passphrase?: string): Promise<string>;

  /** Remove all keys from the agent. */
  agentRemoveAll(): void;

  /** List all keys in the agent. */
  agentListKeys(): KeyInfo[];

  // ──── SFTP ────

  /** Open an SFTP subsystem on an existing SSH session. */
  sftpOpen(sessionId: string): Promise<string>;

  /** Close an SFTP session. */
  sftpClose(sftpId: string): void;

  /** List directory contents. */
  sftpListDir(sftpId: string, path: string): Promise<FileInfo[]>;

  /** Get file info for a single path. */
  sftpStat(sftpId: string, path: string): Promise<FileInfo>;

  /** Create a remote directory (recursive). */
  sftpMkdir(sftpId: string, path: string): Promise<void>;

  /** Remove a file or directory. */
  sftpRemove(sftpId: string, path: string, recursive?: boolean): Promise<void>;

  /** Rename/move a file or directory. */
  sftpRename(sftpId: string, oldPath: string, newPath: string): Promise<void>;

  /** Change file permissions. */
  sftpChmod(sftpId: string, path: string, mode: number): Promise<void>;

  /**
   * Upload data to a remote file.
   * @param onProgress - Called with (bytesWritten, totalBytes)
   */
  sftpUpload(
    sftpId: string,
    remotePath: string,
    data: Uint8Array,
    onProgress?: (bytes: number, total: number) => void
  ): Promise<void>;

  /**
   * Download a remote file into memory.
   * For files > 100MB, use sftpDownloadStream instead.
   * @param onProgress - Called with (bytesRead, totalBytes)
   */
  sftpDownload(
    sftpId: string,
    remotePath: string,
    onProgress?: (bytes: number, total: number) => void
  ): Promise<Uint8Array>;

  /**
   * Download a remote file via Service Worker streaming.
   * Triggers a browser download without buffering the entire file in WASM memory.
   * Requires stream_worker.js and stream_helper.js to be loaded.
   * @param onProgress - Called with (bytesRead, totalBytes)
   */
  sftpDownloadStream(
    sftpId: string,
    remotePath: string,
    onProgress?: (bytes: number, total: number) => void
  ): Promise<void>;

  // ──── Port Forwarding ────

  /**
   * Start a port forward through an SSH session.
   * Opens an SSH direct-tcpip channel and connects to the proxy's tunnel endpoint.
   */
  portForwardStart(
    sessionId: string,
    config: PortForwardConfig
  ): Promise<TunnelInfo>;

  /** Stop an active port forward. */
  portForwardStop(tunnelId: string): void;

  /** List all active port forwards for a session. */
  portForwardList(sessionId: string): TunnelInfo[];

  // ──── Internal (used by Service Worker) ────

  /** @internal Pull next chunk for streaming download. */
  _streamPull(streamId: string): { data: Uint8Array | null; done: boolean };

  /** @internal Cancel a streaming download. */
  _streamCancel(streamId: string): void;
}

interface SSHConnectConfig {
  /** WebSocket proxy URL (e.g., wss://proxy.example.com/relay) */
  proxyUrl: string;
  /** SSH server hostname or IP */
  host: string;
  /** SSH server port (default: 22) */
  port?: number;
  /** SSH username */
  username: string;
  /** Authentication method */
  authMethod: 'password' | 'key' | 'agent';
  /** Password for password auth */
  password?: string;
  /** PEM-encoded private key for key auth */
  keyPEM?: string;
  /** Passphrase for encrypted private key */
  keyPassphrase?: string;
  /** Enable SSH agent forwarding */
  agentForward?: boolean;
  /** Terminal columns (default: 80) */
  cols?: number;
  /** Terminal rows (default: 24) */
  rows?: number;
  /** JWT token for proxy authentication */
  token?: string;

  /** Called with terminal output data */
  onData: (data: Uint8Array) => void;
  /** Called when the connection closes */
  onClose: (reason: string) => void;
  /**
   * Called for host key verification.
   * Return true to accept the key, false to reject.
   */
  onHostKey?: (info: HostKeyInfo) => Promise<boolean>;
  /** Called with the SSH server banner */
  onBanner?: (banner: string) => void;
}

interface HostKeyInfo {
  hostname: string;
  /** SHA256 fingerprint (e.g., SHA256:xxx...) */
  fingerprint: string;
  /** Key type (e.g., ssh-ed25519, ssh-rsa) */
  keyType: string;
}

interface FileInfo {
  name: string;
  path: string;
  /** File size in bytes */
  size: number;
  isDir: boolean;
  isSymlink: boolean;
  /** Permission string (e.g., "rwxr-xr-x") */
  permissions: string;
  /** Last modification time in Unix milliseconds */
  modTime: number;
}

interface KeyInfo {
  /** SHA256 fingerprint */
  fingerprint: string;
  /** Key type (e.g., ssh-ed25519) */
  type: string;
  /** Key comment */
  comment: string;
}

interface PortForwardConfig {
  /** Remote host to forward to (e.g., localhost) */
  remoteHost: string;
  /** Remote port to forward to (e.g., 3000) */
  remotePort: number;
  /** WebSocket URL for proxy tunnel endpoint */
  proxyTunnelUrl: string;
  /** JWT token for proxy auth */
  token?: string;
}

interface TunnelInfo {
  id: string;
  remoteHost: string;
  remotePort: number;
  /** Public URL for the tunnel (e.g., https://abc123.tunnel.example.com) */
  tunnelUrl: string;
  /** Raw TCP port allocated by the proxy (0 if unavailable) */
  rawPort: number;
  active: boolean;
}

declare const GoSSH: GoSSHAPI;
