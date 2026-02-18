// ssh.go implements SSH session management: connect, write, resize, disconnect.
// Each session is a complete SSH connection with its own WebSocket, PTY, and
// optional agent forwarding.

//go:build js && wasm

package gossh

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall/js"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// keepaliveInterval is the time between SSH keepalive pings.
	keepaliveInterval = 30 * time.Second
	// keepaliveTimeout is how long to wait for a keepalive response.
	keepaliveTimeout = 15 * time.Second
	// dialTimeout is the maximum time to establish a WebSocket connection.
	dialTimeout = 30 * time.Second
	// sshHandshakeTimeout is the maximum time for the SSH handshake.
	sshHandshakeTimeout = 30 * time.Second
)

// session holds all state for a single SSH connection.
type session struct {
	id         string
	ctx        context.Context
	cancel     context.CancelFunc
	conn       *wsConn
	sshClient  *ssh.Client
	sshSession *ssh.Session
	stdin      io.WriteCloser
	onData     js.Value // callback(Uint8Array)
	onClose    js.Value // callback(string)
	closeOnce  sync.Once
}

// sessionStore is the global map of active sessions, keyed by session ID.
var sessionStore sync.Map

// sshConnect establishes an SSH connection through a WebSocket proxy.
// Called from JS as: GoSSH.connect(config) → Promise<sessionId>
func sshConnect(config js.Value) js.Value {
	return newPromise(func() (any, error) {
		sessionID := generateID()

		proxyURL := jsString(config.Get("proxyUrl"))
		host := jsString(config.Get("host"))
		port := jsInt(config.Get("port"), 22)
		username := jsString(config.Get("username"))
		authMethod := jsString(config.Get("authMethod"))

		if proxyURL == "" || host == "" || username == "" {
			return nil, fmt.Errorf("connect: proxyUrl, host, and username are required")
		}

		// Build the WebSocket URL with target host info for the proxy.
		wsURL := fmt.Sprintf("%s?host=%s&port=%d", proxyURL, host, port)

		// Append JWT token if present in config.
		if token := jsString(config.Get("token")); token != "" {
			wsURL += "&token=" + token
		}

		// Establish WebSocket connection to proxy.
		dialCtx, dialCancel := context.WithTimeout(context.Background(), dialTimeout)
		defer dialCancel()

		netConn, err := DialWebSocket(dialCtx, wsURL)
		if err != nil {
			return nil, fmt.Errorf("connect: websocket dial: %w", err)
		}

		// Build SSH client config.
		sshConfig := &ssh.ClientConfig{
			User:            username,
			HostKeyCallback: makeHostKeyCallback(config),
			Timeout:         sshHandshakeTimeout,
		}

		// Configure authentication method.
		switch authMethod {
		case "password":
			password := jsString(config.Get("password"))
			if password == "" {
				netConn.Close()
				return nil, fmt.Errorf("connect: password required for password auth")
			}
			sshConfig.Auth = []ssh.AuthMethod{ssh.Password(password)}

		case "key":
			keyPEM := jsString(config.Get("keyPEM"))
			if keyPEM == "" {
				netConn.Close()
				return nil, fmt.Errorf("connect: keyPEM required for key auth")
			}
			signer, err := parsePrivateKey(keyPEM, jsString(config.Get("keyPassphrase")))
			if err != nil {
				netConn.Close()
				return nil, fmt.Errorf("connect: parse key: %w", err)
			}
			sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}

		case "agent":
			if globalAgent == nil {
				netConn.Close()
				return nil, fmt.Errorf("connect: no agent keys loaded")
			}
			sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeysCallback(globalAgent.Signers)}

		default:
			netConn.Close()
			return nil, fmt.Errorf("connect: unknown authMethod %q (use password, key, or agent)", authMethod)
		}

		// SSH handshake over the WebSocket connection.
		sshConn, chans, reqs, err := ssh.NewClientConn(netConn, fmt.Sprintf("%s:%d", host, port), sshConfig)
		if err != nil {
			netConn.Close()
			return nil, fmt.Errorf("connect: ssh handshake: %w", err)
		}

		sshClient := ssh.NewClient(sshConn, chans, reqs)

		// Set up agent forwarding if requested.
		if jsBool(config.Get("agentForward")) && globalAgent != nil {
			if err := agent.ForwardToAgent(sshClient, globalAgent); err != nil {
				// Non-fatal: log but continue without agent forwarding.
				_ = err
			}
		}

		// Open an SSH session for the terminal.
		sshSession, err := sshClient.NewSession()
		if err != nil {
			sshClient.Close()
			return nil, fmt.Errorf("connect: new session: %w", err)
		}

		// Request agent forwarding on the session if enabled.
		if jsBool(config.Get("agentForward")) && globalAgent != nil {
			_ = agent.RequestAgentForwarding(sshSession)
		}

		// Handle SSH banner.
		if onBanner, ok := getCallback(config, "onBanner"); ok {
			if banner := sshConn.ServerVersion(); len(banner) > 0 {
				onBanner.Invoke(maskControl(string(banner)))
			}
		}

		// Request PTY.
		cols := jsInt(config.Get("cols"), 80)
		rows := jsInt(config.Get("rows"), 24)

		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := sshSession.RequestPty("xterm-256color", rows, cols, modes); err != nil {
			sshSession.Close()
			sshClient.Close()
			return nil, fmt.Errorf("connect: request pty: %w", err)
		}

		// Set up stdin pipe.
		stdin, err := sshSession.StdinPipe()
		if err != nil {
			sshSession.Close()
			sshClient.Close()
			return nil, fmt.Errorf("connect: stdin pipe: %w", err)
		}

		// Set up stdout pipe.
		stdout, err := sshSession.StdoutPipe()
		if err != nil {
			sshSession.Close()
			sshClient.Close()
			return nil, fmt.Errorf("connect: stdout pipe: %w", err)
		}

		// Start shell.
		if err := sshSession.Shell(); err != nil {
			sshSession.Close()
			sshClient.Close()
			return nil, fmt.Errorf("connect: shell: %w", err)
		}

		// Create session context for lifecycle management.
		sessCtx, sessCancel := context.WithCancel(context.Background())

		sess := &session{
			id:         sessionID,
			ctx:        sessCtx,
			cancel:     sessCancel,
			conn:       netConn.(*wsConn),
			sshClient:  sshClient,
			sshSession: sshSession,
			stdin:      stdin,
			onData:     config.Get("onData"),
			onClose:    config.Get("onClose"),
		}

		sessionStore.Store(sessionID, sess)

		// Goroutine: read stdout and forward to JS onData callback.
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := stdout.Read(buf)
				if n > 0 {
					if onData, ok := getCallback(config, "onData"); ok {
						onData.Invoke(bytesToUint8Array(buf[:n]))
					}
				}
				if err != nil {
					break
				}
			}
			sess.close("session ended")
		}()

		// Goroutine: SSH keepalive.
		go func() {
			ticker := time.NewTicker(keepaliveInterval)
			defer ticker.Stop()
			for {
				select {
				case <-sessCtx.Done():
					return
				case <-ticker.C:
					_, _, err := sshClient.SendRequest("keepalive@openssh.com", true, nil)
					if err != nil {
						sess.close("keepalive failed")
						return
					}
				}
			}
		}()

		return sessionID, nil
	})
}

// sshWrite sends data to the SSH session's stdin.
// Called from JS as: GoSSH.write(sessionId, data: Uint8Array)
func sshWrite(sessionID string, data js.Value) {
	val, ok := sessionStore.Load(sessionID)
	if !ok {
		return
	}
	sess := val.(*session)
	_, _ = sess.stdin.Write(uint8ArrayToBytes(data))
}

// sshResize changes the PTY window size.
// Called from JS as: GoSSH.resize(sessionId, cols, rows)
func sshResize(sessionID string, cols, rows int) {
	val, ok := sessionStore.Load(sessionID)
	if !ok {
		return
	}
	sess := val.(*session)
	_ = sess.sshSession.WindowChange(rows, cols)
}

// sshDisconnect gracefully closes an SSH session.
// Called from JS as: GoSSH.disconnect(sessionId)
func sshDisconnect(sessionID string) {
	val, ok := sessionStore.Load(sessionID)
	if !ok {
		return
	}
	sess := val.(*session)
	sess.close("user disconnect")
}

// close shuts down a session and notifies JS via onClose callback.
// Safe to call multiple times — only the first call takes effect.
func (s *session) close(reason string) {
	s.closeOnce.Do(func() {
		s.cancel()

		if s.stdin != nil {
			s.stdin.Close()
		}
		if s.sshSession != nil {
			s.sshSession.Close()
		}
		if s.sshClient != nil {
			s.sshClient.Close()
		}
		if s.conn != nil {
			s.conn.Close()
		}

		sessionStore.Delete(s.id)

		// Notify JS.
		if !s.onClose.IsUndefined() && !s.onClose.IsNull() && s.onClose.Type() == js.TypeFunction {
			s.onClose.Invoke(reason)
		}
	})
}

// makeHostKeyCallback creates an SSH HostKeyCallback that delegates
// to a JS async function for user verification.
// The JS callback receives {hostname, fingerprint, keyType} and returns
// a Promise<boolean>. The Go goroutine blocks until the user decides.
func makeHostKeyCallback(config js.Value) ssh.HostKeyCallback {
	onHostKey, hasCallback := getCallback(config, "onHostKey")
	if !hasCallback {
		// If no callback provided, accept all host keys (insecure but
		// matches the "library doesn't store known_hosts" design).
		return ssh.InsecureIgnoreHostKey()
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		keyType := key.Type()

		// Create the info object for JS.
		info := map[string]any{
			"hostname":    hostname,
			"fingerprint": fingerprint,
			"keyType":     keyType,
		}

		// Call JS callback and await the Promise<boolean> result.
		promise := onHostKey.Invoke(info)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		result, err := awaitPromise(ctx, promise)
		if err != nil {
			return fmt.Errorf("host key verification failed: %w", err)
		}

		if !result.Bool() {
			return fmt.Errorf("host key rejected by user")
		}
		return nil
	}
}

// parsePrivateKey parses a PEM-encoded private key, optionally decrypting
// it with a passphrase.
func parsePrivateKey(keyPEM string, passphrase string) (ssh.Signer, error) {
	var signer ssh.Signer
	var err error

	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(keyPEM), []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(keyPEM))
	}
	if err != nil {
		return nil, err
	}
	return signer, nil
}

// generateID creates a unique session identifier using crypto/rand via JS.
func generateID() string {
	array := js.Global().Get("Uint8Array").New(16)
	js.Global().Get("crypto").Call("getRandomValues", array)
	bytes := make([]byte, 16)
	js.CopyBytesToGo(bytes, array)
	return fmt.Sprintf("%x", bytes)
}
