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
	"net/url"
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

	// Jump host resources (non-nil if ProxyJump was used).
	jumpConn   *wsConn
	jumpClient *ssh.Client
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

		if proxyURL == "" || host == "" || username == "" {
			return nil, fmt.Errorf("connect: proxyUrl, host, and username are required")
		}

		// Build auth methods for the final host.
		authMethods, err := buildAuthMethods(config)
		if err != nil {
			return nil, fmt.Errorf("connect: %w", err)
		}

		// Determine the transport: direct WS or through a jump host.
		var netConn net.Conn
		var jumpConn *wsConn
		var jumpClient *ssh.Client

		jumpConfig := config.Get("jumpHost")
		hasJump := !jumpConfig.IsUndefined() && !jumpConfig.IsNull()

		if hasJump {
			// Jump host (ProxyJump) — connect to bastion first, then tunnel through.
			jumpHost := jsString(jumpConfig.Get("host"))
			jumpPort := jsInt(jumpConfig.Get("port"), 22)
			jumpUser := jsString(jumpConfig.Get("username"))
			if jumpHost == "" || jumpUser == "" {
				return nil, fmt.Errorf("connect: jumpHost requires host and username")
			}

			jumpAuth, err := buildAuthMethods(jumpConfig)
			if err != nil {
				return nil, fmt.Errorf("connect: jump host: %w", err)
			}

			// Build WS URL for jump host.
			u, err := url.Parse(proxyURL)
			if err != nil {
				return nil, fmt.Errorf("connect: invalid proxyUrl: %w", err)
			}
			q := u.Query()
			q.Set("host", jumpHost)
			q.Set("port", fmt.Sprintf("%d", jumpPort))
			if token := jsString(config.Get("token")); token != "" {
				q.Set("token", token)
			}
			u.RawQuery = q.Encode()

			dialCtx, dialCancel := context.WithTimeout(context.Background(), dialTimeout)
			defer dialCancel()

			jConn, err := DialWebSocket(dialCtx, u.String())
			if err != nil {
				return nil, fmt.Errorf("connect: jump host websocket: %w", err)
			}
			jumpConn = jConn.(*wsConn)

			jSSHConfig := &ssh.ClientConfig{
				User:            jumpUser,
				Auth:            jumpAuth,
				HostKeyCallback: makeHostKeyCallback(jumpConfig),
				Timeout:         sshHandshakeTimeout,
			}

			jSSHConn, jChans, jReqs, err := ssh.NewClientConn(jConn, fmt.Sprintf("%s:%d", jumpHost, jumpPort), jSSHConfig)
			if err != nil {
				jConn.Close()
				return nil, fmt.Errorf("connect: jump host ssh handshake: %w", err)
			}
			jumpClient = ssh.NewClient(jSSHConn, jChans, jReqs)

			// Tunnel through jump host to final destination.
			netConn, err = jumpClient.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
			if err != nil {
				jumpClient.Close()
				return nil, fmt.Errorf("connect: jump host tunnel to %s:%d: %w", host, port, err)
			}
		} else {
			// Direct connection through WebSocket proxy.
			u, err := url.Parse(proxyURL)
			if err != nil {
				return nil, fmt.Errorf("connect: invalid proxyUrl: %w", err)
			}
			q := u.Query()
			q.Set("host", host)
			q.Set("port", fmt.Sprintf("%d", port))
			if token := jsString(config.Get("token")); token != "" {
				q.Set("token", token)
			}
			u.RawQuery = q.Encode()

			dialCtx, dialCancel := context.WithTimeout(context.Background(), dialTimeout)
			defer dialCancel()

			netConn, err = DialWebSocket(dialCtx, u.String())
			if err != nil {
				return nil, fmt.Errorf("connect: websocket dial: %w", err)
			}
		}

		// Build SSH client config for the final host.
		sshConfig := &ssh.ClientConfig{
			User:            username,
			Auth:            authMethods,
			HostKeyCallback: makeHostKeyCallback(config),
			Timeout:         sshHandshakeTimeout,
		}

		// SSH handshake over the transport (direct WS or tunneled through jump host).
		sshConn, chans, reqs, err := ssh.NewClientConn(netConn, fmt.Sprintf("%s:%d", host, port), sshConfig)
		if err != nil {
			netConn.Close()
			if jumpClient != nil {
				jumpClient.Close()
			}
			return nil, fmt.Errorf("connect: ssh handshake: %w", err)
		}

		sshClient := ssh.NewClient(sshConn, chans, reqs)

		// Set up agent forwarding if requested.
		if jsBool(config.Get("agentForward")) && globalAgent != nil {
			if err := agent.ForwardToAgent(sshClient, globalAgent); err != nil {
				js.Global().Get("console").Call("warn",
					"[gossh] Agent forwarding setup failed:", err.Error())
			} else {
				js.Global().Get("console").Call("info",
					"[gossh] SSH agent forwarding enabled — the remote server can use your keys to connect to other servers.")
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

		// conn may be a *wsConn (direct) or nil (jump host — cleanup via jumpConn).
		var wsC *wsConn
		if wc, ok := netConn.(*wsConn); ok {
			wsC = wc
		}

		sess := &session{
			id:         sessionID,
			ctx:        sessCtx,
			cancel:     sessCancel,
			conn:       wsC,
			sshClient:  sshClient,
			sshSession: sshSession,
			stdin:      stdin,
			onData:     config.Get("onData"),
			onClose:    config.Get("onClose"),
			jumpConn:   jumpConn,
			jumpClient: jumpClient,
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

		// Goroutine: SSH keepalive with backoff.
		go func() {
			ticker := time.NewTicker(keepaliveInterval)
			defer ticker.Stop()
			failures := 0
			const maxFailures = 3
			for {
				select {
				case <-sessCtx.Done():
					return
				case <-ticker.C:
					_, _, err := sshClient.SendRequest("keepalive@openssh.com", true, nil)
					if err != nil {
						failures++
						if failures >= maxFailures {
							sess.close("keepalive failed after 3 attempts")
							return
						}
						continue
					}
					failures = 0
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

		// Clean up any SFTP sessions tied to this SSH session.
		sftpStore.Range(func(key, val any) bool {
			ss := val.(*sftpSession)
			if ss.sessionID == s.id {
				ss.client.Close()
				sftpStore.Delete(key)
			}
			return true
		})

		// Clean up any port forwards tied to this SSH session.
		forwardStore.Range(func(key, val any) bool {
			fwd := val.(*portForward)
			if fwd.sessionID == s.id {
				fwd.cleanup() // Uses cleanupOnce — safe to call even if handleTunnelMessages defer also calls it.
			}
			return true
		})

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

		// Clean up jump host resources.
		if s.jumpClient != nil {
			s.jumpClient.Close()
		}
		if s.jumpConn != nil {
			s.jumpConn.Close()
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
		// WARNING: Accepting all host keys makes the connection vulnerable to MITM.
		// Callers SHOULD provide onHostKey for production use.
		js.Global().Get("console").Call("warn",
			"[gossh] No onHostKey callback provided — accepting all host keys. "+
				"This is insecure and vulnerable to MITM attacks. "+
				"Provide onHostKey in your connect config for production use.")
		return ssh.InsecureIgnoreHostKey()
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		keyType := key.Type()

		// Create the info object for JS.
		info := map[string]any{
			"hostname":       hostname,
			"fingerprint":    fingerprint,
			"fingerprintMD5": ssh.FingerprintLegacyMD5(key),
			"keyType":        keyType,
			"randomArt":      RandomArt(key),
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

// buildAuthMethods constructs SSH auth methods from a JS config object.
func buildAuthMethods(config js.Value) ([]ssh.AuthMethod, error) {
	authMethod := jsString(config.Get("authMethod"))
	switch authMethod {
	case "password":
		password := jsString(config.Get("password"))
		if password == "" {
			return nil, fmt.Errorf("password required for password auth")
		}
		return []ssh.AuthMethod{ssh.Password(password)}, nil

	case "key":
		keyPEM := jsString(config.Get("keyPEM"))
		if keyPEM == "" {
			return nil, fmt.Errorf("keyPEM required for key auth")
		}
		signer, err := parsePrivateKey(keyPEM, jsString(config.Get("keyPassphrase")))
		if err != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil

	case "agent":
		if globalAgent == nil {
			return nil, fmt.Errorf("no agent keys loaded")
		}
		return []ssh.AuthMethod{ssh.PublicKeysCallback(globalAgent.Signers)}, nil

	default:
		return nil, fmt.Errorf("unknown authMethod %q (use password, key, or agent)", authMethod)
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
