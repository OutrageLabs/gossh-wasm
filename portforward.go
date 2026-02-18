// portforward.go implements SSH local port forwarding (-L) adapted for browsers.
//
// In a native SSH client, port forwarding opens a local TCP listener.
// In the browser, there's no TCP listener — instead, we open an SSH
// direct-tcpip channel and a second WebSocket to the proxy's /tunnel
// endpoint. The proxy provides a public subdomain URL and optional raw
// TCP port. External clients connect to the subdomain, and traffic
// flows: Client → Proxy → WS → Browser WASM → SSH → Remote Service.

//go:build js && wasm

package gossh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// maxConcurrentHandlers limits goroutines per tunnel to prevent OOM.
	maxConcurrentHandlers = 100
)

// portForward represents an active port forwarding tunnel.
type portForward struct {
	id         string
	sessionID  string
	remoteHost string
	remotePort int
	tunnelURL  string
	rawPort    int
	ctx        context.Context
	cancel     context.CancelFunc
	tunnelConn net.Conn // WebSocket to proxy /tunnel endpoint

	// wsMu serializes writes to tunnelConn (concurrent goroutines write frames).
	wsMu sync.Mutex

	// sem limits concurrent http_request/tcp_open goroutines.
	sem chan struct{}

	// cleanupOnce ensures cleanup() is idempotent (called from defer + portForwardStop + session.close).
	cleanupOnce sync.Once

	// tcpChans dispatches incoming binary frames to the right TCP connection.
	tcpChans sync.Map // connID → chan []byte
}

// forwardStore tracks active port forwards.
var forwardStore sync.Map

// portForwardStart initiates a port forward through an SSH session.
// Called from JS as:
//
//	GoSSH.portForwardStart(sessionId, config) → Promise<TunnelInfo>
//
// Config: { remoteHost, remotePort, proxyTunnelUrl, token? }
func portForwardStart(sessionID string, config js.Value) js.Value {
	return newPromise(func() (any, error) {
		val, ok := sessionStore.Load(sessionID)
		if !ok {
			return nil, fmt.Errorf("portForwardStart: session %q not found", sessionID)
		}
		sess := val.(*session)

		remoteHost := jsString(config.Get("remoteHost"))
		remotePort := jsInt(config.Get("remotePort"), 0)
		proxyTunnelURL := jsString(config.Get("proxyTunnelUrl"))

		if remoteHost == "" || remotePort == 0 || proxyTunnelURL == "" {
			return nil, fmt.Errorf("portForwardStart: remoteHost, remotePort, and proxyTunnelUrl required")
		}
		if remotePort < 1 || remotePort > 65535 {
			return nil, fmt.Errorf("portForwardStart: invalid remotePort %d (must be 1-65535)", remotePort)
		}

		// Build tunnel WebSocket URL with properly encoded query parameters.
		u, err := url.Parse(proxyTunnelURL)
		if err != nil {
			return nil, fmt.Errorf("portForwardStart: invalid proxyTunnelUrl: %w", err)
		}
		if token := jsString(config.Get("token")); token != "" {
			q := u.Query()
			q.Set("token", token)
			u.RawQuery = q.Encode()
		}
		tunnelWsURL := u.String()

		// Connect to proxy tunnel endpoint.
		ctx, cancel := context.WithCancel(sess.ctx)

		tunnelConn, err := DialWebSocket(ctx, tunnelWsURL)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("portForwardStart: dial tunnel: %w", err)
		}

		// Read tunnel_ready message from proxy.
		// Use json.NewDecoder to handle messages of any size without a fixed buffer,
		// with a 1 MB LimitReader to prevent OOM from a malicious proxy.
		var ready struct {
			Type      string `json:"type"`
			TunnelURL string `json:"tunnelUrl"`
			RawPort   int    `json:"rawPort"`
		}
		if err := json.NewDecoder(io.LimitReader(tunnelConn, 1<<20)).Decode(&ready); err != nil {
			tunnelConn.Close()
			cancel()
			return nil, fmt.Errorf("portForwardStart: parse tunnel_ready: %w", err)
		}
		if ready.Type != "tunnel_ready" {
			tunnelConn.Close()
			cancel()
			return nil, fmt.Errorf("portForwardStart: expected tunnel_ready, got %q", ready.Type)
		}

		forwardID := generateID()
		fwd := &portForward{
			id:         forwardID,
			sessionID:  sessionID,
			remoteHost: remoteHost,
			remotePort: remotePort,
			tunnelURL:  ready.TunnelURL,
			rawPort:    ready.RawPort,
			ctx:        ctx,
			cancel:     cancel,
			tunnelConn: tunnelConn,
			sem:        make(chan struct{}, maxConcurrentHandlers),
		}

		forwardStore.Store(forwardID, fwd)

		// Start goroutine to handle incoming tunnel messages.
		go fwd.handleTunnelMessages(sess)

		result := map[string]any{
			"id":         forwardID,
			"remoteHost": remoteHost,
			"remotePort": remotePort,
			"tunnelUrl":  ready.TunnelURL,
			"rawPort":    ready.RawPort,
			"active":     true,
		}
		return js.ValueOf(result), nil
	})
}

// handleTunnelMessages reads control messages from the proxy tunnel WebSocket
// and forwards traffic through SSH direct-tcpip channels.
// Binary frames (TCP data) are dispatched to the appropriate connection by connID.
func (fwd *portForward) handleTunnelMessages(sess *session) {
	defer fwd.cleanup()

	buf := make([]byte, 64*1024)
	for {
		n, err := fwd.tunnelConn.Read(buf)
		if err != nil {
			return
		}

		data := buf[:n]

		// Check if this is a binary frame (TCP data): starts with 4-byte length prefix.
		// Binary frames: [4B connID len][connID][payload]
		if n >= 4 && !isJSON(data) {
			connID, payload := parseBinaryFrame(data)
			if connID != "" {
				if ch, ok := fwd.tcpChans.Load(connID); ok {
					// Make a copy since buf is reused.
					pCopy := make([]byte, len(payload))
					copy(pCopy, payload)
					select {
					case ch.(chan []byte) <- pCopy:
					case <-fwd.ctx.Done():
						return
					}
				}
				continue
			}
		}

		// Try to parse as JSON control message.
		var msg struct {
			Type    string            `json:"type"`
			ID      string            `json:"id"`
			ConnID  string            `json:"connId"`
			Method  string            `json:"method"`
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
		}

		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		// Copy fields before spawning goroutines to avoid any closure capture issues.
		reqID := msg.ID
		method := msg.Method
		path := msg.Path
		headers := msg.Headers
		body := msg.Body
		connID := msg.ConnID

		switch msg.Type {
		case "http_request":
			select {
			case fwd.sem <- struct{}{}:
				go func() {
					defer func() { <-fwd.sem }()
					fwd.handleHTTPRequest(sess, reqID, method, path, headers, body)
				}()
			default:
				fwd.sendHTTPResponse(reqID, 503, map[string]string{}, "too many concurrent requests", "")
			}

		case "tcp_open":
			select {
			case fwd.sem <- struct{}{}:
				go func() {
					defer func() { <-fwd.sem }()
					fwd.handleTCPOpen(sess, connID)
				}()
			default:
				fwd.sendTCPClose(connID)
			}
		}
	}
}

// isJSON is a fast check: does the data start with '{' (after optional whitespace)?
func isJSON(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
}

// parseBinaryFrame extracts connID and payload from a binary TCP frame.
// Format: [4B connID len (big-endian)][connID bytes][payload bytes]
func parseBinaryFrame(data []byte) (connID string, payload []byte) {
	if len(data) < 4 {
		return "", nil
	}
	idLen := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if idLen <= 0 || idLen > 256 || 4+idLen > len(data) {
		return "", nil
	}
	return string(data[4 : 4+idLen]), data[4+idLen:]
}

// sshDialWithTimeout wraps ssh.Client.Dial with a context-aware timeout.
// ssh.Client.Dial has no context param, so we use a goroutine + select.
func sshDialWithTimeout(ctx context.Context, client *ssh.Client, network, addr string, timeout time.Duration) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := client.Dial(network, addr)
		ch <- result{c, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case r := <-ch:
		return r.conn, r.err
	case <-timer.C:
		// Close any late connection to prevent leak.
		go func() {
			if r := <-ch; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, fmt.Errorf("ssh dial %s timed out after %v", addr, timeout)
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// handleHTTPRequest forwards an HTTP request from the proxy through an SSH
// direct-tcpip channel to the remote service.
func (fwd *portForward) handleHTTPRequest(sess *session, reqID, method, path string, headers map[string]string, body string) {
	// Open SSH direct-tcpip channel to the remote service.
	addr := fmt.Sprintf("%s:%d", fwd.remoteHost, fwd.remotePort)
	channel, err := sshDialWithTimeout(fwd.ctx, sess.sshClient, "tcp", addr, 30*time.Second)
	if err != nil {
		fwd.sendHTTPResponse(reqID, 502, map[string]string{}, fmt.Sprintf("SSH dial failed: %v", err), "")
		return
	}
	defer channel.Close()

	// Build and send HTTP request through the SSH channel.
	httpReq := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s:%d\r\n", method, path, fwd.remoteHost, fwd.remotePort)
	for k, v := range headers {
		// Skip hop-by-hop and proxy headers.
		switch k {
		case "Host", "Connection", "Upgrade", "Keep-Alive",
			"Transfer-Encoding", "TE", "Trailer", "Proxy-Authorization",
			"Proxy-Connection":
			continue
		}
		// Sanitize: reject header values containing \r or \n (header injection).
		if containsCRLF(k) || containsCRLF(v) {
			continue
		}
		httpReq += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	if body != "" {
		httpReq += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	}
	httpReq += "Connection: close\r\n\r\n"
	if body != "" {
		httpReq += body
	}

	if _, err := channel.Write([]byte(httpReq)); err != nil {
		fwd.sendHTTPResponse(reqID, 502, map[string]string{}, "write failed", "")
		return
	}

	// Read the entire response.
	respBytes, err := io.ReadAll(io.LimitReader(channel, 10*1024*1024)) // 10MB limit
	if err != nil {
		fwd.sendHTTPResponse(reqID, 502, map[string]string{}, "read failed", "")
		return
	}

	// Parse HTTP response (simple parsing — find header/body boundary).
	respStr := string(respBytes)
	status := 200
	respHeaders := map[string]string{}
	respBody := respStr

	if headerEnd := findHeaderEnd(respStr); headerEnd > 0 {
		headerPart := respStr[:headerEnd]
		respBody = respStr[headerEnd+4:] // Skip \r\n\r\n

		// Parse status line and headers.
		lines := splitLines(headerPart)
		if len(lines) > 0 {
			statusLine := lines[0]
			if spaceIdx := findSpace(statusLine); spaceIdx > 0 && spaceIdx+4 <= len(statusLine) {
				fmt.Sscanf(statusLine[spaceIdx+1:spaceIdx+4], "%d", &status)
			}
		}

		for _, line := range lines[1:] { // Skip status line
			if colonIdx := findColon(line); colonIdx > 0 {
				key := line[:colonIdx]
				val := ""
				if colonIdx+2 < len(line) {
					val = line[colonIdx+2:]
				}
				respHeaders[key] = val
			}
		}
	}

	// Encode binary response bodies as base64.
	bodyEncoding := ""
	contentType := respHeaders["Content-Type"]
	if contentType != "" && !isTextContentType(contentType) {
		bodyEncoding = "base64"
		respBody = base64.StdEncoding.EncodeToString([]byte(respBody))
	}

	fwd.sendHTTPResponse(reqID, status, respHeaders, respBody, bodyEncoding)
}

// handleTCPOpen handles a raw TCP connection forwarding through SSH.
// Data is multiplexed via binary frames tagged with connID.
func (fwd *portForward) handleTCPOpen(sess *session, connID string) {
	addr := fmt.Sprintf("%s:%d", fwd.remoteHost, fwd.remotePort)
	channel, err := sshDialWithTimeout(fwd.ctx, sess.sshClient, "tcp", addr, 30*time.Second)
	if err != nil {
		fwd.sendTCPClose(connID)
		return
	}
	defer channel.Close()

	// Register a channel to receive incoming data for this connection.
	inCh := make(chan []byte, 256)
	fwd.tcpChans.Store(connID, inCh)
	defer fwd.tcpChans.Delete(connID)

	done := make(chan struct{}, 2)

	// Proxy → SSH: read multiplexed frames from inCh, write to SSH channel.
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			select {
			case data, ok := <-inCh:
				if !ok {
					return
				}
				if _, err := channel.Write(data); err != nil {
					return
				}
			case <-fwd.ctx.Done():
				return
			}
		}
	}()

	// SSH → Proxy: read from SSH channel, write as binary frames to tunnel WS.
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := channel.Read(buf)
			if n > 0 {
				frame := buildBinaryFrameWASM(connID, buf[:n])
				fwd.wsMu.Lock()
				_, writeErr := fwd.tunnelConn.Write(frame)
				fwd.wsMu.Unlock()
				if writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for both goroutines, but don't block forever if SSH hangs.
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-fwd.ctx.Done():
			// Tunnel closing — don't wait further.
			// Close SSH channel to unblock any stuck Read/Write.
			channel.Close()
			<-done // Now safe to drain since channel is closed.
		}
	}
	fwd.sendTCPClose(connID)
}

// buildBinaryFrameWASM constructs a binary frame for TCP tunnel data (browser side).
// Format: [4B connID len (big-endian)][connID bytes][payload bytes]
func buildBinaryFrameWASM(connID string, payload []byte) []byte {
	idBytes := []byte(connID)
	idLen := len(idBytes)
	frame := make([]byte, 4+idLen+len(payload))
	frame[0] = byte(idLen >> 24)
	frame[1] = byte(idLen >> 16)
	frame[2] = byte(idLen >> 8)
	frame[3] = byte(idLen)
	copy(frame[4:], idBytes)
	copy(frame[4+idLen:], payload)
	return frame
}

// sendHTTPResponse sends an HTTP response back through the tunnel WebSocket.
func (fwd *portForward) sendHTTPResponse(reqID string, status int, headers map[string]string, body string, bodyEncoding string) {
	resp := map[string]any{
		"type":    "http_response",
		"id":      reqID,
		"status":  status,
		"headers": headers,
		"body":    body,
	}
	if bodyEncoding != "" {
		resp["bodyEncoding"] = bodyEncoding
	}
	data, _ := json.Marshal(resp)
	fwd.wsMu.Lock()
	fwd.tunnelConn.Write(data)
	fwd.wsMu.Unlock()
}

// sendTCPClose notifies the proxy that a TCP connection has closed.
func (fwd *portForward) sendTCPClose(connID string) {
	msg := map[string]string{"type": "tcp_close", "connId": connID}
	data, _ := json.Marshal(msg)
	fwd.wsMu.Lock()
	fwd.tunnelConn.Write(data)
	fwd.wsMu.Unlock()
}

// cleanup closes the port forward and removes it from the store.
// Safe to call multiple times (guarded by sync.Once).
func (fwd *portForward) cleanup() {
	fwd.cleanupOnce.Do(func() {
		fwd.cancel()
		if fwd.tunnelConn != nil {
			fwd.tunnelConn.Close()
		}
		forwardStore.Delete(fwd.id)
	})
}

// portForwardStop stops an active port forward.
// Called from JS as: GoSSH.portForwardStop(tunnelId)
func portForwardStop(forwardID string) {
	val, ok := forwardStore.Load(forwardID)
	if !ok {
		return
	}
	fwd := val.(*portForward)
	fwd.cleanup()
}

// portForwardList returns all active port forwards for a session.
// Called from JS as: GoSSH.portForwardList(sessionId) → TunnelInfo[]
func portForwardList(sessionID string) js.Value {
	var results []any

	forwardStore.Range(func(key, val any) bool {
		fwd := val.(*portForward)
		if fwd.sessionID == sessionID {
			results = append(results, map[string]any{
				"id":         fwd.id,
				"remoteHost": fwd.remoteHost,
				"remotePort": fwd.remotePort,
				"tunnelUrl":  fwd.tunnelURL,
				"rawPort":    fwd.rawPort,
				"active":     true,
			})
		}
		return true
	})

	arr := js.Global().Get("Array").New(len(results))
	for i, r := range results {
		arr.SetIndex(i, js.ValueOf(r))
	}
	return arr
}

// Helper functions for simple HTTP parsing.

func findHeaderEnd(s string) int {
	for i := 0; i < len(s)-3; i++ {
		if s[i] == '\r' && s[i+1] == '\n' && s[i+2] == '\r' && s[i+3] == '\n' {
			return i
		}
	}
	return -1
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '\r' && s[i+1] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 2
			i++
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func findSpace(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return i
		}
	}
	return -1
}

func findColon(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

// isTextContentType returns true for text-based content types that can be sent as plain strings.
func isTextContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "html")
}

// containsCRLF checks if a string contains \r or \n (header injection guard).
func containsCRLF(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			return true
		}
	}
	return false
}
