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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall/js"
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

		// Build tunnel WebSocket URL.
		tunnelWsURL := proxyTunnelURL
		if token := jsString(config.Get("token")); token != "" {
			tunnelWsURL += "?token=" + token
		}

		// Connect to proxy tunnel endpoint.
		ctx, cancel := context.WithCancel(sess.ctx)

		tunnelConn, err := DialWebSocket(ctx, tunnelWsURL)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("portForwardStart: dial tunnel: %w", err)
		}

		// Read tunnel_ready message from proxy.
		readBuf := make([]byte, 4096)
		n, err := tunnelConn.Read(readBuf)
		if err != nil {
			tunnelConn.Close()
			cancel()
			return nil, fmt.Errorf("portForwardStart: read tunnel_ready: %w", err)
		}

		var ready struct {
			Type      string `json:"type"`
			TunnelURL string `json:"tunnelUrl"`
			RawPort   int    `json:"rawPort"`
		}
		if err := json.Unmarshal(readBuf[:n], &ready); err != nil {
			tunnelConn.Close()
			cancel()
			return nil, fmt.Errorf("portForwardStart: parse tunnel_ready: %w", err)
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
func (fwd *portForward) handleTunnelMessages(sess *session) {
	defer fwd.cleanup()

	buf := make([]byte, 64*1024)
	for {
		n, err := fwd.tunnelConn.Read(buf)
		if err != nil {
			return
		}

		// Try to parse as JSON control message.
		var msg struct {
			Type   string `json:"type"`
			ID     string `json:"id"`
			ConnID string `json:"connId"`
			Method string `json:"method"`
			Path   string `json:"path"`
			Headers map[string]string `json:"headers"`
			Body   string `json:"body"`
		}

		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			// Might be binary data for a TCP connection — handle below.
			continue
		}

		switch msg.Type {
		case "http_request":
			go fwd.handleHTTPRequest(sess, msg.ID, msg.Method, msg.Path, msg.Headers, msg.Body)

		case "tcp_open":
			go fwd.handleTCPOpen(sess, msg.ConnID)
		}
	}
}

// handleHTTPRequest forwards an HTTP request from the proxy through an SSH
// direct-tcpip channel to the remote service.
func (fwd *portForward) handleHTTPRequest(sess *session, reqID, method, path string, headers map[string]string, body string) {
	// Open SSH direct-tcpip channel to the remote service.
	addr := fmt.Sprintf("%s:%d", fwd.remoteHost, fwd.remotePort)
	channel, err := sess.sshClient.Dial("tcp", addr)
	if err != nil {
		fwd.sendHTTPResponse(reqID, 502, map[string]string{}, fmt.Sprintf("SSH dial failed: %v", err))
		return
	}
	defer channel.Close()

	// Build and send HTTP request through the SSH channel.
	httpReq := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s:%d\r\n", method, path, fwd.remoteHost, fwd.remotePort)
	for k, v := range headers {
		// Skip hop-by-hop headers.
		if k == "Host" || k == "Connection" || k == "Upgrade" {
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
		fwd.sendHTTPResponse(reqID, 502, map[string]string{}, "write failed")
		return
	}

	// Read the entire response.
	respBytes, err := io.ReadAll(io.LimitReader(channel, 10*1024*1024)) // 10MB limit
	if err != nil {
		fwd.sendHTTPResponse(reqID, 502, map[string]string{}, "read failed")
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

		// Parse status line.
		if len(headerPart) > 12 {
			fmt.Sscanf(headerPart[:12], "HTTP/1.%*d %d", &status)
		}

		// Parse headers (simple).
		lines := splitLines(headerPart)
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

	fwd.sendHTTPResponse(reqID, status, respHeaders, respBody)
}

// handleTCPOpen handles a raw TCP connection forwarding through SSH.
func (fwd *portForward) handleTCPOpen(sess *session, connID string) {
	addr := fmt.Sprintf("%s:%d", fwd.remoteHost, fwd.remotePort)
	channel, err := sess.sshClient.Dial("tcp", addr)
	if err != nil {
		fwd.sendTCPClose(connID)
		return
	}
	defer channel.Close()

	// Bidirectional relay between tunnel WebSocket and SSH channel.
	// This is simplified — in production, we'd need to multiplex by connID
	// in the binary frames. For now, single TCP connection per tunnel.
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(channel, fwd.tunnelConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(fwd.tunnelConn, channel)
		done <- struct{}{}
	}()

	<-done
	fwd.sendTCPClose(connID)
}

// sendHTTPResponse sends an HTTP response back through the tunnel WebSocket.
func (fwd *portForward) sendHTTPResponse(reqID string, status int, headers map[string]string, body string) {
	resp := map[string]any{
		"type":    "http_response",
		"id":      reqID,
		"status":  status,
		"headers": headers,
		"body":    body,
	}
	data, _ := json.Marshal(resp)
	fwd.tunnelConn.Write(data)
}

// sendTCPClose notifies the proxy that a TCP connection has closed.
func (fwd *portForward) sendTCPClose(connID string) {
	msg := map[string]string{"type": "tcp_close", "connId": connID}
	data, _ := json.Marshal(msg)
	fwd.tunnelConn.Write(data)
}

// cleanup closes the port forward and removes it from the store.
func (fwd *portForward) cleanup() {
	fwd.cancel()
	if fwd.tunnelConn != nil {
		fwd.tunnelConn.Close()
	}
	forwardStore.Delete(fwd.id)
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

func findColon(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}
