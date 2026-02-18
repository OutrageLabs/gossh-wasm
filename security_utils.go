//go:build js && wasm

package gossh

import (
	"errors"
	"io"
	"net/url"
	"strings"
	"syscall/js"
)

var errHostKeyCallbackRequired = errors.New("connect: onHostKey callback is required (or set allowInsecureHostKey=true for development)")

func parseWebSocketURL(raw string, allowInsecure bool) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("proxy URL is required")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid WebSocket URL")
	}

	switch strings.ToLower(u.Scheme) {
	case "wss":
		return u, nil
	case "ws":
		if allowInsecure {
			return u, nil
		}
		return nil, errors.New("insecure ws:// URL blocked; use wss:// or set allowInsecureWS=true for development")
	default:
		return nil, errors.New("WebSocket URL must use ws:// or wss://")
	}
}

func publicErr(publicMsg string, err error) error {
	if err != nil {
		logWarnf(publicMsg+":", err.Error())
	}
	return errors.New(publicMsg)
}

func scrubBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func closeQuietly(c io.Closer) {
	if c != nil {
		_ = c.Close()
	}
}

func logWarnf(msg string, args ...any) {
	console := js.Global().Get("console")
	if console.IsUndefined() || console.IsNull() {
		return
	}
	console.Call("warn", append([]any{"[gossh] " + msg}, args...)...)
}

func isHexID(s string, wantLen int) bool {
	if len(s) != wantLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
