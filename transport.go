// Package gossh provides an SSH client compiled to WebAssembly for browser use.
//
// transport.go implements a net.Conn adapter over browser WebSocket (syscall/js).
// This allows golang.org/x/crypto/ssh to operate transparently over WebSocket.

//go:build js && wasm

package gossh

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"syscall/js"
	"time"
)

const (
	// wsReadChanSize is the capacity of the incoming message channel.
	// Large enough to prevent backpressure from stalling the JS event loop.
	wsReadChanSize = 4096

	// wsWriteChunkSize is the max bytes per WebSocket send() call.
	// Matches sshterm's proven chunk size for SSH-over-WS throughput.
	wsWriteChunkSize = 4096

	// wsMaxMessageSize bounds one incoming WebSocket frame to prevent
	// unbounded allocation from malicious or compromised peers.
	wsMaxMessageSize = 8 * 1024 * 1024 // 8 MB
)

var (
	errWSClosed     = errors.New("websocket: connection closed")
	errWSNotOpen    = errors.New("websocket: not in OPEN state")
	errDialTimeout  = errors.New("websocket: dial timeout")
	errDialFailed   = errors.New("websocket: dial failed")
	errWSFrameLarge = errors.New("websocket: incoming frame too large")
	errWSBackpress  = errors.New("websocket: receive buffer overflow")
)

// wsConn implements net.Conn over a browser WebSocket.
// All shared state is protected by mu to prevent race conditions
// between JS event callbacks and Go Read()/Write() calls.
type wsConn struct {
	ctx    context.Context
	cancel context.CancelFunc

	// mu protects err and closed fields.
	mu     sync.Mutex
	err    error
	closed bool

	ws     js.Value    // browser WebSocket object
	readCh chan []byte // incoming message data
	buf    []byte      // leftover bytes from previous Read()

	// JS function references (prevent GC while registered)
	onOpen    js.Func
	onMessage js.Func
	onError   js.Func
	onClose   js.Func

	cleanupOnce sync.Once
}

// DialWebSocket creates a new WebSocket connection and returns it as net.Conn.
// The url should be a fully-formed WebSocket URL (ws:// or wss://) including
// any query parameters for the proxy (e.g., ?host=x&port=22&token=jwt).
//
// The context controls the dial timeout — if the WebSocket doesn't reach
// OPEN state before ctx is cancelled, the connection is aborted.
func DialWebSocket(ctx context.Context, url string) (net.Conn, error) {
	connCtx, cancel := context.WithCancel(ctx)

	c := &wsConn{
		ctx:    connCtx,
		cancel: cancel,
		readCh: make(chan []byte, wsReadChanSize),
	}

	// Create the browser WebSocket via syscall/js.
	ws := js.Global().Get("WebSocket").New(url)
	ws.Set("binaryType", "arraybuffer")
	c.ws = ws

	// Channel to signal that WebSocket is open (or failed).
	openCh := make(chan error, 1)

	c.onOpen = js.FuncOf(func(this js.Value, args []js.Value) any {
		select {
		case openCh <- nil:
		default:
		}
		return nil
	})

	c.onError = js.FuncOf(func(this js.Value, args []js.Value) any {
		c.mu.Lock()
		if c.err == nil {
			c.err = errDialFailed
		}
		c.mu.Unlock()
		select {
		case openCh <- errDialFailed:
		default:
		}
		return nil
	})

	c.onClose = js.FuncOf(func(this js.Value, args []js.Value) any {
		c.mu.Lock()
		if c.err == nil {
			c.err = errWSClosed
		}
		c.closed = true
		c.mu.Unlock()
		c.cancel()
		return nil
	})

	c.onMessage = js.FuncOf(func(this js.Value, args []js.Value) any {
		event := args[0]
		arrayBuf := event.Get("data")

		uint8Array := js.Global().Get("Uint8Array").New(arrayBuf)
		size := uint8Array.Get("byteLength").Int()
		if size > wsMaxMessageSize {
			c.mu.Lock()
			if c.err == nil {
				c.err = errWSFrameLarge
			}
			c.mu.Unlock()
			c.cancel()
			state := c.ws.Get("readyState").Int()
			if state == 0 || state == 1 { // CONNECTING or OPEN
				c.ws.Call("close")
			}
			return nil
		}

		// Copy ArrayBuffer → Go []byte
		data := make([]byte, size)
		js.CopyBytesToGo(data, uint8Array)

		select {
		case c.readCh <- data:
		case <-c.ctx.Done():
		default:
			c.mu.Lock()
			if c.err == nil {
				c.err = errWSBackpress
			}
			c.mu.Unlock()
			c.cancel()
			state := c.ws.Get("readyState").Int()
			if state == 0 || state == 1 { // CONNECTING or OPEN
				c.ws.Call("close")
			}
		}
		return nil
	})

	ws.Call("addEventListener", "open", c.onOpen)
	ws.Call("addEventListener", "error", c.onError)
	ws.Call("addEventListener", "close", c.onClose)
	ws.Call("addEventListener", "message", c.onMessage)

	// Wait for WebSocket to open or context to cancel.
	select {
	case err := <-openCh:
		if err != nil {
			c.cleanup()
			return nil, err
		}
	case <-ctx.Done():
		c.cleanup()
		return nil, errDialTimeout
	}

	return c, nil
}

// Read implements net.Conn.Read with greedy read optimization.
// If the internal buffer is empty but the channel has more queued messages,
// it reads all available data before returning — reducing syscall overhead.
func (c *wsConn) Read(p []byte) (int, error) {
	if err := c.getErr(); err != nil {
		// Drain any remaining buffered data before reporting error.
		if len(c.buf) > 0 {
			n := copy(p, c.buf)
			c.buf = c.buf[n:]
			return n, nil
		}
		return 0, err
	}

	// If we have leftover bytes from a previous read, serve those first.
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	// Block until we get data, an error, or context cancellation.
	select {
	case data, ok := <-c.readCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, data)
		if n < len(data) {
			c.buf = data[n:]
		}

		// Greedy read: if the channel has more messages queued and we have
		// room in p, keep reading without blocking. This is critical for
		// SSH throughput — avoids returning partial data when more is ready.
		for n < len(p) {
			select {
			case extra, ok := <-c.readCh:
				if !ok {
					return n, nil
				}
				copied := copy(p[n:], extra)
				n += copied
				if copied < len(extra) {
					c.buf = extra[copied:]
					return n, nil
				}
			default:
				// No more queued messages — return what we have.
				return n, nil
			}
		}
		return n, nil

	case <-c.ctx.Done():
		return 0, c.ctxErr()
	}
}

// Write implements net.Conn.Write, chunking data into wsWriteChunkSize segments.
// Each chunk becomes one WebSocket binary message.
func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.getErr(); err != nil {
		return 0, err
	}

	if c.ws.Get("readyState").Int() != 1 { // 1 = OPEN
		return 0, errWSNotOpen
	}

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > wsWriteChunkSize {
			chunk = p[:wsWriteChunkSize]
		}
		p = p[len(chunk):]

		// Create Uint8Array and copy Go bytes into JS.
		jsArray := js.Global().Get("Uint8Array").New(len(chunk))
		js.CopyBytesToJS(jsArray, chunk)
		c.ws.Call("send", jsArray)
		total += len(chunk)
	}
	return total, nil
}

// Close implements net.Conn.Close.
func (c *wsConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.err == nil {
		c.err = errWSClosed
	}
	c.mu.Unlock()

	c.cancel()

	// Close the WebSocket if it's still open or connecting.
	state := c.ws.Get("readyState").Int()
	if state == 0 || state == 1 { // CONNECTING or OPEN
		c.ws.Call("close")
	}

	c.cleanup()
	return nil
}

// cleanup releases JS function references to prevent memory leaks.
// Safe to call multiple times — only the first call releases.
func (c *wsConn) cleanup() {
	c.cleanupOnce.Do(func() {
		c.onOpen.Release()
		c.onMessage.Release()
		c.onError.Release()
		c.onClose.Release()
	})
}

// LocalAddr returns a dummy address (browsers don't expose local socket info).
func (c *wsConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

// RemoteAddr returns a dummy address (browsers don't expose remote socket info).
func (c *wsConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

// SetDeadline is a no-op — browser WebSockets don't support deadlines.
func (c *wsConn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op.
func (c *wsConn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op.
func (c *wsConn) SetWriteDeadline(t time.Time) error { return nil }

// getErr returns the current error state, thread-safe.
func (c *wsConn) getErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// ctxErr converts context error to io.EOF for clean SSH shutdown.
func (c *wsConn) ctxErr() error {
	if c.ctx.Err() != nil {
		return io.EOF
	}
	return nil
}
