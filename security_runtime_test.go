//go:build js && wasm

package gossh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	mrand "math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"syscall/js"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey failed: %v", err)
	}
	return key
}

func TestHostKeyCallback_NoCallbackRejectsKey(t *testing.T) {
	config := js.Global().Get("Object").New()
	cb := makeHostKeyCallback(config)
	if err := cb("example.test:22", nil, testPublicKey(t)); err == nil {
		t.Fatal("expected missing callback path to reject key")
	}
}

func TestHostKeyCallback_NoCallbackAllowInsecure(t *testing.T) {
	config := js.Global().Get("Object").New()
	config.Set("allowInsecureHostKey", true)
	cb := makeHostKeyCallback(config)
	if err := cb("example.test:22", nil, testPublicKey(t)); err != nil {
		t.Fatalf("expected allowInsecureHostKey path to accept key, got: %v", err)
	}
}

func TestHostKeyCallback_UserRejectsKey(t *testing.T) {
	config := js.Global().Get("Object").New()

	rejectFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		return js.Global().Get("Promise").Call("resolve", false)
	})
	defer rejectFn.Release()
	config.Set("onHostKey", rejectFn)

	cb := makeHostKeyCallback(config)
	err := cb("example.test:22", nil, testPublicKey(t))
	if err == nil {
		t.Fatal("expected rejection error, got nil")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("expected rejection error, got: %v", err)
	}
}

func TestAwaitPromise_TimesOut(t *testing.T) {
	neverResolve := js.FuncOf(func(this js.Value, args []js.Value) any {
		// Intentionally do not call resolve/reject.
		return nil
	})
	promise := js.Global().Get("Promise").New(neverResolve)
	neverResolve.Release()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := awaitPromise(ctx, promise)
	if !errors.Is(err, errAwaitTimeout) {
		t.Fatalf("expected errAwaitTimeout, got: %v", err)
	}
}

func TestParseWebSocketURL_RejectsInsecureByDefault(t *testing.T) {
	if _, err := parseWebSocketURL("ws://example.test/relay", false); err == nil {
		t.Fatal("expected ws:// URL to be rejected by default")
	}
}

func TestParseWebSocketURL_AllowsInsecureWithOptIn(t *testing.T) {
	if _, err := parseWebSocketURL("ws://example.test/relay", true); err != nil {
		t.Fatalf("expected ws:// URL to be allowed with opt-in, got: %v", err)
	}
}

func TestSessionClose_IdempotentUnderConcurrency(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var closeCalls atomic.Int32
	onClose := js.FuncOf(func(this js.Value, args []js.Value) any {
		closeCalls.Add(1)
		return nil
	})
	defer onClose.Release()

	s := &session{
		id:      "sess-close-idempotent",
		ctx:     ctx,
		cancel:  cancel,
		onClose: onClose.Value,
	}
	sessionStore.Store(s.id, s)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.close("test shutdown")
		}()
	}
	wg.Wait()

	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("onClose called %d times, want 1", got)
	}
	if _, ok := sessionStore.Load(s.id); ok {
		t.Fatalf("session %q still present in store after close", s.id)
	}
}

func TestParseBinaryFrame_AdversarialCorpus_NoPanic(t *testing.T) {
	r := mrand.New(mrand.NewSource(1337))

	for i := 0; i < 10000; i++ {
		n := r.Intn(2048)
		data := make([]byte, n)
		for j := range data {
			data[j] = byte(r.Intn(256))
		}

		connID, payload := parseBinaryFrame(data)

		if connID == "" {
			if payload != nil {
				t.Fatalf("invalid frame returned non-nil payload at iter %d", i)
			}
			continue
		}

		if len(connID) == 0 || len(connID) > 256 {
			t.Fatalf("invalid connID length %d at iter %d", len(connID), i)
		}
		if payload == nil {
			t.Fatalf("valid connID returned nil payload at iter %d", i)
		}
	}
}

type fakeReadCloser struct {
	closed atomic.Bool
}

func (f *fakeReadCloser) Read(p []byte) (int, error) { return 0, nil }

func (f *fakeReadCloser) Close() error {
	f.closed.Store(true)
	return nil
}

func TestStreamCancel_ClosesAndRemovesState(t *testing.T) {
	const streamID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	f := &fakeReadCloser{}
	state := &streamState{
		file:  f,
		token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		done:  make(chan struct{}),
	}
	activeStreams.Store(streamID, state)

	streamCancel(streamID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	streamCancel(streamID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // Second call should be harmless.

	if _, ok := activeStreams.Load(streamID); ok {
		t.Fatalf("stream state %q still in activeStreams", streamID)
	}
	if !f.closed.Load() {
		t.Fatal("stream file was not closed on cancel")
	}
	select {
	case <-state.done:
	default:
		t.Fatal("state.done channel not closed on cancel")
	}
}

func TestStreamCancel_WrongTokenDoesNotClose(t *testing.T) {
	const streamID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	f := &fakeReadCloser{}
	state := &streamState{
		file:  f,
		token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		done:  make(chan struct{}),
	}
	activeStreams.Store(streamID, state)

	streamCancel(streamID, "cccccccccccccccccccccccccccccccc")
	if _, ok := activeStreams.Load(streamID); !ok {
		t.Fatal("stream state removed with invalid token")
	}
	if f.closed.Load() {
		t.Fatal("stream file closed with invalid token")
	}

	streamCancel(streamID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
}

type fakeFileInfo struct {
	name string
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 1 }
func (f fakeFileInfo) Mode() fs.FileMode  { return 0o644 }
func (f fakeFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

func TestFileInfoToJS_PathIsNormalized(t *testing.T) {
	v := fileInfoToJS("/base", fakeFileInfo{name: "../tricky"})
	got := v.Get("path").String()
	if got != "/tricky" {
		t.Fatalf("unexpected path rendering: got %q", got)
	}
}

func FuzzParseBinaryFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 4, 't', 'e', 's', 't', 'x'})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 1, 1}) // idLen > 256
	f.Add([]byte("not-a-frame"))

	f.Fuzz(func(t *testing.T, data []byte) {
		connID, payload := parseBinaryFrame(data)
		if connID == "" {
			if payload != nil {
				t.Fatalf("invalid frame returned non-nil payload")
			}
			return
		}

		if len(connID) == 0 || len(connID) > 256 {
			t.Fatalf("invalid connID length %d", len(connID))
		}
		if payload == nil {
			t.Fatal("valid frame returned nil payload")
		}
		if len(data) < 4 {
			t.Fatal("valid connID with short frame")
		}

		idLen := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		if idLen != len(connID) {
			t.Fatalf("frame id length mismatch: header=%d parsed=%d", idLen, len(connID))
		}
		if 4+idLen > len(data) {
			t.Fatal("parsed frame exceeds buffer length")
		}
	})
}

func FuzzContainsCRLF(f *testing.F) {
	f.Add("normal")
	f.Add("line\nbreak")
	f.Add("line\rbreak")
	f.Add("\r\n")

	f.Fuzz(func(t *testing.T, s string) {
		got := containsCRLF(s)
		want := strings.ContainsAny(s, "\r\n")
		if got != want {
			t.Fatalf("containsCRLF mismatch for %q: got=%v want=%v", s, got, want)
		}
	})
}

func FuzzFindHeaderEnd(f *testing.F) {
	f.Add("HTTP/1.1 200 OK\r\nA: b\r\n\r\nbody")
	f.Add("no-headers")
	f.Add("\r\n\r\n")

	f.Fuzz(func(t *testing.T, s string) {
		idx := findHeaderEnd(s)
		if idx == -1 {
			return
		}
		if idx < 0 || idx+4 > len(s) {
			t.Fatalf("invalid index: %d for len=%d", idx, len(s))
		}
		if s[idx:idx+4] != "\r\n\r\n" {
			t.Fatalf("index does not point to header delimiter: %q", s[idx:idx+4])
		}
	})
}
