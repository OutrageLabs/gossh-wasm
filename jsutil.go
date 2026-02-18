// jsutil.go provides JavaScript interop utilities for Go WASM:
// Promise creation, async Await with timeout, type conversions,
// and SSH output sanitization.

//go:build js && wasm

package gossh

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall/js"
	"unicode"
)

var errAwaitTimeout = errors.New("jsutil: await timed out")

// newPromise wraps a Go function as a JS Promise. The function runs
// in a goroutine so it can block without stalling the JS event loop.
//
// Usage from JS: const sessionId = await GoSSH.connect({...})
func newPromise(fn func() (any, error)) js.Value {
	handler := js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			result, err := fn()
			if err != nil {
				reject.Invoke(jsError(err))
			} else {
				resolve.Invoke(result)
			}
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

// awaitPromise blocks the current goroutine until a JS Promise settles,
// with context-based timeout protection. This fixes sshterm's Await()
// which could hang forever on unresolved promises.
func awaitPromise(ctx context.Context, promise js.Value) (js.Value, error) {
	ch := make(chan js.Value, 1)
	errCh := make(chan error, 1)

	thenFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) > 0 {
			ch <- args[0]
		} else {
			ch <- js.Undefined()
		}
		return nil
	})
	defer thenFn.Release()

	catchFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) > 0 {
			errCh <- fmt.Errorf("js: %s", args[0].Call("toString").String())
		} else {
			errCh <- errors.New("js: unknown promise rejection")
		}
		return nil
	})
	defer catchFn.Release()

	promise.Call("then", thenFn).Call("catch", catchFn)

	select {
	case val := <-ch:
		return val, nil
	case err := <-errCh:
		return js.Undefined(), err
	case <-ctx.Done():
		return js.Undefined(), errAwaitTimeout
	}
}

// jsError creates a JS Error object from a Go error.
func jsError(err error) js.Value {
	return js.Global().Get("Error").New(err.Error())
}

// uint8ArrayToBytes copies a JS Uint8Array into a Go byte slice.
func uint8ArrayToBytes(arr js.Value) []byte {
	length := arr.Get("byteLength").Int()
	buf := make([]byte, length)
	js.CopyBytesToGo(buf, arr)
	return buf
}

// bytesToUint8Array copies a Go byte slice into a JS Uint8Array.
func bytesToUint8Array(data []byte) js.Value {
	arr := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(arr, data)
	return arr
}

// jsString safely extracts a string from a JS value, returning empty string
// if undefined or null.
func jsString(v js.Value) string {
	if v.IsUndefined() || v.IsNull() {
		return ""
	}
	return v.String()
}

// jsInt safely extracts an int from a JS value, returning defaultVal
// if undefined or null.
func jsInt(v js.Value, defaultVal int) int {
	if v.IsUndefined() || v.IsNull() {
		return defaultVal
	}
	return v.Int()
}

// jsBool safely extracts a bool from a JS value, returning false
// if undefined or null.
func jsBool(v js.Value) bool {
	if v.IsUndefined() || v.IsNull() {
		return false
	}
	return v.Bool()
}

// maskControl sanitizes SSH banner and prompt output by replacing
// dangerous control characters that could be used for terminal injection.
// Preserves CR, LF, TAB, and standard printable characters.
//
// This is a security measure — malicious SSH servers can send escape
// sequences in banners to manipulate the user's terminal.
func maskControl(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n', r == '\r', r == '\t':
			b.WriteRune(r)
		case unicode.IsControl(r):
			// Replace control chars with Unicode replacement character.
			b.WriteRune(unicode.ReplacementChar)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// getCallback safely retrieves a JS callback function from a config object.
// Returns the function and true if it exists, or (undefined, false) otherwise.
func getCallback(config js.Value, name string) (js.Value, bool) {
	fn := config.Get(name)
	if fn.IsUndefined() || fn.IsNull() {
		return js.Undefined(), false
	}
	if fn.Type() != js.TypeFunction {
		return js.Undefined(), false
	}
	return fn, true
}
