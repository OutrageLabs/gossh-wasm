//go:build !js

package gossh

import (
	"strings"
	"testing"
)

// parseBinaryFrame mirrors the parser in portforward.go for host-side fuzzing.
func parseBinaryFrame(data []byte) (connID string, payload []byte) {
	if len(data) < 4 {
		return "", nil
	}
	idLen := int(uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]))
	if idLen <= 0 || idLen > 256 || 4+idLen > len(data) {
		return "", nil
	}
	return string(data[4 : 4+idLen]), data[4+idLen:]
}

// containsCRLF mirrors the guard in portforward.go for host-side fuzzing.
func containsCRLF(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			return true
		}
	}
	return false
}

// findHeaderEnd mirrors the parser helper in portforward.go for host-side fuzzing.
func findHeaderEnd(s string) int {
	for i := 0; i < len(s)-3; i++ {
		if s[i] == '\r' && s[i+1] == '\n' && s[i+2] == '\r' && s[i+3] == '\n' {
			return i
		}
	}
	return -1
}

func FuzzParseBinaryFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 4, 't', 'e', 's', 't', 'x'})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 1, 1})
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
