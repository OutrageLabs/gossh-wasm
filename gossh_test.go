// gossh_test.go — unit tests for pure logic functions in gossh-wasm.
//
// Run with: GOOS=js GOARCH=wasm go test ./...
// Requires Node.js and the Go WASM test runner.

//go:build js && wasm

package gossh

import (
	"bytes"
	"strings"
	"syscall/js"
	"testing"
)

// ────────────────────────────────────────────────────────────────────
// portforward.go — binary frame parsing
// ────────────────────────────────────────────────────────────────────

func TestParseBinaryFrame(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantConnID string
		wantData   []byte
	}{
		{
			name:       "valid frame",
			data:       append([]byte{0, 0, 0, 4}, append([]byte("conn"), []byte("payload")...)...),
			wantConnID: "conn",
			wantData:   []byte("payload"),
		},
		{
			name:       "empty payload",
			data:       append([]byte{0, 0, 0, 3}, []byte("abc")...),
			wantConnID: "abc",
			wantData:   []byte{},
		},
		{
			name:       "too short",
			data:       []byte{0, 1},
			wantConnID: "",
			wantData:   nil,
		},
		{
			name:       "zero id length",
			data:       []byte{0, 0, 0, 0, 1, 2, 3},
			wantConnID: "",
			wantData:   nil,
		},
		{
			name:       "id length exceeds data",
			data:       []byte{0, 0, 0, 10, 'a', 'b'},
			wantConnID: "",
			wantData:   nil,
		},
		{
			name:       "id length > 256",
			data:       append([]byte{0, 0, 1, 1}, make([]byte, 300)...),
			wantConnID: "",
			wantData:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connID, payload := parseBinaryFrame(tt.data)
			if connID != tt.wantConnID {
				t.Errorf("connID = %q, want %q", connID, tt.wantConnID)
			}
			if !bytes.Equal(payload, tt.wantData) {
				t.Errorf("payload = %v, want %v", payload, tt.wantData)
			}
		})
	}
}

func TestBuildAndParseBinaryFrame(t *testing.T) {
	// Round-trip test: build → parse should give back original values.
	connID := "test-conn-12345"
	payload := []byte("hello world this is test data")

	frame := buildBinaryFrameWASM(connID, payload)
	gotID, gotPayload := parseBinaryFrame(frame)

	if gotID != connID {
		t.Errorf("connID round-trip: got %q, want %q", gotID, connID)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload round-trip: got %v, want %v", gotPayload, payload)
	}
}

// ────────────────────────────────────────────────────────────────────
// portforward.go — helper functions
// ────────────────────────────────────────────────────────────────────

func TestIsJSON(t *testing.T) {
	tests := []struct {
		data []byte
		want bool
	}{
		{[]byte(`{"type":"test"}`), true},
		{[]byte(`  {"type":"test"}`), true},
		{[]byte("\t\n{"), true},
		{[]byte(`[1,2,3]`), false}, // Starts with [, not {
		{[]byte{0, 0, 0, 4}, false},
		{[]byte{}, false},
		{[]byte("   "), false},
	}

	for _, tt := range tests {
		got := isJSON(tt.data)
		if got != tt.want {
			t.Errorf("isJSON(%q) = %v, want %v", tt.data, got, tt.want)
		}
	}
}

func TestContainsCRLF(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"normal header", false},
		{"has\nnewline", true},
		{"has\rreturn", true},
		{"has\r\nboth", true},
		{"", false},
	}

	for _, tt := range tests {
		got := containsCRLF(tt.s)
		if got != tt.want {
			t.Errorf("containsCRLF(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestIsTextContentType(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"text/html", true},
		{"text/plain", true},
		{"application/json", true},
		{"application/xml", true},
		{"text/javascript", true},
		{"application/octet-stream", false},
		{"image/png", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isTextContentType(tt.ct)
		if got != tt.want {
			t.Errorf("isTextContentType(%q) = %v, want %v", tt.ct, got, tt.want)
		}
	}
}

func TestFindHeaderEnd(t *testing.T) {
	tests := []struct {
		s    string
		want int
	}{
		{"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody", 41},
		{"no headers here", -1},
		{"\r\n\r\n", 0},
	}

	for _, tt := range tests {
		got := findHeaderEnd(tt.s)
		if got != tt.want {
			t.Errorf("findHeaderEnd(%q) = %d, want %d", tt.s, got, tt.want)
		}
	}
}

func TestSplitLines(t *testing.T) {
	input := "line1\r\nline2\r\nline3"
	got := splitLines(input)
	want := []string{"line1", "line2", "line3"}
	if len(got) != len(want) {
		t.Fatalf("splitLines: got %d lines, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("splitLines[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// ────────────────────────────────────────────────────────────────────
// randomart.go — Bishop algorithm
// ────────────────────────────────────────────────────────────────────

func TestRandomArtFromHash(t *testing.T) {
	// Use a known hash and verify structural properties.
	hash := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	art := randomArtFromHash(hash, "ssh-rsa", 4096, "MD5")

	lines := strings.Split(art, "\n")
	if len(lines) != artHeight+2 {
		t.Fatalf("expected %d lines, got %d", artHeight+2, len(lines))
	}

	// Top border should contain key type.
	if !strings.Contains(lines[0], "SSH-RSA") {
		t.Errorf("top border missing key type: %s", lines[0])
	}
	if !strings.Contains(lines[0], "4096") {
		t.Errorf("top border missing key bits: %s", lines[0])
	}

	// Bottom border should contain hash name.
	if !strings.Contains(lines[len(lines)-1], "MD5") {
		t.Errorf("bottom border missing hash name: %s", lines[len(lines)-1])
	}

	// Grid lines should be width+2 (pipes).
	for i := 1; i <= artHeight; i++ {
		if len(lines[i]) != artWidth+2 {
			t.Errorf("line %d width = %d, want %d: %q", i, len(lines[i]), artWidth+2, lines[i])
		}
		if lines[i][0] != '|' || lines[i][artWidth+1] != '|' {
			t.Errorf("line %d missing pipes: %q", i, lines[i])
		}
	}

	// Should contain start 'S' and end 'E'.
	artBody := strings.Join(lines[1:artHeight+1], "")
	if !strings.Contains(artBody, "S") {
		t.Error("randomart missing start marker 'S'")
	}
	if !strings.Contains(artBody, "E") {
		t.Error("randomart missing end marker 'E'")
	}
}

func TestRandomArtDeterministic(t *testing.T) {
	hash := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	art1 := randomArtFromHash(hash, "ed25519", 256, "MD5")
	art2 := randomArtFromHash(hash, "ed25519", 256, "MD5")
	if art1 != art2 {
		t.Error("randomart not deterministic for same input")
	}
}

func TestRandomArtFromFingerprint(t *testing.T) {
	// MD5 fingerprint format with colons.
	fp := "MD5:de:ad:be:ef:ca:fe:ba:be:01:23:45:67:89:ab:cd:ef"
	art := RandomArtFromFingerprint(fp, "ssh-rsa", 4096)
	if art == "" {
		t.Error("RandomArtFromFingerprint returned empty string")
	}
	if !strings.Contains(art, "SSH-RSA") {
		t.Errorf("missing key type in art: %s", art)
	}

	// Without prefix.
	fp2 := "deadbeefcafebabe0123456789abcdef"
	art2 := RandomArtFromFingerprint(fp2, "ssh-rsa", 4096)
	if art != art2 {
		t.Error("fingerprint with and without MD5: prefix should produce same art")
	}
}

// ────────────────────────────────────────────────────────────────────
// sftp_transfer.go — helper functions
// ────────────────────────────────────────────────────────────────────

func TestIsAbortedUndefined(t *testing.T) {
	// isAborted must return false for undefined/null without panicking.
	if isAborted(js.Undefined()) {
		t.Error("isAborted(js.Undefined()) should be false")
	}
	if isAborted(js.Null()) {
		t.Error("isAborted(js.Null()) should be false")
	}
}
