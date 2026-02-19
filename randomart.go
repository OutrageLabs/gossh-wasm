// randomart.go implements OpenSSH's "visual host key" (Bishop algorithm).
//
// The algorithm: a "bishop" starts at the center of a 9×17 grid and makes
// moves based on successive bit-pairs from the fingerprint hash. Each cell
// tracks how many times it's been visited. Visit counts are rendered as
// ASCII characters, with 'S' marking the start and 'E' the end position.
//
// Reference: http://www.dirk-loss.de/sshvis/drunken_bishop.pdf

//go:build js && wasm

package gossh

import (
	"crypto/md5" // #nosec G501 -- OpenSSH-compatible randomart intentionally uses MD5 visualization bytes.
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	artWidth  = 17
	artHeight = 9
)

// artChars maps visit counts to display characters (same as OpenSSH).
// Index 0 = never visited (space), higher = more visits, last two = start/end.
const artCharsStr = " .o+=*BOX@%&#/^SE"

var (
	artChars       = []byte(artCharsStr)
	artStartMarker = byte(len(artChars) - 2) // #nosec G115 -- bounded static table.
	artEndMarker   = byte(len(artChars) - 1) // #nosec G115 -- bounded static table.
)

// RandomArt generates an ASCII art representation of an SSH public key fingerprint.
// The output matches OpenSSH's visual host key format.
//
// Example output:
//
//	+--[ED25519 256]--+
//	|        .o..     |
//	|       .. o.     |
//	|      .. +.      |
//	|     . .= .      |
//	|      oS.+ .     |
//	|     ..o=.+ .    |
//	|    . =+o=.o     |
//	|   . +.*+o+      |
//	|    E.=*BOo.     |
//	+----[SHA256]-----+
func RandomArt(pubKey ssh.PublicKey) string {
	// Use MD5 hash of the raw public key for the bishop walk
	// (matches OpenSSH's original randomart implementation).
	rawHash := md5.Sum(pubKey.Marshal()) // #nosec G401 -- visualization only, not cryptographic security.
	return randomArtFromHash(rawHash[:], pubKey.Type(), keyBits(pubKey), "MD5")
}

// RandomArtSHA256 generates randomart from a SHA256 fingerprint.
// Takes the raw SHA256 hash bytes (not the base64-encoded fingerprint string).
func RandomArtSHA256(hash []byte, keyType string, bits int) string {
	return randomArtFromHash(hash, keyType, bits, "SHA256")
}

// randomArtFromHash implements the core Bishop algorithm.
func randomArtFromHash(hash []byte, keyType string, bits int, hashName string) string {
	var field [artHeight][artWidth]byte

	// Start at the center.
	x, y := artWidth/2, artHeight/2

	// Walk the grid based on bit-pairs from the hash.
	for _, b := range hash {
		for shift := 0; shift < 8; shift += 2 {
			// Extract 2-bit direction: bits 0-1, 2-3, 4-5, 6-7 (LSB first).
			dir := (b >> shift) & 0x03

			// Move the bishop.
			switch dir {
			case 0: // ↖ up-left
				x--
				y--
			case 1: // ↗ up-right
				x++
				y--
			case 2: // ↙ down-left
				x--
				y++
			case 3: // ↘ down-right
				x++
				y++
			}

			// Clamp to grid bounds.
			if x < 0 {
				x = 0
			}
			if x >= artWidth {
				x = artWidth - 1
			}
			if y < 0 {
				y = 0
			}
			if y >= artHeight {
				y = artHeight - 1
			}

			field[y][x]++
		}
	}

	// Mark start and end positions with special values.
	startX, startY := artWidth/2, artHeight/2
	field[startY][startX] = artStartMarker // 'S'
	field[y][x] = artEndMarker             // 'E'

	// Render the grid.
	var sb strings.Builder

	// Top border with key info.
	header := fmt.Sprintf("%s %d", strings.ToUpper(keyType), bits)
	topPad := (artWidth - len(header) - 4) / 2
	if topPad < 0 {
		topPad = 0
	}
	sb.WriteString("+")
	sb.WriteString(strings.Repeat("-", topPad))
	sb.WriteString("[")
	sb.WriteString(header)
	sb.WriteString("]")
	rightPad := artWidth - topPad - len(header) - 2
	if rightPad < 0 {
		rightPad = 0
	}
	sb.WriteString(strings.Repeat("-", rightPad))
	sb.WriteString("+\n")

	// Grid rows.
	for row := 0; row < artHeight; row++ {
		sb.WriteByte('|')
		for col := 0; col < artWidth; col++ {
			idx := int(field[row][col])
			if idx >= len(artChars) {
				idx = len(artChars) - 3 // Cap at max visit char.
			}
			sb.WriteByte(artChars[idx])
		}
		sb.WriteString("|\n")
	}

	// Bottom border with hash type.
	botPad := (artWidth - len(hashName) - 2) / 2
	if botPad < 0 {
		botPad = 0
	}
	sb.WriteString("+")
	sb.WriteString(strings.Repeat("-", botPad))
	sb.WriteString("[")
	sb.WriteString(hashName)
	sb.WriteString("]")
	rightBotPad := artWidth - botPad - len(hashName) - 2
	if rightBotPad < 0 {
		rightBotPad = 0
	}
	sb.WriteString(strings.Repeat("-", rightBotPad))
	sb.WriteString("+")

	return sb.String()
}

// RandomArtFromFingerprint generates randomart from a hex-encoded fingerprint string.
// Accepts formats like "MD5:xx:xx:xx:..." or raw hex "xxxxxx...".
func RandomArtFromFingerprint(fingerprint string, keyType string, bits int) string {
	// Strip "MD5:" prefix and colons.
	fp := fingerprint
	if strings.HasPrefix(fp, "MD5:") {
		fp = fp[4:]
	}
	fp = strings.ReplaceAll(fp, ":", "")

	hash, err := hex.DecodeString(fp)
	if err != nil {
		return ""
	}
	return randomArtFromHash(hash, keyType, bits, "MD5")
}
