// agent.go implements an in-memory SSH agent for key management.
// Keys live only in WASM memory — page reload clears everything.
// The application (Subterm) is responsible for loading keys from storage.

//go:build js && wasm

package gossh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"syscall/js"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// keyBits returns the key size in bits for display (e.g., "RSA 4096-bit").
func keyBits(pubKey ssh.PublicKey) int {
	cryptoPubKey, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return 0
	}
	cryptoPub := cryptoPubKey.CryptoPublicKey()
	switch k := cryptoPub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// globalAgent is the in-memory SSH agent shared across all sessions.
// It implements the agent.Agent interface from golang.org/x/crypto/ssh/agent.
var globalAgent agent.Agent

func init() {
	globalAgent = agent.NewKeyring()
}

// agentAddKey parses a PEM private key and adds it to the in-memory agent.
// Returns the key's SHA256 fingerprint.
// Called from JS as: GoSSH.agentAddKey(keyPEM, passphrase?) → Promise<fingerprint>
func agentAddKey(keyPEM string, passphrase string) js.Value {
	return newPromise(func() (any, error) {
		// Parse raw private key (rsa, ed25519, ecdsa, etc.)
		var rawKey any
		var err error
		keyBytes := []byte(keyPEM)
		defer scrubBytes(keyBytes)
		if passphrase != "" {
			passBytes := []byte(passphrase)
			defer scrubBytes(passBytes)
			rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase(keyBytes, passBytes)
		} else {
			rawKey, err = ssh.ParseRawPrivateKey(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("agentAddKey: %w", err)
		}

		addedKey := agent.AddedKey{
			PrivateKey: rawKey,
		}
		if err := globalAgent.Add(addedKey); err != nil {
			return nil, fmt.Errorf("agentAddKey: add to keyring: %w", err)
		}

		// Get fingerprint by creating a signer from the raw key.
		signer, err := ssh.NewSignerFromKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("agentAddKey: fingerprint: %w", err)
		}

		fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
		return fingerprint, nil
	})
}

// agentRemoveKey removes a single key from the agent by its SHA256 fingerprint.
// Called from JS as: GoSSH.agentRemoveKey(fingerprint) → Promise<void>
func agentRemoveKey(fingerprint string) js.Value {
	return newPromise(func() (any, error) {
		keys, err := globalAgent.List()
		if err != nil {
			return nil, fmt.Errorf("agentRemoveKey: list: %w", err)
		}
		for _, k := range keys {
			if ssh.FingerprintSHA256(k) == fingerprint {
				if err := globalAgent.Remove(k); err != nil {
					return nil, fmt.Errorf("agentRemoveKey: remove: %w", err)
				}
				return nil, nil
			}
		}
		return nil, fmt.Errorf("agentRemoveKey: key with fingerprint %q not found", fingerprint)
	})
}

// agentRemoveAll removes all keys from the in-memory agent.
// Called from JS as: GoSSH.agentRemoveAll()
func agentRemoveAll() {
	if err := globalAgent.RemoveAll(); err != nil {
		logWarnf("agentRemoveAll failed:", err.Error())
	}
}

// agentListKeys returns information about all keys in the agent.
// Called from JS as: GoSSH.agentListKeys() → [{fingerprint, type, comment}]
func agentListKeys() js.Value {
	keys, err := globalAgent.List()
	if err != nil {
		return js.Global().Get("Array").New()
	}

	result := js.Global().Get("Array").New(len(keys))
	for i, k := range keys {
		info := map[string]any{
			"fingerprint": ssh.FingerprintSHA256(k),
			"type":        k.Type(),
			"comment":     k.Comment,
			"bits":        keyBits(k),
			"randomArt":   RandomArt(k),
		}
		result.SetIndex(i, js.ValueOf(info))
	}
	return result
}
