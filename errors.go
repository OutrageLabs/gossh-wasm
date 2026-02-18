//go:build js && wasm

package gossh

import "errors"

var (
	errMissingConfig = errors.New("connect: config object required")
	errMissingKey    = errors.New("agentAddKey: keyPEM string required")
)
