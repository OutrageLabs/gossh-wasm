// cmd/gossh/main.go is the WASM binary entry point.
// Build with: GOOS=js GOARCH=wasm go build -o gossh.wasm ./cmd/gossh/

//go:build js && wasm

package main

import (
	gossh "github.com/OutrageLabs/gossh-wasm"
)

func main() {
	gossh.RegisterAPI()

	// Block forever — WASM must stay alive for JS to call GoSSH methods.
	select {}
}
