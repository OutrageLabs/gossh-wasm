// main.go registers the GoSSH global object on window with the complete API.

//go:build js && wasm

package gossh

import (
	"syscall/js"
)

// RegisterAPI sets up the GoSSH global object accessible from JavaScript.
// Call this from a main package that imports gossh.
func RegisterAPI() {
	gossh := map[string]any{}

	// === SSH Session ===

	gossh["connect"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return jsError(errMissingConfig)
		}
		return sshConnect(args[0])
	})

	gossh["write"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return nil
		}
		sshWrite(args[0].String(), args[1])
		return nil
	})

	gossh["resize"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 3 {
			return nil
		}
		sshResize(args[0].String(), args[1].Int(), args[2].Int())
		return nil
	})

	gossh["disconnect"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return nil
		}
		sshDisconnect(args[0].String())
		return nil
	})

	// === SSH Agent ===

	gossh["agentAddKey"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return jsError(errMissingKey)
		}
		passphrase := ""
		if len(args) > 1 && !args[1].IsUndefined() && !args[1].IsNull() {
			passphrase = args[1].String()
		}
		return agentAddKey(args[0].String(), passphrase)
	})

	gossh["agentRemoveAll"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		agentRemoveAll()
		return nil
	})

	gossh["agentListKeys"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		return agentListKeys()
	})

	// === SFTP ===

	gossh["sftpOpen"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return jsError(errMissingConfig)
		}
		return sftpOpen(args[0].String())
	})

	gossh["sftpClose"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return nil
		}
		sftpClose(args[0].String())
		return nil
	})

	gossh["sftpListDir"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return jsError(errMissingConfig)
		}
		return sftpListDir(args[0].String(), args[1].String())
	})

	gossh["sftpStat"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return jsError(errMissingConfig)
		}
		return sftpStat(args[0].String(), args[1].String())
	})

	gossh["sftpMkdir"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return jsError(errMissingConfig)
		}
		return sftpMkdir(args[0].String(), args[1].String())
	})

	gossh["sftpRemove"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return jsError(errMissingConfig)
		}
		recursive := false
		if len(args) > 2 && !args[2].IsUndefined() {
			recursive = args[2].Bool()
		}
		return sftpRemove(args[0].String(), args[1].String(), recursive)
	})

	gossh["sftpRename"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 3 {
			return jsError(errMissingConfig)
		}
		return sftpRename(args[0].String(), args[1].String(), args[2].String())
	})

	gossh["sftpChmod"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 3 {
			return jsError(errMissingConfig)
		}
		return sftpChmod(args[0].String(), args[1].String(), uint32(args[2].Int()))
	})

	gossh["sftpUpload"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 3 {
			return jsError(errMissingConfig)
		}
		var onProgress js.Value
		if len(args) > 3 {
			onProgress = args[3]
		}
		return sftpUpload(args[0].String(), args[1].String(), args[2], onProgress)
	})

	gossh["sftpDownload"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return jsError(errMissingConfig)
		}
		var onProgress js.Value
		if len(args) > 2 {
			onProgress = args[2]
		}
		return sftpDownload(args[0].String(), args[1].String(), onProgress)
	})

	gossh["sftpDownloadStream"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return jsError(errMissingConfig)
		}
		var onProgress js.Value
		if len(args) > 2 {
			onProgress = args[2]
		}
		return sftpDownloadStream(args[0].String(), args[1].String(), onProgress)
	})

	// Internal streaming API (called by Service Worker via stream_helper.js)
	gossh["_streamPull"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return js.ValueOf(map[string]any{"data": js.Null(), "done": true})
		}
		return streamPull(args[0].String())
	})

	gossh["_streamCancel"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return nil
		}
		streamCancel(args[0].String())
		return nil
	})

	// === Port Forwarding ===

	gossh["portForwardStart"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return jsError(errMissingConfig)
		}
		return portForwardStart(args[0].String(), args[1])
	})

	gossh["portForwardStop"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return nil
		}
		portForwardStop(args[0].String())
		return nil
	})

	gossh["portForwardList"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return js.Global().Get("Array").New()
		}
		return portForwardList(args[0].String())
	})

	// Register as window.GoSSH
	js.Global().Set("GoSSH", js.ValueOf(gossh))
}
