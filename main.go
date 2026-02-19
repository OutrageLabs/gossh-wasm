// main.go registers the GoSSH global object on window with the complete API.

//go:build js && wasm

package gossh

import (
	"fmt"
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

	gossh["agentRemoveKey"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return jsError(fmt.Errorf("agentRemoveKey: fingerprint required"))
		}
		return agentRemoveKey(args[0].String())
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
		mode := args[2].Int()
		if mode < 0 || mode > 0o7777 {
			return jsError(fmt.Errorf("sftpChmod: mode must be between 0 and 07777"))
		}
		return sftpChmod(args[0].String(), args[1].String(), uint32(mode))
	})

	gossh["sftpGetwd"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return jsError(errMissingConfig)
		}
		return sftpGetwd(args[0].String())
	})

	gossh["sftpRealPath"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return jsError(errMissingConfig)
		}
		return sftpRealPath(args[0].String(), args[1].String())
	})

	gossh["sftpUpload"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 3 {
			return jsError(errMissingConfig)
		}
		onProgress := js.Undefined()
		if len(args) > 3 {
			onProgress = args[3]
		}
		signal := js.Undefined()
		if len(args) > 4 {
			signal = args[4]
		}
		return sftpUpload(args[0].String(), args[1].String(), args[2], onProgress, signal)
	})

	gossh["sftpDownload"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return jsError(errMissingConfig)
		}
		onProgress := js.Undefined()
		if len(args) > 2 {
			onProgress = args[2]
		}
		signal := js.Undefined()
		if len(args) > 3 {
			signal = args[3]
		}
		return sftpDownload(args[0].String(), args[1].String(), onProgress, signal)
	})

	gossh["sftpDownloadStream"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return jsError(errMissingConfig)
		}
		onProgress := js.Undefined()
		if len(args) > 2 {
			onProgress = args[2]
		}
		return sftpDownloadStream(args[0].String(), args[1].String(), onProgress)
	})

	// === Streaming Upload ===

	gossh["sftpUploadStreamStart"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 3 {
			return jsError(errMissingConfig)
		}
		return sftpUploadStreamStart(args[0].String(), args[1].String(), int64(args[2].Float()))
	})

	gossh["sftpUploadStreamWrite"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return jsError(errMissingConfig)
		}
		return sftpUploadStreamWrite(args[0].String(), args[1])
	})

	gossh["sftpUploadStreamEnd"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return jsError(errMissingConfig)
		}
		return sftpUploadStreamEnd(args[0].String())
	})

	gossh["sftpUploadStreamCancel"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return nil
		}
		sftpUploadStreamCancel(args[0].String())
		return nil
	})

	// Internal streaming API (called by Service Worker via stream_helper.js)
	gossh["_streamPull"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return js.ValueOf(map[string]any{"data": js.Null(), "done": true})
		}
		return streamPull(args[0].String(), args[1].String())
	})

	gossh["_streamCancel"] = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return nil
		}
		streamCancel(args[0].String(), args[1].String())
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
