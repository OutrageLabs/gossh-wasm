// sftp_transfer.go implements SFTP file upload and download with progress
// callbacks and streaming support for large files.
//
// Two download strategies:
// 1. sftpDownload — reads entire file into Uint8Array (simple, limited by WASM memory)
// 2. sftpDownloadStream — uses Service Worker streaming (no memory buffering)

//go:build js && wasm

package gossh

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"syscall/js"
)

const (
	// transferChunkSize is the size of each read/write chunk during transfers.
	// 64KB balances throughput with GC pressure from js.CopyBytesToGo/JS calls.
	transferChunkSize = 64 * 1024
)

// sftpUpload uploads data from a JS Uint8Array to a remote file.
// Called from JS as:
//
//	GoSSH.sftpUpload(sftpId, remotePath, data: Uint8Array, onProgress?) → Promise<void>
func sftpUpload(sftpID string, remotePath string, data js.Value, onProgress js.Value) js.Value {
	return newPromise(func() (any, error) {
		client, err := getSFTPClient(sftpID)
		if err != nil {
			return nil, err
		}

		// Convert JS Uint8Array to Go bytes.
		totalSize := data.Get("byteLength").Int()
		src := make([]byte, totalSize)
		js.CopyBytesToGo(src, data)

		// Create remote file.
		f, err := client.Create(remotePath)
		if err != nil {
			return nil, fmt.Errorf("sftpUpload: create: %w", err)
		}
		defer f.Close()

		hasProgress := !onProgress.IsUndefined() && !onProgress.IsNull() && onProgress.Type() == js.TypeFunction

		// Write in chunks with progress reporting.
		written := 0
		for written < totalSize {
			end := written + transferChunkSize
			if end > totalSize {
				end = totalSize
			}
			n, err := f.Write(src[written:end])
			if err != nil {
				return nil, fmt.Errorf("sftpUpload: write at %d: %w", written, err)
			}
			written += n

			if hasProgress {
				onProgress.Invoke(written, totalSize)
			}
		}

		return nil, nil
	})
}

// sftpDownload downloads a remote file into a JS Uint8Array.
// Suitable for files that fit in WASM memory (< ~1-2 GB).
// Called from JS as:
//
//	GoSSH.sftpDownload(sftpId, remotePath, onProgress?) → Promise<Uint8Array>
func sftpDownload(sftpID string, remotePath string, onProgress js.Value) js.Value {
	return newPromise(func() (any, error) {
		client, err := getSFTPClient(sftpID)
		if err != nil {
			return nil, err
		}

		// Get file size for progress reporting.
		info, err := client.Stat(remotePath)
		if err != nil {
			return nil, fmt.Errorf("sftpDownload: stat: %w", err)
		}
		totalSize := info.Size()

		f, err := client.Open(remotePath)
		if err != nil {
			return nil, fmt.Errorf("sftpDownload: open: %w", err)
		}
		defer f.Close()

		hasProgress := !onProgress.IsUndefined() && !onProgress.IsNull() && onProgress.Type() == js.TypeFunction

		// Read in chunks.
		buf := make([]byte, 0, totalSize)
		chunk := make([]byte, transferChunkSize)
		totalRead := int64(0)

		for {
			n, err := f.Read(chunk)
			if n > 0 {
				buf = append(buf, chunk[:n]...)
				totalRead += int64(n)

				if hasProgress {
					onProgress.Invoke(int(totalRead), int(totalSize))
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("sftpDownload: read: %w", err)
			}
		}

		return bytesToUint8Array(buf), nil
	})
}

// ────────────────────────────────────────────────────────────────────
// Streaming download via Service Worker
// ────────────────────────────────────────────────────────────────────

// activeStreams tracks in-progress streaming downloads.
// The Service Worker sends fetch requests with a stream ID, and Go
// provides data via a pull-based ReadableStream.
var activeStreams sync.Map // streamID → *streamState

type streamState struct {
	sftpID     string
	remotePath string
	totalSize  int64
	read       int64
	file       io.ReadCloser
	progress   atomic.Int64
	done       chan struct{}
}

// sftpDownloadStream initiates a streaming download via Service Worker.
// This avoids buffering the entire file in WASM memory.
//
// Flow:
// 1. Go registers a stream with a unique ID
// 2. Go tells JS to navigate to /_stream/<streamID>/<filename>
// 3. Service Worker intercepts the fetch and calls GoSSH._streamPull(streamID)
// 4. Go returns chunks until EOF
// 5. Browser saves the file progressively
//
// Called from JS as:
//
//	GoSSH.sftpDownloadStream(sftpId, remotePath, onProgress?) → Promise<void>
func sftpDownloadStream(sftpID string, remotePath string, onProgress js.Value) js.Value {
	return newPromise(func() (any, error) {
		client, err := getSFTPClient(sftpID)
		if err != nil {
			return nil, err
		}

		info, err := client.Stat(remotePath)
		if err != nil {
			return nil, fmt.Errorf("sftpDownloadStream: stat: %w", err)
		}

		f, err := client.Open(remotePath)
		if err != nil {
			return nil, fmt.Errorf("sftpDownloadStream: open: %w", err)
		}

		streamID := generateID()
		state := &streamState{
			sftpID:     sftpID,
			remotePath: remotePath,
			totalSize:  info.Size(),
			file:       f,
			done:       make(chan struct{}),
		}
		activeStreams.Store(streamID, state)

		// Extract filename from path.
		filename := remotePath
		for i := len(remotePath) - 1; i >= 0; i-- {
			if remotePath[i] == '/' {
				filename = remotePath[i+1:]
				break
			}
		}

		// Tell JS to trigger download via Service Worker.
		streamInfo := map[string]any{
			"streamId":  streamID,
			"filename":  filename,
			"size":      info.Size(),
			"mimeType":  "application/octet-stream",
		}

		// JS side will: location.href = `/_stream/${streamId}/${filename}`
		// or create a hidden anchor and click it.
		js.Global().Call("dispatchEvent",
			js.Global().Get("CustomEvent").New("gossh-stream-download", map[string]any{
				"detail": js.ValueOf(streamInfo),
			}),
		)

		// Wait for download to complete or timeout.
		<-state.done

		// Report final progress.
		if hasProgressFn(onProgress) {
			onProgress.Invoke(int(state.progress.Load()), int(state.totalSize))
		}

		activeStreams.Delete(streamID)
		return nil, nil
	})
}

// streamPull is called by the Service Worker to pull the next chunk.
// Called from JS as: GoSSH._streamPull(streamId) → {data: Uint8Array|null, done: bool}
func streamPull(streamID string) js.Value {
	val, ok := activeStreams.Load(streamID)
	if !ok {
		return js.ValueOf(map[string]any{"data": js.Null(), "done": true})
	}
	state := val.(*streamState)

	chunk := make([]byte, transferChunkSize)
	n, err := state.file.Read(chunk)

	if n > 0 {
		state.progress.Add(int64(n))
		result := map[string]any{
			"data": bytesToUint8Array(chunk[:n]),
			"done": err != nil,
		}
		if err != nil {
			state.file.Close()
			close(state.done)
		}
		return js.ValueOf(result)
	}

	// EOF or error — close stream.
	state.file.Close()
	close(state.done)

	return js.ValueOf(map[string]any{"data": js.Null(), "done": true})
}

// streamCancel cancels a streaming download.
// Called from JS as: GoSSH._streamCancel(streamId)
func streamCancel(streamID string) {
	val, ok := activeStreams.LoadAndDelete(streamID)
	if !ok {
		return
	}
	state := val.(*streamState)
	state.file.Close()
	close(state.done)
}

func hasProgressFn(v js.Value) bool {
	return !v.IsUndefined() && !v.IsNull() && v.Type() == js.TypeFunction
}
