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
	"time"
)

const (
	// transferChunkSize is the size of each read/write chunk during transfers.
	// 64KB balances throughput with GC pressure from js.CopyBytesToGo/JS calls.
	transferChunkSize = 64 * 1024

	// maxDownloadSize is the maximum file size for in-memory sftpDownload.
	// WASM memory is limited; use sftpDownloadStream for larger files.
	maxDownloadSize = 512 * 1024 * 1024 // 512 MB
)

// sftpUpload uploads data from a JS Uint8Array to a remote file.
// Called from JS as:
//
//	GoSSH.sftpUpload(sftpId, remotePath, data: Uint8Array, onProgress?, signal?: AbortSignal) → Promise<void>
func sftpUpload(sftpID string, remotePath string, data js.Value, onProgress js.Value, signal js.Value) js.Value {
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

		hasProgress := hasProgressFn(onProgress)

		// Write in chunks with progress reporting.
		written := 0
		for written < totalSize {
			if isAborted(signal) {
				return nil, errTransferCancelled
			}
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
				onProgress.Invoke(float64(written), float64(totalSize))
			}
		}

		return nil, nil
	})
}

// sftpDownload downloads a remote file into a JS Uint8Array.
// Suitable for files that fit in WASM memory (< ~1-2 GB).
// Called from JS as:
//
//	GoSSH.sftpDownload(sftpId, remotePath, onProgress?, signal?: AbortSignal) → Promise<Uint8Array>
func sftpDownload(sftpID string, remotePath string, onProgress js.Value, signal js.Value) js.Value {
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
		if totalSize > maxDownloadSize {
			return nil, fmt.Errorf("sftpDownload: file too large (%d bytes, max %d). Use sftpDownloadStream for large files", totalSize, maxDownloadSize)
		}

		f, err := client.Open(remotePath)
		if err != nil {
			return nil, fmt.Errorf("sftpDownload: open: %w", err)
		}
		defer f.Close()

		hasProgress := hasProgressFn(onProgress)

		// Read in chunks. Use a modest initial capacity to avoid pre-allocating
		// hundreds of MB upfront; append will grow geometrically as needed.
		initCap := totalSize
		if initCap > 1024*1024 {
			initCap = 1024 * 1024 // Cap initial alloc at 1 MB.
		}
		buf := make([]byte, 0, initCap)
		chunk := make([]byte, transferChunkSize)
		totalRead := int64(0)

		for {
			if isAborted(signal) {
				return nil, errTransferCancelled
			}
			n, err := f.Read(chunk)
			if n > 0 {
				buf = append(buf, chunk[:n]...)
				totalRead += int64(n)

				if hasProgress {
					onProgress.Invoke(float64(totalRead), float64(totalSize))
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
	doneOnce   sync.Once
}

// closeDone safely signals completion. Multiple calls are harmless.
func (s *streamState) closeDone() {
	s.doneOnce.Do(func() { close(s.done) })
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

		// Wait for download to complete or timeout (30 min max for large files).
		timeout := time.NewTimer(30 * time.Minute)
		defer timeout.Stop()
		select {
		case <-state.done:
		case <-timeout.C:
			state.file.Close()
			state.closeDone()
			activeStreams.Delete(streamID)
			return nil, fmt.Errorf("sftpDownloadStream: timed out after 30 minutes")
		}

		// Report final progress.
		if hasProgressFn(onProgress) {
			onProgress.Invoke(float64(state.progress.Load()), float64(state.totalSize))
		}

		activeStreams.Delete(streamID)
		return nil, nil
	})
}

// ────────────────────────────────────────────────────────────────────
// Streaming upload (push-based)
// ────────────────────────────────────────────────────────────────────

// activeUploads tracks in-progress streaming uploads.
var activeUploads sync.Map // uploadID → *uploadState

type uploadState struct {
	dataCh   chan []byte   // JS pushes chunks here
	doneCh   chan struct{} // Signals upload completion
	doneOnce sync.Once
	written  atomic.Int64
	size     int64

	// writeErr is a sticky error from the writer goroutine.
	// Once set, all subsequent sftpUploadStreamWrite calls fail immediately.
	writeErrMu sync.Mutex
	writeErr   error
}

func (u *uploadState) closeDone() {
	u.doneOnce.Do(func() { close(u.doneCh) })
}

func (u *uploadState) setErr(err error) {
	u.writeErrMu.Lock()
	if u.writeErr == nil {
		u.writeErr = err
	}
	u.writeErrMu.Unlock()
}

func (u *uploadState) getErr() error {
	u.writeErrMu.Lock()
	defer u.writeErrMu.Unlock()
	return u.writeErr
}

// sftpUploadStreamStart begins a streaming upload.
// Returns a stream ID that JS uses to push chunks.
// Called from JS as:
//
//	GoSSH.sftpUploadStreamStart(sftpId, remotePath, size) → Promise<string>
func sftpUploadStreamStart(sftpID string, remotePath string, size int64) js.Value {
	return newPromise(func() (any, error) {
		client, err := getSFTPClient(sftpID)
		if err != nil {
			return nil, err
		}

		f, err := client.Create(remotePath)
		if err != nil {
			return nil, fmt.Errorf("sftpUploadStreamStart: create: %w", err)
		}

		uploadID := generateID()
		state := &uploadState{
			dataCh: make(chan []byte, 16), // Buffer up to 16 chunks (1 MB at 64KB chunks).
			doneCh: make(chan struct{}),
			size:   size,
		}
		activeUploads.Store(uploadID, state)

		// Background writer goroutine: drains dataCh and writes to SFTP file.
		go func() {
			defer f.Close()
			defer state.closeDone()

			for chunk := range state.dataCh {
				n, err := f.Write(chunk)
				if err != nil {
					state.setErr(fmt.Errorf("sftpUploadStream: write: %w", err))
					// Drain remaining chunks to unblock pushers.
					for range state.dataCh {
					}
					return
				}
				state.written.Add(int64(n))
			}
		}()

		return uploadID, nil
	})
}

// sftpUploadStreamWrite pushes a chunk to an active streaming upload.
// Called from JS as:
//
//	GoSSH.sftpUploadStreamWrite(uploadId, chunk: Uint8Array) → Promise<void>
func sftpUploadStreamWrite(uploadID string, chunk js.Value) js.Value {
	return newPromise(func() (any, error) {
		val, ok := activeUploads.Load(uploadID)
		if !ok {
			return nil, fmt.Errorf("sftpUploadStreamWrite: upload %q not found", uploadID)
		}
		state := val.(*uploadState)

		// Check for sticky writer error — persists across all subsequent calls.
		if err := state.getErr(); err != nil {
			return nil, err
		}

		// Copy JS Uint8Array to Go bytes.
		length := chunk.Get("byteLength").Int()
		data := make([]byte, length)
		js.CopyBytesToGo(data, chunk)

		// Send to writer goroutine.
		state.dataCh <- data

		// Re-check: the write may have failed while we were blocked on send.
		if err := state.getErr(); err != nil {
			return nil, err
		}
		return nil, nil
	})
}

// sftpUploadStreamEnd finalizes a streaming upload.
// Called from JS as:
//
//	GoSSH.sftpUploadStreamEnd(uploadId) → Promise<void>
func sftpUploadStreamEnd(uploadID string) js.Value {
	return newPromise(func() (any, error) {
		val, ok := activeUploads.LoadAndDelete(uploadID)
		if !ok {
			return nil, fmt.Errorf("sftpUploadStreamEnd: upload %q not found", uploadID)
		}
		state := val.(*uploadState)

		// Signal no more chunks.
		close(state.dataCh)

		// Wait for writer to finish.
		<-state.doneCh

		// Return sticky write error if any.
		if err := state.getErr(); err != nil {
			return nil, err
		}

		return nil, nil
	})
}

// sftpUploadStreamCancel cancels an active streaming upload.
// Called from JS as: GoSSH.sftpUploadStreamCancel(uploadId)
func sftpUploadStreamCancel(uploadID string) {
	val, ok := activeUploads.LoadAndDelete(uploadID)
	if !ok {
		return
	}
	state := val.(*uploadState)
	close(state.dataCh) // Unblocks writer goroutine, which will close file.
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
			state.closeDone()
		}
		return js.ValueOf(result)
	}

	// EOF or error — close stream.
	state.file.Close()
	state.closeDone()

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
	state.closeDone()
}

func hasProgressFn(v js.Value) bool {
	return !v.IsUndefined() && !v.IsNull() && v.Type() == js.TypeFunction
}

// isAborted checks if a JS AbortSignal has been aborted.
func isAborted(signal js.Value) bool {
	return !signal.IsUndefined() && !signal.IsNull() && signal.Get("aborted").Bool()
}

var errTransferCancelled = fmt.Errorf("transfer cancelled")
