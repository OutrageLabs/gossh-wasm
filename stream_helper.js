/**
 * stream_helper.js — Client-side helper for GoSSH streaming downloads.
 *
 * Include this in your app AFTER loading the WASM. It:
 * 1. Handles 'gossh-stream-download' events from Go WASM
 * 2. Responds to Service Worker pull requests via MessageChannel
 * 3. Falls back to Blob download if Service Worker is unavailable
 *
 * Usage:
 *   <script src="stream_helper.js"></script>
 *   // Or import and call: initGoSSHStreaming()
 */

(() => {
  const MAX_BLOB_FALLBACK_SIZE = 100 * 1024 * 1024; // 100 MB

  // Register Service Worker for streaming.
  async function registerStreamWorker() {
    if (!('serviceWorker' in navigator)) {
      console.warn('[gossh] Service Workers not available, using Blob fallback');
      return false;
    }

    try {
      await navigator.serviceWorker.register('/stream_worker.js', { scope: '/_stream/' });
      await navigator.serviceWorker.ready;
      console.log('[gossh] Stream Service Worker registered');
      return true;
    } catch (err) {
      console.warn('[gossh] Service Worker registration failed:', err);
      return false;
    }
  }

  // Handle pull requests from the Service Worker.
  navigator.serviceWorker?.addEventListener('message', (event) => {
    const { type, streamId, streamToken } = event.data;

    if (type === 'gossh-stream-pull' && event.ports[0]) {
      const port = event.ports[0];
      try {
        const result = GoSSH._streamPull(streamId, streamToken);
        if (result.done || !result.data) {
          port.postMessage({ data: null, done: true });
        } else {
          // Transfer the ArrayBuffer for zero-copy.
          const buffer = result.data.buffer;
          port.postMessage(
            { data: buffer, done: false },
            [buffer]
          );
        }
      } catch (err) {
        port.postMessage({ error: err.message });
      }
    }

    if (type === 'gossh-stream-cancel') {
      try { GoSSH._streamCancel(streamId, streamToken); } catch { /* ignore */ }
    }
  });

  // Handle download trigger events from Go WASM.
  // detail: { streamId, streamToken, filename, size, mimeType }
  let swAvailable = false;

  window.addEventListener('gossh-stream-download', async (event) => {
    const { streamId, streamToken, filename, size } = event.detail;

    if (swAvailable) {
      // Trigger download via Service Worker stream.
      const link = document.createElement('a');
      link.href = `/_stream/${streamId}/${streamToken}/${encodeURIComponent(filename)}`;
      link.download = filename;
      link.style.display = 'none';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } else {
      // Fallback: pull chunks asynchronously into a Blob and trigger download.
      // Uses setTimeout to yield to the event loop between chunks.
      if (typeof size === 'number' && size > MAX_BLOB_FALLBACK_SIZE) {
        console.error(`[gossh] Blob fallback disabled for large file (${size} bytes > ${MAX_BLOB_FALLBACK_SIZE})`);
        try { GoSSH._streamCancel(streamId, streamToken); } catch { /* ignore */ }
        return;
      }
      console.warn(`[gossh] Using Blob fallback for ${filename} (${size} bytes)`);
      const chunks = [];
      const pullChunk = () => {
        try {
          const result = GoSSH._streamPull(streamId, streamToken);
          if (result.done || !result.data) {
            // All chunks collected — create blob and download.
            const blob = new Blob(chunks);
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            return;
          }
          chunks.push(result.data);
          // Yield to event loop before pulling next chunk.
          setTimeout(pullChunk, 0);
        } catch (err) {
          console.error('[gossh] Blob fallback failed:', err);
        }
      };
      pullChunk();
    }
  });

  // Initialize on load.
  registerStreamWorker().then(available => {
    swAvailable = available;
  });

  // Export for manual initialization if needed.
  window.initGoSSHStreaming = registerStreamWorker;
})();
