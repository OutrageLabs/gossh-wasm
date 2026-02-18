/**
 * stream_worker.js — Service Worker for streaming SFTP downloads.
 *
 * When Go WASM initiates a streaming download, it dispatches a
 * 'gossh-stream-download' event with {streamId, streamToken, filename, size, mimeType}.
 * The app creates a hidden link to /_stream/<streamId>/<streamToken>/<filename> and clicks it.
 * This Service Worker intercepts that fetch and serves a ReadableStream
 * that pulls data from GoSSH._streamPull(streamId, streamToken).
 *
 * Result: the browser downloads the file progressively without buffering
 * the entire file in memory. Works for files of any size.
 *
 * Registration (from your app):
 *   navigator.serviceWorker.register('/stream_worker.js', { scope: '/_stream/' });
 */

const STREAM_PATH_PREFIX = '/_stream/';

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  if (!url.pathname.startsWith(STREAM_PATH_PREFIX)) {
    return; // Not a stream request — let it pass through.
  }

  // Parse: /_stream/<streamId>/<streamToken>/<filename>
  const parts = url.pathname.slice(STREAM_PATH_PREFIX.length).split('/');
  if (parts.length < 3) {
    event.respondWith(new Response('Invalid stream URL', { status: 400 }));
    return;
  }

  const streamId = parts[0];
  const streamToken = parts[1];
  const filename = decodeURIComponent(parts.slice(2).join('/'));

  if (!isHexId(streamId) || !isHexId(streamToken)) {
    event.respondWith(new Response('Invalid stream credentials', { status: 400 }));
    return;
  }

  // Use event.clientId to target the correct tab (multi-tab safe).
  event.respondWith(handleStreamRequest(streamId, streamToken, filename, event.clientId));
});

async function handleStreamRequest(streamId, streamToken, filename, clientId) {
  // We need to call GoSSH._streamPull(streamId, streamToken) on the main thread.
  // Service Workers can't access the main thread's globals directly,
  // so we use a MessageChannel to communicate.

  const client = await getSourceClient(clientId);
  if (!client) {
    return new Response('No controlling client', { status: 500 });
  }

  const stream = new ReadableStream({
    async pull(controller) {
      try {
        const result = await pullFromMain(client, streamId, streamToken);
        if (result.done || !result.data) {
          controller.close();
          return;
        }
        controller.enqueue(result.data);
      } catch (err) {
        controller.error(err);
      }
    },
    cancel() {
      // Notify Go that the download was cancelled.
      notifyCancel(client, streamId, streamToken);
    }
  });

  // Sanitize filename for Content-Disposition to prevent header injection.
  const safeName = filename.replace(/["\\\r\n]/g, '_');
  const encodedName = encodeURIComponent(filename);

  return new Response(stream, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${safeName}"; filename*=UTF-8''${encodedName}`,
    }
  });
}

/**
 * Pull a chunk from the main thread via MessageChannel.
 * The main thread has a listener that calls GoSSH._streamPull(streamId, streamToken).
 */
function pullFromMain(client, streamId, streamToken) {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();

    // Timeout if main thread doesn't respond within 30 seconds.
    const timer = setTimeout(() => {
      channel.port1.onmessage = null;
      reject(new Error('pullFromMain: timeout waiting for main thread response'));
    }, 30000);

    channel.port1.onmessage = (event) => {
      clearTimeout(timer);
      if (event.data.error) {
        reject(new Error(event.data.error));
      } else {
        resolve({
          data: event.data.data ? new Uint8Array(event.data.data) : null,
          done: event.data.done
        });
      }
    };

    client.postMessage(
      { type: 'gossh-stream-pull', streamId, streamToken },
      [channel.port2]
    );
  });
}

function notifyCancel(client, streamId, streamToken) {
  client.postMessage({ type: 'gossh-stream-cancel', streamId, streamToken });
}

/**
 * Get the client that initiated the stream request.
 * Uses clientId from the fetch event for strict multi-tab isolation.
 */
async function getSourceClient(clientId) {
  if (!clientId) {
    return null;
  }
  return await self.clients.get(clientId);
}

function isHexId(value) {
  return typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
}
