/**
 * stream_worker.js — Service Worker for streaming SFTP downloads.
 *
 * When Go WASM initiates a streaming download, it dispatches a
 * 'gossh-stream-download' event with {streamId, filename, size, mimeType}.
 * The app creates a hidden link to /_stream/<streamId>/<filename> and clicks it.
 * This Service Worker intercepts that fetch and serves a ReadableStream
 * that pulls data from GoSSH._streamPull(streamId).
 *
 * Result: the browser downloads the file progressively without buffering
 * the entire file in memory. Works for files of any size.
 *
 * Registration (from your app):
 *   navigator.serviceWorker.register('/stream_worker.js', { scope: '/' });
 */

const STREAM_PATH_PREFIX = '/_stream/';

self.addEventListener('install', (event) => {
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

  // Parse: /_stream/<streamId>/<filename>
  const parts = url.pathname.slice(STREAM_PATH_PREFIX.length).split('/');
  if (parts.length < 2) {
    return;
  }

  const streamId = parts[0];
  const filename = decodeURIComponent(parts.slice(1).join('/'));

  event.respondWith(handleStreamRequest(streamId, filename));
});

async function handleStreamRequest(streamId, filename) {
  // We need to call GoSSH._streamPull(streamId) which is on the main thread.
  // Service Workers can't access the main thread's globals directly,
  // so we use a MessageChannel to communicate.

  const client = await getControllingClient();
  if (!client) {
    return new Response('No controlling client', { status: 500 });
  }

  const stream = new ReadableStream({
    async pull(controller) {
      try {
        const result = await pullFromMain(client, streamId);
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
      notifyCancel(client, streamId);
    }
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${filename}"`,
    }
  });
}

/**
 * Pull a chunk from the main thread via MessageChannel.
 * The main thread has a listener that calls GoSSH._streamPull(streamId).
 */
function pullFromMain(client, streamId) {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();

    channel.port1.onmessage = (event) => {
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
      { type: 'gossh-stream-pull', streamId },
      [channel.port2]
    );
  });
}

function notifyCancel(client, streamId) {
  client.postMessage({ type: 'gossh-stream-cancel', streamId });
}

async function getControllingClient() {
  const clients = await self.clients.matchAll({ type: 'window' });
  return clients[0] || null;
}
