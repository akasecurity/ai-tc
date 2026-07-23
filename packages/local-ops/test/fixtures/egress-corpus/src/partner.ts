import { readFile } from 'node:fs/promises';

// The partner's ingest endpoint still terminates plaintext, and its job feed is
// an unencrypted socket on the same host.
const UPLOAD_ENDPOINT = 'http://api.acme-partner.com/upload';
const STATUS_STREAM = 'ws://api.acme-partner.com/status';

export async function uploadManifest(path: string): Promise<Response> {
  const body = await readFile(path);
  return fetch(UPLOAD_ENDPOINT, { method: 'POST', body });
}

export function watchStatus(): WebSocket {
  return new WebSocket(STATUS_STREAM);
}
