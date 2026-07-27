/**
 * The MV3 service worker — owns the ONE chrome.runtime.connectNative port to
 * the local native-messaging host (native-host/host.ts, spawned by Chrome per
 * the manifest `aka extension install` writes) and relays every content
 * script request over it. Content scripts can't call connectNative directly
 * (Chrome restricts it to background/extension pages), so this file is the
 * one relay between every tab's content script and the local store.
 *
 * The port is lazily (re)connected on first use and again after a disconnect,
 * so neither a not-yet-installed host nor a host that was just reinstalled
 * requires reloading the extension itself — the next request just reconnects.
 */
import { NATIVE_HOST_NAME } from './constants.ts';
import type { BackgroundRequest, BackgroundResponse } from './messaging.ts';

let port: chrome.runtime.Port | null = null;
let nextRequestId = 0;
const pending = new Map<string, (response: BackgroundResponse) => void>();

function handleNativeMessage(message: unknown): void {
  const response = message as BackgroundResponse;
  const requestId = response.requestId;
  if (requestId === undefined) return;
  const resolve = pending.get(requestId);
  if (!resolve) return;
  pending.delete(requestId);
  resolve(response);
}

function handleDisconnect(): void {
  port = null;
  // Anything still in flight when the host went away gets a synthetic error
  // response instead of hanging forever — a stale/missing native host must
  // never leave a content script's send() promise unresolved.
  for (const [requestId, resolve] of pending) {
    resolve({ type: 'error', requestId, ok: false, message: 'native host disconnected' });
  }
  pending.clear();
}

function connect(): chrome.runtime.Port {
  const nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);
  nativePort.onMessage.addListener(handleNativeMessage);
  nativePort.onDisconnect.addListener(handleDisconnect);
  return nativePort;
}

function send(request: BackgroundRequest): Promise<BackgroundResponse> {
  const requestId = `${Date.now().toString()}-${(nextRequestId++).toString()}`;
  return new Promise((resolve) => {
    pending.set(requestId, resolve);
    try {
      (port ?? (port = connect())).postMessage({ ...request, requestId });
    } catch {
      pending.delete(requestId);
      resolve({
        type: 'error',
        requestId,
        ok: false,
        message:
          'failed to reach the AKA native host — is it installed? Run `aka extension install`.',
      });
    }
  });
}

function isBackgroundRequest(value: unknown): value is BackgroundRequest {
  return typeof value === 'object' && value !== null && 'type' in value;
}

chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
  if (!isBackgroundRequest(message)) return false;
  send(message)
    .then(sendResponse)
    .catch(() => {
      sendResponse({ type: 'error', requestId: undefined, ok: false, message: 'relay failed' });
    });
  return true; // keep the message channel open for the async sendResponse above
});
