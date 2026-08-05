import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { BackgroundResponse } from '../src/messaging.ts';

// background.ts wires itself to the chrome.* globals on import (its
// onMessage listener and the lazily-connected native port), so a scriptable
// chrome stub is installed FIRST and the module dynamically imported fresh
// per test — the stub captures the listener registration and each
// connectNative port so tests can drive both sides of the relay.

type OnMessageListener = (
  message: unknown,
  sender: unknown,
  sendResponse: (response?: unknown) => void,
) => boolean;

interface FakePort {
  posted: Record<string, unknown>[];
  emitMessage(message: unknown): void;
  emitDisconnect(): void;
}

function installChromeStub(): { ports: FakePort[]; dispatch: OnMessageListener } {
  const ports: FakePort[] = [];
  let listener: OnMessageListener | undefined;

  const runtime = {
    connectNative: () => {
      const messageListeners: ((message: unknown) => void)[] = [];
      const disconnectListeners: (() => void)[] = [];
      const port: FakePort = {
        posted: [],
        emitMessage: (message) => {
          for (const l of messageListeners) l(message);
        },
        emitDisconnect: () => {
          for (const l of disconnectListeners) l();
        },
      };
      ports.push(port);
      return {
        onMessage: {
          addListener: (l: (message: unknown) => void) => {
            messageListeners.push(l);
          },
        },
        onDisconnect: {
          addListener: (l: () => void) => {
            disconnectListeners.push(l);
          },
        },
        postMessage: (message: unknown) => {
          port.posted.push(message as Record<string, unknown>);
        },
      };
    },
    onMessage: {
      addListener: (l: OnMessageListener) => {
        listener = l;
      },
    },
  };
  vi.stubGlobal('chrome', { runtime });

  return {
    ports,
    dispatch: (message, sender, sendResponse) => {
      if (!listener) throw new Error('background.ts registered no onMessage listener');
      return listener(message, sender, sendResponse);
    },
  };
}

async function boot(): Promise<ReturnType<typeof installChromeStub>> {
  const stub = installChromeStub();
  await import('../src/background.ts');
  return stub;
}

// The content-script side of one relayed request: dispatch through the
// captured onMessage listener and record what sendResponse eventually gets.
function request(
  stub: Awaited<ReturnType<typeof boot>>,
  message: unknown,
): { responses: BackgroundResponse[] } {
  const responses: BackgroundResponse[] = [];
  const keptOpen = stub.dispatch(message, {}, (response) => {
    responses.push(response as BackgroundResponse);
  });
  expect(keptOpen).toBe(true); // the channel must stay open for the async reply
  return { responses };
}

async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

beforeEach(() => {
  vi.resetModules(); // fresh module state (pending map, port) per test
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('background relay (service worker)', () => {
  it('correlates a native response to exactly its pending request by requestId', async () => {
    const stub = await boot();
    const first = request(stub, { type: 'ping' });
    const second = request(stub, { type: 'health' });

    const [port] = stub.ports;
    expect(port?.posted).toHaveLength(2);
    const firstId = port?.posted[0]?.requestId as string;
    const secondId = port?.posted[1]?.requestId as string;
    expect(firstId).not.toBe(secondId);

    // Answer the SECOND request first — only its sender resolves.
    port?.emitMessage({ type: 'health', requestId: secondId, ok: true, findings: 0 });
    await flush();
    expect(first.responses).toHaveLength(0);
    expect(second.responses).toEqual([
      { type: 'health', requestId: secondId, ok: true, findings: 0 },
    ]);

    port?.emitMessage({ type: 'ping', requestId: firstId, ok: true });
    await flush();
    expect(first.responses).toEqual([{ type: 'ping', requestId: firstId, ok: true }]);
  });

  it('a disconnect resolves EVERY in-flight request with a fail-open error', async () => {
    const stub = await boot();
    const first = request(stub, { type: 'ping' });
    const second = request(stub, { type: 'health' });

    stub.ports[0]?.emitDisconnect();
    await flush();

    for (const { responses } of [first, second]) {
      expect(responses).toHaveLength(1);
      expect(responses[0]).toMatchObject({
        type: 'error',
        ok: false,
        message: 'native host disconnected',
      });
    }
  });

  it('reconnects after a disconnect: the next request opens a fresh port and resolves over it', async () => {
    const stub = await boot();
    request(stub, { type: 'ping' });
    stub.ports[0]?.emitDisconnect();
    await flush();

    const after = request(stub, { type: 'ping' });
    expect(stub.ports).toHaveLength(2);
    const port = stub.ports[1];
    expect(port?.posted).toHaveLength(1);

    const requestId = port?.posted[0]?.requestId as string;
    port?.emitMessage({ type: 'ping', requestId, ok: true });
    await flush();
    expect(after.responses).toEqual([{ type: 'ping', requestId, ok: true }]);
  });
});
