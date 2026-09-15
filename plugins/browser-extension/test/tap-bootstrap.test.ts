// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { TAP_CHANNEL } from '../src/tap-protocol.ts';

// The handshake `bootstrap()` posts, which is the ONLY path that runs in a real
// page — `tap.test.ts` drives `installTap` directly with a port it built
// itself, and `tap-bundle.test.ts` counts substrings in the built file, which
// is blind to what the call is actually passed.
//
// A SEPARATE file for two reasons. `bootstrap()` runs at module scope, so the
// spy has to be installed before the import and the module has to be loaded
// fresh — `vi.resetModules()` plus a dynamic import, which would disturb every
// other case in a shared file. And the tap patches `window.fetch` and
// `window.XMLHttpRequest` on the way through, so the window it lands on must
// be one nothing else is asserting about.
//
// What slips through without this: drop the transfer list and the call becomes
// `window.postMessage({ tag: TAP_CHANNEL }, '*')`. `postMessage` then throws
// DataCloneError — no, worse: it succeeds, carries no port, and the bridge's
// handshake handler finds nothing to take. Either way the extension captures
// nothing on every page, with the whole suite green.
describe('the tap bootstrap handshake', () => {
  let posted: { data: unknown; origin: unknown; transfer: unknown }[];

  beforeEach(() => {
    posted = [];
    vi.spyOn(window, 'postMessage').mockImplementation(
      (data: unknown, origin?: unknown, transfer?: unknown) => {
        posted.push({ data, origin, transfer });
      },
    );
    vi.resetModules();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('posts one handshake carrying exactly one MessagePort', async () => {
    await import('../src/tap.ts');

    expect(posted).toHaveLength(1);
    const call = posted[0];
    expect(call?.data).toEqual({ tag: TAP_CHANNEL });
    // '*' reaches THIS window only — the post is to `window` itself, not to a
    // frame — and the tap reads nothing back off the channel, so a page script
    // that sees the handshake gains only the bytes of its own traffic.
    expect(call?.origin).toBe('*');

    const transfer = call?.transfer;
    expect(Array.isArray(transfer)).toBe(true);
    expect(transfer as unknown[]).toHaveLength(1);
    // A MessagePort, not merely something truthy: the whole point of the
    // transfer list is that the bridge ends up holding the other end.
    expect((transfer as unknown[])[0]).toBeInstanceOf(MessagePort);
  });

  it('installs a tap that reports over the port it handed over', async () => {
    // The positive control. Without it this file would pass on a bootstrap
    // that posted a well-formed handshake and installed nothing behind it.
    //
    // Asserted through the PORT rather than by reading `window.fetch` back:
    // that global is banned in this repository (see CLAUDE.md "No network
    // calls"), and the port is the better witness anyway — it is the channel
    // the bridge really listens on, and `patched` is the tap's own statement
    // that it hooked something.
    await import('../src/tap.ts');
    const port = (posted[0]?.transfer as MessagePort[] | undefined)?.[0];
    expect(port).toBeInstanceOf(MessagePort);
    if (port === undefined) throw new Error('the handshake carried no port');

    const seen: { type?: string }[] = [];
    port.onmessage = (event: MessageEvent) => {
      seen.push(event.data as { type?: string });
    };
    port.start();
    // Wait for the report itself rather than for one timer. A Node MessagePort
    // delivers through its own event-loop source, so a single timer can fire
    // before the queued messages are dispatched and read an empty list. The
    // wait is bounded, so a tap that never reports fails on the assertion
    // below rather than on the runner's timeout.
    for (let turn = 0; turn < 400 && !seen.some((m) => m.type === 'patched'); turn += 1) {
      await new Promise((resolve) => {
        setTimeout(resolve, 0);
      });
    }

    expect(seen.map((m) => m.type)).toContain('patched');
  });
});
