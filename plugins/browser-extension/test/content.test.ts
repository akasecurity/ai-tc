// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { ProviderAdapter } from '../src/providers/types.ts';
import type { SharedScope } from '../src/tab-session.ts';
import { readEnforcementState } from '../src/tab-session.ts';

// content.ts resolves an adapter for `location.hostname` at import time and
// bootstraps only if it finds one. Under jsdom the hostname is `localhost`, so
// no adapter matches and importing the module runs nothing — which is what
// makes it testable at all. `bootstrap` is then driven directly, with a fake
// adapter standing in for a site.
//
// The stub has to exist before the import, because the module body runs on
// import and `relay` reaches for `chrome`.
const sendMessage = vi.hoisted(() => vi.fn(() => Promise.resolve({ type: 'error', ok: false })));
vi.stubGlobal('chrome', { runtime: { sendMessage } });

// bootstrap() attaches a MutationObserver and never disconnects it — benign in
// production, where it runs once per page, but here every case's observer would
// stay live for the rest of the file, fire on the next case's DOM setup, and
// publish from its own adapter closure into the shared scope. Standing in for
// the constructor is what makes each case see only its own writes, and lets the
// remount case drive the callback rather than waiting on jsdom's timing.
const observers: { cb: () => void; disconnect: () => void }[] = [];
vi.stubGlobal(
  'MutationObserver',
  class {
    constructor(cb: () => void) {
      observers.push({ cb, disconnect: () => undefined });
    }
    observe = (): void => undefined;
    disconnect = (): void => undefined;
  },
);

// Fires every observer bootstrap() has registered, the way a DOM mutation would.
function mutate(): void {
  for (const o of observers) o.cb();
}

const frames: (() => void)[] = [];
vi.stubGlobal('requestAnimationFrame', (cb: () => void) => {
  frames.push(cb);
  return frames.length;
});

// Past the window a degraded enforcement state must outlast to be believed.
function settle(): void {
  vi.advanceTimersByTime(5_000);
}

// Run every frame callback queued so far. Synchronous: the rAF stub above just
// collects callbacks, so draining them needs no clock and no await.
function nextFrame(): void {
  const queued = frames.splice(0);
  for (const cb of queued) cb();
}

const { bootstrap } = await import('../src/content.ts');

interface Harness {
  adapter: ProviderAdapter;
  bound: () => number;
  unbound: () => number;
}

function fakeAdapter(): Harness {
  let bound = 0;
  let unbound = 0;
  return {
    bound: () => bound,
    unbound: () => unbound,
    adapter: {
      id: 'chatgpt',
      hostnames: ['chatgpt.com'],
      findComposer: () => document.querySelector<HTMLElement>('#composer'),
      findSendButton: () => document.querySelector<HTMLElement>('#send'),
      extractText: () => 'text',
      setText: () => undefined,
      watchSubmit: () => {
        bound += 1;
        return () => {
          unbound += 1;
        };
      },
      submit: () => true,
      endpoints: [],
      requiredPaths: { request: [], response: [] },
      protocolTokens: [],
      parseRequest: () => ({ requiredPathsSeen: false }),
      parseStream: () => ({ push: () => undefined, end: () => null }),
    },
  };
}

describe('bootstrap: what the DOM path reports about itself', () => {
  beforeEach(() => {
    observers.length = 0;
    frames.length = 0;
    // Scoped so this file's rAF stub survives; the frame pump needs it.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    // A FRESH body per case, not `innerHTML = ''`. bootstrap() attaches a
    // MutationObserver to whatever document.body was and never disconnects it,
    // so every earlier case's observer is still live and still holds its own
    // adapter closure. Clearing the existing body notifies all of them, and
    // they publish over each other in the shared scope — which made one case
    // here pass on a neighbour's write rather than its own.
    document.body = document.createElement('body');
    delete (window as unknown as SharedScope).__akaEnforcement;
    delete (window as unknown as SharedScope).__akaWebSessionId;
    sendMessage.mockClear();
  });

  const scope = (): SharedScope => window as unknown as SharedScope;

  it("publishes 'watching' and binds the watcher when both halves resolve", () => {
    document.body.innerHTML = '<div id="composer"></div><button id="send"></button>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();

    expect(readEnforcementState(scope())).toBe('watching');
    expect(h.bound()).toBe(1);
  });

  it("publishes 'composer-only' and binds NOTHING when the send button is missing", () => {
    // The live signed-in chatgpt.com shape. Binding here would swallow every
    // message, because an intercepted send is completed by clicking that button
    // — so not binding is right, and saying so is the part that was missing.
    document.body.innerHTML = '<div id="composer"></div>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();

    settle();
    expect(readEnforcementState(scope())).toBe('composer-only');
    expect(h.bound()).toBe(0);
  });

  it("publishes 'button-only' when the composer is missing", () => {
    // The anonymous chatgpt.com shape, where the composer is a <textarea> no
    // contenteditable selector reaches.
    document.body.innerHTML = '<button id="send"></button>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();

    settle();
    expect(readEnforcementState(scope())).toBe('button-only');
    expect(h.bound()).toBe(0);
  });

  it("publishes 'unattached' when neither half resolves", () => {
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();

    settle();
    expect(readEnforcementState(scope())).toBe('unattached');
    expect(h.bound()).toBe(0);
  });

  it('republishes when a remount takes the send button away', () => {
    // The regression that matters: a state that only ever moved toward
    // 'watching' would report the healthy moment for the life of the tab.
    document.body.innerHTML = '<div id="composer"></div><button id="send"></button>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    expect(readEnforcementState(scope())).toBe('watching');

    document.querySelector('#send')?.remove();
    mutate();
    nextFrame();
    settle();

    expect(readEnforcementState(scope())).toBe('composer-only');
    expect(h.unbound()).toBe(1);
  });
});

describe('a degraded enforcement state has to settle before it is believed', () => {
  beforeEach(() => {
    observers.length = 0;
    frames.length = 0;
    document.body = document.createElement('body');
    delete (window as unknown as SharedScope).__akaEnforcement;
    delete (window as unknown as SharedScope).__akaWebSessionId;
    // Only the timeout family. Faking requestAnimationFrame too would replace
    // this file's own rAF stub, and the frame pump would never run.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  });

  const scope = (): SharedScope => window as unknown as SharedScope;

  it('publishes nothing but watching when a mount passes through a half-resolved state', () => {
    // The live shape: a page load reports button-only for a moment, then
    // watching once the composer mounts. Publishing the intermediate puts a
    // red "not enforcing" row in the store and a warning in the popup for a
    // tab that is perfectly healthy — on every page load, on every tab.
    document.body.innerHTML = '<button id="send"></button>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    expect(readEnforcementState(scope())).toBe('unknown');

    document.body.innerHTML = '<div id="composer"></div><button id="send"></button>';
    mutate();
    nextFrame();

    expect(readEnforcementState(scope())).toBe('watching');
    vi.advanceTimersByTime(30_000);
    expect(readEnforcementState(scope())).toBe('watching');
  });

  it('publishes watching immediately — a bound watcher is not provisional', () => {
    document.body.innerHTML = '<div id="composer"></div><button id="send"></button>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    expect(readEnforcementState(scope())).toBe('watching');
  });

  it('holds a degraded state back for the whole window, not merely one tick', () => {
    // Without a SHORT advance this suite cannot tell a 2s settle from a 0ms
    // one: every other case either checks before any timer runs or advances
    // far past the window, and both readings are identical either way. A zero
    // window republishes every transient mount state, which is the noise the
    // settle exists to remove — so the lower bound is the property, and this
    // is the only case that holds it.
    document.body.innerHTML = '<div id="composer"></div>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();

    vi.advanceTimersByTime(1_500);
    expect(readEnforcementState(scope())).toBe('unknown');

    vi.advanceTimersByTime(1_000);
    expect(readEnforcementState(scope())).toBe('composer-only');
  });

  it('publishes a degraded state that persists past the settle window', () => {
    document.body.innerHTML = '<div id="composer"></div>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    expect(readEnforcementState(scope())).toBe('unknown');

    vi.advanceTimersByTime(30_000);
    expect(readEnforcementState(scope())).toBe('composer-only');
  });

  it('still reports a watcher that dies mid-session, once it has settled', () => {
    // The regression direction matters as much as the mount direction: a
    // composer whose send button goes away for good must not stay 'watching'.
    document.body.innerHTML = '<div id="composer"></div><button id="send"></button>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    expect(readEnforcementState(scope())).toBe('watching');

    document.querySelector('#send')?.remove();
    mutate();
    nextFrame();
    vi.advanceTimersByTime(30_000);

    expect(readEnforcementState(scope())).toBe('composer-only');
  });

  it('a repeating degraded state is not deferred for ever by the churn that repeats it', () => {
    // reattach runs on every DOM mutation, and these sites mutate constantly.
    // Resetting the timer on each identical report would mean a genuinely
    // broken page never reports at all.
    document.body.innerHTML = '<div id="composer"></div>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    for (let i = 0; i < 20; i += 1) {
      vi.advanceTimersByTime(500);
      mutate();
      nextFrame();
    }
    expect(readEnforcementState(scope())).toBe('composer-only');
  });
});
